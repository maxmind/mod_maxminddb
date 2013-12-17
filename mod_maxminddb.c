/* maxminddb module
 *
 * Version 0.1
 *
 * This module sets an environment variable to the remote country
 * based on the requestor's IP address.  It uses the maxminddb library
 * to lookup the country by IP address.
 *
 * Copyright 2013, MaxMind Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "util_script.h"
#include <netdb.h>
#include <arpa/inet.h>
#include "maxminddb.h"
#include <string.h>
#include <alloca.h>

#define INFO(server_rec, ...) \
                    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, "[mod_maxminddb]: " __VA_ARGS__);

typedef struct key_value_list_s {
    const char *path;
    const char *env_key;
    struct key_value_list_s *next;
    const char **names;
} key_value_list_s;

typedef struct {
    int enabled;
} maxminddb_config;

typedef struct {
    maxminddb_config mmcfg;
} maxminddb_dir_config_rec;

typedef struct maxminddb_server_list {
    struct maxminddb_server_list *nextdb;
    const char *disk_name;
    const char *nick_name;
    MMDB_s *mmdb;
    key_value_list_s *next;
} maxminddb_server_list;

typedef struct maxminddb_server_config {
    maxminddb_server_list *nextdb;
    int enabled;
} maxminddb_server_config;

typedef struct {
    maxminddb_server_config mmsrvcfg;
} maxminddb_server_config_rec;

module AP_MODULE_DECLARE_DATA maxminddb_module;
static void add_database(cmd_parms * cmd, maxminddb_server_config * conf,
                         const char *nickname, const char *filename);

static void set_env_for_ip(request_rec * r, maxminddb_server_config * mmsrvcfg, const char *ipaddr);

static void set_user_env(request_rec * r, maxminddb_server_config * mmsrvcfg,
                         const char *ipaddr);

static void set_env(request_rec * r, maxminddb_server_config * mmsrvcfg,
                    MMDB_lookup_result_s * root, key_value_list_s * key_value);

static maxminddb_config *get_maxminddb_config(request_rec * r);

static void init_maxminddb_server_config(maxminddb_server_config * srv)
{
    srv->nextdb = NULL;
    srv->enabled = 1;
}
 

static void init_maxminddb_config(maxminddb_config * cfg)
{
    cfg->enabled = 1;
}

/* create a disabled directory entry */

static void *create_dir_config(apr_pool_t * p, char *d)
{

    maxminddb_dir_config_rec *dcfg;

    dcfg =
        (maxminddb_dir_config_rec *) apr_pcalloc(p,
                                                 sizeof
                                                 (maxminddb_dir_config_rec));
    init_maxminddb_config(&dcfg->mmcfg);

    return dcfg;
}

static void *merge_dir_config(apr_pool_t * p, void *parent, void *cur)
{
    return cur;
}

/* create a standard disabled server entry */

static void *create_server_config(apr_pool_t * p, server_rec * srec)
{
    maxminddb_server_config_rec *conf =
        apr_pcalloc(p, sizeof(maxminddb_server_config_rec));
    if (!conf) {
        return NULL;
    }

    init_maxminddb_server_config(&conf->mmsrvcfg);
    INFO(srec, "create_server_config");

    return (void *)conf;
}

static apr_status_t cleanup(void *cfgdata)
{
    int i;
    maxminddb_server_config_rec *cfg = (maxminddb_server_config_rec *) cfgdata;
    return APR_SUCCESS;
}

/* initialize maxminddb once per server ( even virtal server! ) */
static void server_init(apr_pool_t * p, server_rec * s)
{
    maxminddb_server_config_rec *cfg;
    cfg = (maxminddb_server_config_rec *)
        ap_get_module_config(s->module_config, &maxminddb_module);

    apr_pool_cleanup_register(p, (void *)cfg, cleanup, cleanup);
    INFO(s, "server_init");

}

static void child_init(apr_pool_t * p, server_rec * s)
{
    maxminddb_server_config_rec *cfg;
    int i, flags;

    INFO(s, "child_init");

    cfg = (maxminddb_server_config_rec *)
        ap_get_module_config(s->module_config, &maxminddb_module);

}

/* map into the first apache */
static int post_config(apr_pool_t * p, apr_pool_t * plog,
                       apr_pool_t * ptemp, server_rec * s)
{
    INFO(s, "post_config");
    server_init(p, s);
    return OK;
}

static int maxminddb_header_parser(request_rec * r,
                                   maxminddb_server_config * mmcfg);
static int maxminddb_post_read_request(request_rec * r)
{
    maxminddb_server_config_rec *cfg;
    cfg = ap_get_module_config(r->server->module_config, &maxminddb_module);

    INFO(r->server, "maxminddb_post_read_request");
    if (!cfg)
        return DECLINED;

    if (!cfg->mmsrvcfg.enabled)
        return DECLINED;

    return maxminddb_header_parser(r, &cfg->mmsrvcfg);
}

static int maxminddb_per_dir(request_rec * r)
{
    INFO(r->server, "maxminddb_per_dir ( enabled )");
    maxminddb_server_config_rec *scfg =
        ap_get_module_config(r->server->module_config, &maxminddb_module);
    if (!scfg)
        return DECLINED;

    return maxminddb_header_parser(r, &scfg->mmsrvcfg);
}

char *_get_client_ip(request_rec * r)
{
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    return r->useragent_ip;
# else
    return r->connection->remote_ip;
#endif
}

static int maxminddb_header_parser(request_rec * r, maxminddb_server_config * mmsrvcfg)
{
    char *ipaddr;
    char *free_me = NULL;
    char *ipaddr_ptr = NULL;

    ipaddr = _get_client_ip(r);
    INFO(r->server, "maxminddb_header_parser %s", ipaddr);

    if (!mmsrvcfg || !mmsrvcfg->enabled)
        return DECLINED;

    set_env_for_ip(r, mmsrvcfg, ipaddr);
    return OK;
}

void set_string(request_rec * r, MMDB_entry_s * entry, const char *env, ...)
{
    va_list keys;
    MMDB_entry_data_s result;
    if (!entry->offset)
        return;
    va_start(keys, env);
    MMDB_s *mmdb = entry->mmdb;
    MMDB_vget_value(entry, &result, keys);
    if (result.offset) {
        char *value = alloca(result.data_size + 1);
        memcpy(value, (void *)result.pointer, result.data_size);
        value[result.data_size] = 0;
        apr_table_set(r->subprocess_env, env, value);
    }
    va_end(keys);
}

void set_double(request_rec * r, MMDB_entry_s * entry, const char *env, ...)
{
    va_list keys;
    MMDB_entry_data_s result;
    if (!entry->offset)
        return;
    va_start(keys, env);
    MMDB_vget_value(entry, &result, keys);
    if (result.offset) {
        char *value;
        asprintf(&value, "%.5f", result.double_value);
        if (value) {
            apr_table_set(r->subprocess_env, env, value);
            free(value);
        }
    }
    va_end(keys);
}

#define K(...) __VA_ARGS__, NULL

static void set_env_for_ip(request_rec * r, maxminddb_server_config * mmsrvcfg,
                           const char *ipaddr)
{
    apr_table_set(r->subprocess_env, "MMDB_ADDR", ipaddr);
    set_user_env(r, mmsrvcfg, ipaddr);
}

static const char *set_maxminddb_enable(cmd_parms * cmd, void *dummy, int arg)
{
    /* is per directory config? */
    if (cmd->path) {
        maxminddb_dir_config_rec *dcfg = dummy;
        dcfg->mmcfg.enabled = arg;

        INFO(cmd->server, "set_maxminddb_enable: (dir) %d", arg);

        return NULL;
    }
    /* no then it is server config */
    maxminddb_server_config_rec *conf = (maxminddb_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &maxminddb_module);

    if (!conf)
        return "mod_maxminddb: server structure not allocated";

    conf->mmsrvcfg.enabled = arg;
    INFO(cmd->server, "set_maxminddb_enable: (server) %d", arg);

    return NULL;
}

static const char *set_maxminddb_filename(cmd_parms * cmd, void *dummy,
                                          const char *filename,
                                          const char *arg2)
{
    int i;

    if (cmd->path) {
        maxminddb_dir_config_rec *dcfg = dummy;
        dcfg->mmsrvcfg.filename = filename;

        INFO(cmd->server, "set_maxminddb_filename (dir) %s", filename);

        return NULL;
    }

    maxminddb_server_config_rec *conf = (maxminddb_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &maxminddb_module);

    if (!filename)
        return NULL;

    INFO(cmd->server, "add-database (server) %s", filename);
    add_database(cmd, &conf->mmsrvcfg, nickname, filename);

    INFO(cmd->server, "set_maxminddb_filename (server) %s", filename);

    return NULL;
}

static void add_database(cmd_parms * cmd, maxminddb_server_config * conf,
                         const char *nickname, const char *filename)
{
    for (maxminddb_server_list * cur = conf->nextdb; cur; cur = cur->nextdb) {
        if (!strcmp(cur->nick_name, nickname)) {
            // we know the nickname already
            INFO(cmd->server, "We know already db (%s) skipping %s", nickname,
                 filename);
            return;
        }
    }
    // insert
    maxminddb_server_list *sl =
        apr_palloc(cmd->pool, sizeof(maxminddb_server_list));
    sl->nextdb = NULL;
    sl->next = NULL;
    sl->mmdb = apr_palloc(cmd->pool, sizeof(MMDB_s));
    int mmdb_error = MMDB_open(filename, MMDB_MODE_MMAP, sl->mmdb);
    if (mmdb_error != MMDB_SUCCESS) {
        INFO(cmd->server, "Open database failed: %s %d", filename, mmdb_error);
        return;
    }
    sl->disk_name = (char *)apr_pstrdup(cmd->pool, filename);
    sl->nick_name = (char *)apr_pstrdup(cmd->pool, nickname);
    sl->nextdb = conf->nextdb;
    conf->nextdb = sl;
    INFO(cmd->server, "Insert db (%s)%s", nickname, filename);
}

static void insert_kvlist(maxminddb_server_config * mmsrvcfg,
                          key_value_list_s * list)
{

    list->next = mmcfg->next;
    mmcfg->next = list;
}

static const char *set_maxminddb_env(cmd_parms * cmd, void *dummy,
                                     const char *env, const char *dbpath)
{
    int i;

    key_value_list_s *list = apr_palloc(cmd->pool, sizeof(key_value_list_s));
    list->path = dbpath;
    list->env_key = env;
    list->next = NULL;
    list->names = NULL;

    maxminddb_server_config_rec *conf = (maxminddb_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &maxminddb_module);

    INFO(cmd->server, "set_maxminddb_env (server) %s %s", env, dbpath);

    insert_kvlist(&conf->mmsrvcfg, list);

    return NULL;
}

static const command_rec maxminddb_cmds[] = {
    AP_INIT_FLAG("MaxMindDBEnable", set_maxminddb_enable, NULL,
                 OR_FILEINFO, "Turn on mod_maxminddb"),
    AP_INIT_TAKE12("MaxMindDBFile", set_maxminddb_filename, NULL,
                   OR_ALL, "Path to the Database File"),
    AP_INIT_ITERATE2("MaxMindDBEnv", set_maxminddb_env, NULL,
                     OR_ALL, "Set desired env var"),
    {NULL}
};

static void maxminddb_register_hooks(apr_pool_t * p)
{
    /* make sure we run before mod_rewrite's handler */
    static const char *const aszSucc[] =
        { "mod_setenvif.c", "mod_rewrite.c", NULL };

    /* we have two entry points, the header_parser hook, right before
     * the authentication hook used for Dirctory specific enabled maxminddblookups
     * or right before directory rewrite rules.
     */
    ap_hook_header_parser(maxminddb_per_dir, NULL, aszSucc, APR_HOOK_MIDDLE);

    /* and the servectly wide hook, after reading the request. Perfecly
     * suitable to serve serverwide mod_rewrite actions
     */
    ap_hook_post_read_request(maxminddb_post_read_request, NULL, aszSucc,
                              APR_HOOK_MIDDLE);

    /* setup our childs maxminddb database once for every child */
    ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);

    /* static const char * const list[]={ "mod_maxminddb.c", NULL }; */
    /* mmap the database(s) into the master process */
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);

}

/* Dispatch list for API hooks */
AP_DECLARE_MODULE(maxminddb) = {
    STANDARD20_MODULE_STUFF,    /* */
        create_dir_config,      /* create per-dir    config structures */
        merge_dir_config,       /* merge  per-dir    config structures */
        create_server_config,   /* create per-server config structures */
        NULL,                   /* merge  per-server config structures */
        maxminddb_cmds,         /* table of config file commands       */
        maxminddb_register_hooks        /* register hooks                      */
};

static maxminddb_server_config *get_maxminddb_config(request_rec * r)
{
    maxminddb_server_config_rec *scfg =
        ap_get_module_config(r->server->module_config, &maxminddb_module);
    return (scfg ? &scfg->mmsrvcfg : NULL);
}

static void set_user_env(request_rec * r, maxminddb_server_config * mmsrvcfg,
                         const char *ipaddr)
{
    struct in6_addr v6;

    if (ipaddr == NULL)
        return;

    for (maxminddb_server_list * sl = mmsrvcfg->nextdb; sl; sl = sl->nextdb) {

        INFO(r->server, "sl %08lx n:%08lx", sl, sl->next);

        if (sl->next == NULL)
            continue;

        int gai_error, mmdb_error;
        assert(sl->mmdb != NULL);
        MMDB_lookup_result_s lookup_result =
            MMDB_lookup_string(sl->mmdb, ipaddr, &gai_error, &mmdb_error);

        if (mmdb_error != MMDB_SUCCESS)
            continue;

        if (gai_error != MMDB_SUCCESS)
            continue;

        apr_table_set(r->subprocess_env, "MMDB_INFO", "lookup success");

        INFO(r->server, "MMDB_lookup_string %s works", ipaddr);

        if (lookup_result.found_entry) {

            for (key_value_list_s * kv = sl->next; kv; kv = kv->next) {
                apr_table_set(r->subprocess_env, "MMDB_INFO", "result found");

                MMDB_entry_data_s result;
                MMDB_aget_value(&lookup_result.entry, &result, &kv->names[1]);
                if (result.offset > 0) {
                    char *value;
                    switch (result.type) {
                    case MMDB_DATA_TYPE_UTF8_STRING:
                        value = malloc(result.data_size + 1);
                        memcpy(value, result.utf8_string, result.data_size);
                        value[result.data_size] = '\0';
                        break;
                    case MMDB_DATA_TYPE_BYTES:
                        value = malloc(result.data_size + 1);
                        memcpy(value, result.bytes, result.data_size);
                        value[result.data_size] = '\0';
                        break;
                    case MMDB_DATA_TYPE_FLOAT:
                        asprintf(&value, "%.5f", result.float_value);
                        break;
                    case MMDB_DATA_TYPE_DOUBLE:
                        asprintf(&value, "%.5f", result.double_value);
                        break;
                    case MMDB_DATA_TYPE_UINT16:
                        asprintf(&value, "%d", result.uint16);
                        break;
                    case MMDB_DATA_TYPE_UINT32:
                        asprintf(&value, "%u", result.uint32);
                        break;
                    case MMDB_DATA_TYPE_INT32:
                        asprintf(&value, "%d", result.int32);
                        break;
                    default:
                        asprintf(&value, "Unsupported");
                        break;
                    }
                    apr_table_set(r->subprocess_env, kv->env_key, value);
                    free(value);
                }
            }
        }
    }
}

static void set_env(request_rec * r, maxminddb_server_config * mmsrvcfg,
                    MMDB_lookup_result_s * root, key_value_list_s * key_value)
{
    const int max_list = 80;
    char *list[max_list + 1];
    int i;
    char *ptr, *cur, *tok;
    cur = ptr = strdup(key_value->path);
    for (i = 0; i < max_list; i++)
        if ((list[i] = strsep(&cur, "/")) == NULL)
            break;
    list[i] = NULL;
    MMDB_entry_data_s result;
    MMDB_aget_value(&root->entry, &result, list);
    if (result.offset > 0) {
        char *value;
        switch (result.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
            value = malloc(result.data_size + 1);
            memcpy(value, result.utf8_string, result.data_size);
            value[result.data_size] = '\0';
            break;
        case MMDB_DATA_TYPE_BYTES:
            value = malloc(result.data_size + 1);
            memcpy(value, result.bytes, result.data_size);
            value[result.data_size] = '\0';
            break;
        case MMDB_DATA_TYPE_FLOAT:
            asprintf(&value, "%.5f", result.float_value);
            break;
        case MMDB_DATA_TYPE_DOUBLE:
            asprintf(&value, "%.5f", result.double_value);
            break;
        case MMDB_DATA_TYPE_UINT16:
            asprintf(&value, "%d", result.uint16);
            break;
        case MMDB_DATA_TYPE_UINT32:
            asprintf(&value, "%u", result.uint32);
            break;
        case MMDB_DATA_TYPE_INT32:
            asprintf(&value, "%d", result.int32);
            break;
        default:
            asprintf(&value, "Unsupported");
            break;
        }
        apr_table_set(r->subprocess_env, key_value->env_key, value);
        free(value);
    }
    free(ptr);
}
