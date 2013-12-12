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
} key_value_list_s;

typedef struct {
    const char *filename;
    int enabled;
    int flags;
    key_value_list_s *next;
} maxminddb_config;

typedef struct {
    maxminddb_config mmcfg;
} maxminddb_server_config_rec;

typedef maxminddb_server_config_rec maxminddb_dir_config_rec;

module AP_MODULE_DECLARE_DATA maxminddb_module;

static void set_env_for_ip(request_rec * r, const char *filename,
                           const char *ipaddr);

static void set_user_env(request_rec * r, MMDB_s * mmdb,
                         MMDB_lookup_result_s * root);

static void set_env(request_rec * r, MMDB_s * mmdb, MMDB_lookup_result_s * root,
                    key_value_list_s * key_value);


static maxminddb_config *get_maxminddb_config(request_rec * r);

static void init_maxminddb_config(maxminddb_config * cfg)
{
    cfg->enabled = 0;
    cfg->flags = 0;
    cfg->filename = NULL;
    cfg->next = NULL;
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

    init_maxminddb_config(&conf->mmcfg);
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

static int maxminddb_header_parser(request_rec * r, maxminddb_config * mmcfg);

static int maxminddb_post_read_request(request_rec * r)
{
    maxminddb_server_config_rec *cfg;
    cfg = ap_get_module_config(r->server->module_config, &maxminddb_module);

    INFO(r->server, "maxminddb_post_read_request");
    if (!cfg)
        return DECLINED;

    if (!cfg->mmcfg.enabled)
        return DECLINED;

    return maxminddb_header_parser(r, &cfg->mmcfg);
}

static int maxminddb_per_dir(request_rec * r)
{

    maxminddb_dir_config_rec *dcfg;
    INFO(r->server, "maxminddb_per_dir");

    dcfg = ap_get_module_config(r->per_dir_config, &maxminddb_module);
    if (!dcfg)
        return DECLINED;

    INFO(r->server, "maxminddb_per_dir config exists");

    if (!dcfg->mmcfg.enabled)
        return DECLINED;

    INFO(r->server, "maxminddb_per_dir ( enabled )");
    return maxminddb_header_parser(r, &dcfg->mmcfg);
}

char *_get_client_ip(request_rec * r)
{
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    return r->useragent_ip;
# else
    return r->connection->remote_ip;
#endif
}

static int maxminddb_header_parser(request_rec * r, maxminddb_config * mmcfg)
{
    char *ipaddr;
    char *free_me = NULL;
    char *ipaddr_ptr = NULL;

    ipaddr = _get_client_ip(r);
    INFO(r->server, "maxminddb_header_parser %s", ipaddr);

    if (!mmcfg || !mmcfg->filename || !mmcfg->enabled)
        return DECLINED;

    set_env_for_ip(r, mmcfg->filename, ipaddr);
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

static void set_env_for_ip(request_rec * r, const char *filename,
                           const char *ipaddr)
{
    struct in6_addr v6;
    ipaddr = "24.24.24.24";
    apr_table_set(r->subprocess_env, "MMDB_ADDR", ipaddr);
    MMDB_s mmdb = { };

    INFO(r->server, "Before open");
    apr_table_set(r->subprocess_env, "MMDB_INFO", "Before open");

    int mmdb_error = MMDB_open(filename, MMDB_MODE_MMAP, &mmdb);

    INFO(r->server, "Open database result: %d", mmdb_error);
    apr_table_set(r->subprocess_env, "MMDB_INFO", "After open");

    if (mmdb_error != MMDB_SUCCESS)
        return;
    INFO(r->server, "Open database works");
    apr_table_set(r->subprocess_env, "MMDB_INFO", "open success");

    if (ipaddr != NULL) {
        int gai_error;
        MMDB_lookup_result_s result =
            MMDB_lookup_string(&mmdb, ipaddr, &gai_error, &mmdb_error);

        if (mmdb_error != MMDB_SUCCESS)
            return;

        if (gai_error != MMDB_SUCCESS)
            return;
        apr_table_set(r->subprocess_env, "MMDB_INFO", "lookup success");

        INFO(r->server, "MMDB_lookup_string %s works", ipaddr);

        if (result.found_entry) {
            apr_table_set(r->subprocess_env, "MMDB_INFO", "result found");
            set_user_env(r, &mmdb, &result);

            MMDB_entry_data_s entry_data;
            MMDB_get_value(&result.entry, &entry_data, K("location"));
            MMDB_entry_s location = {.mmdb = result.entry.mmdb,.offset =
                    entry_data.offset
            };
            set_double(r, &location, "MMDB_LATITUDE", K("latitude"));
            set_double(r, &location, "MMDB_LONGITUDE", K("longitude"));
            set_string(r, &location, "MMDB_METRO_CODE", K("metro_code"));
            set_string(r, &location, "MMDB_TIME_ZONE", K("time_zone"));

            MMDB_get_value(&result.entry, &entry_data, K("continent"));
            location.offset = entry_data.offset;
            set_string(r, &location, "MMDB_CONTINENT_CODE", K("code"));
            set_string(r, &location, "MMDB_CONTINENT_NAME", K("names", "en"));

            MMDB_get_value(&result.entry, &entry_data, K("country"));
            location.offset = entry_data.offset;
            set_string(r, &location, "MMDB_COUNTRY_CODE", K("iso_code"));
            set_string(r, &location, "MMDB_COUNTRY_NAME", K("names", "en"));

            MMDB_get_value(&result.entry, &entry_data, K("registered_country"));
            location.offset = entry_data.offset;
            set_string(r, &location, "MMDB_REGISTERED_COUNTRY_CODE",
                       K("iso_code"));
            set_string(r, &location, "MMDB_REGISTERED_COUNTRY_NAME",
                       K("names", "en"));

            MMDB_get_value(&result.entry, &entry_data, K("subdivisions", "0"));
            location.offset = entry_data.offset;
            set_string(r, &location, "MMDB_REGION_CODE", K("iso_code"));
            set_string(r, &location, "MMDB_REGION_NAME", K("names", "en"));

            set_string(r, &result.entry, "MMDB_CITY", K("city", "names", "en"));
            set_string(r, &result.entry, "MMDB_POSTAL_CODE",
                       K("postal", "code"));
        }
    }
    MMDB_close(&mmdb);
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

    conf->mmcfg.enabled = arg;
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
        dcfg->mmcfg.filename = filename;

        INFO(cmd->server, "set_maxminddb_filename (dir) %s", filename);

        return NULL;
    }

    maxminddb_server_config_rec *conf = (maxminddb_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &maxminddb_module);

    if (!filename)
        return NULL;

    conf->mmcfg.filename = (char *)apr_pstrdup(cmd->pool, filename);
    INFO(cmd->server, "set_maxminddb_filename (server) %s", filename);

    return NULL;
}

static void insert_kvlist(maxminddb_config * mmcfg, key_value_list_s * list)
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

    if (cmd->path) {
        maxminddb_dir_config_rec *dcfg = dummy;

        INFO(cmd->server, "set_maxminddb_env (dir) %s %s", env, dbpath);
        insert_kvlist(&dcfg->mmcfg, list);

        return NULL;
    }

    maxminddb_server_config_rec *conf = (maxminddb_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &maxminddb_module);

    INFO(cmd->server, "set_maxminddb_env (server) %s %s", env, dbpath);

    insert_kvlist(&conf->mmcfg, list);

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

#if 0
static void set_env_for_ip_conf(request_rec * r, const maxminddb_config * mmcfg,
                                const char *ipaddr)
{

    struct in6_addr v6;
    apr_table_set(r->subprocess_env, "MMDB_ADDR", ipaddr);
    MMDB_s *mmdb = MMDB_open(filename, MMDB_MODE_STANDARD);
    MMDB_result_entry_s root = {
        .entry.mmdb = mmdb
    };

    if (!mmdb)
        return;

    int ai_family = AF_INET6;
    int ai_flags = AI_V4MAPPED;

    if ((ipaddr != NULL)
        && (0 == MMDB_lookupaddressX(ipaddr, ai_family, ai_flags, &v6))) {

        int status = MMDB_lookup_by_ipnum_128(v6, &root);
        if (status == MMDB_SUCCESS && result.entry.offset > 0) {

            for (key_value_list_s * key_value = mmcfg->next; key_value;
                 key_value = key_value->next) {
                set_env(r, mmdb, &root, key_value);
            }

        }
    }
}
#endif

static maxminddb_config *get_maxminddb_config(request_rec * r)
{
#if 0
    maxminddb_dir_config_rec *dcfg =
        ap_get_module_config(r->per_dir_config, &maxminddb_module);
    if (dcfg)
        return &dcfg->mmcfg;
#endif
    maxminddb_server_config_rec *scfg =
        ap_get_module_config(r->server->module_config, &maxminddb_module);
    return (scfg ? &scfg->mmcfg : NULL);
}

static void set_user_env(request_rec * r, MMDB_s * mmdb,
                         MMDB_lookup_result_s * root)
{
    maxminddb_config *mmcfg = get_maxminddb_config(r);
    if (mmcfg) {
        for (key_value_list_s * current = mmcfg->next; current;
             current = current->next) {
            set_env(r, mmdb, root, current);
        }
    }
}

static void set_env(request_rec * r, MMDB_s * mmdb, MMDB_lookup_result_s * root,
                    key_value_list_s * key_value)
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
