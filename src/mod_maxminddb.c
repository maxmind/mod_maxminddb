/* maxminddb module
 *
 * This module populates environment variable from a MaxMind DB database
 * using the requestor's IP address.
 *
 * Copyright 2014, MaxMind Inc.
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
#include <inttypes.h>

#if defined (MAXMINDDB_DEBUG)
#define INFO(server_rec, ...)                                            \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, \
                 "[mod_maxminddb]: " __VA_ARGS__)
#else
#define INFO(server_rec, ...)
#endif

#define ERROR(server_rec, ...)                         \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, \
                 "[mod_maxminddb]: " __VA_ARGS__)

#ifdef UNUSED
#elif defined(__GNUC__)
#define  UNUSED(x) UNUSED_ ## x __attribute__((unused))
#else
#define UNUSED
#endif

typedef struct lookup_path_list {
    struct lookup_path_list *next;
    const char *env_key;
    const char **path_segments;
} lookup_path_list;

typedef struct database_list {
    struct database_list *next;
    const char *name;
    MMDB_s *mmdb;
    lookup_path_list *lookup_paths;
} database_list;

typedef struct maxminddb_config {
    database_list *databases;
    int enabled;
} maxminddb_config;

module AP_MODULE_DECLARE_DATA maxminddb_module;

static apr_status_t cleanup_database(void *mmdb);

static char * from_uint128(apr_pool_t *pool,
                           const MMDB_entry_data_s *result);

static void set_env_for_database(request_rec *r, const char *ip_address,
                                 database_list *databases);

static void set_env_for_lookup(request_rec *r, const char *ip_address,
                               MMDB_lookup_result_s *lookup_result,
                               lookup_path_list *lookup_paths);

/* create a disabled directory entry */
static void *create_dir_config(apr_pool_t *pool, char *UNUSED(context))
{
    maxminddb_config *conf = apr_pcalloc(pool, sizeof(maxminddb_config));

    conf->databases = NULL;

    /* We use -1 for off but not set */
    conf->enabled = -1;

    return conf;
}

static void *merge_dir_config(apr_pool_t *pool,
                              void *parent, void *child)
{
    maxminddb_config *conf = (maxminddb_config *) child;
    maxminddb_config *parent_conf = (maxminddb_config *) parent;

    if (conf->enabled == -1) {
        conf->enabled = parent_conf->enabled;
    }

    if (conf->databases && parent_conf->databases) {
        database_list *database = conf->databases;
        while (database->next) {
            database = database->next;
        }

        // set the last element in the child list to point to the head
        // of the parent list
        database->next = parent_conf->databases;
    } else if (parent_conf->databases) {
        conf->databases = parent_conf->databases;
    }
    return conf;
}

static char *get_client_ip(request_rec *r)
{
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    return r->useragent_ip;
# else
    return r->connection->remote_ip;
#endif
}

static const char *set_maxminddb_enable(cmd_parms *cmd, void *config, int arg)
{
    maxminddb_config *conf = (maxminddb_config *)config;

    if (!conf) {
        return "mod_maxminddb: server structure not allocated";
    }

    conf->enabled = arg;
    INFO(cmd->server, "set_maxminddb_enable: (server) %d", arg);

    return NULL;
}

static const char *set_maxminddb_filename(cmd_parms *cmd, void *config,
                                          const char *database_name,
                                          const char *filename)
{
    maxminddb_config *conf = (maxminddb_config *)config;

    INFO(cmd->server, "set_maxminddb_filename (server) %s", filename);

    for (database_list *cur = conf->databases;
         cur; cur = cur->next) {
        if (!strcmp(cur->name, database_name)) {
            // we already have a record for the database
            INFO(cmd->server, "We know already db (%s) skipping %s",
                 database_name, filename);
            return NULL;
        }
    }
    // insert
    database_list *databases =
        apr_palloc(cmd->pool, sizeof(database_list));
    databases->next = NULL;
    databases->lookup_paths = NULL;
    databases->mmdb = apr_palloc(cmd->pool, sizeof(MMDB_s));
    int mmdb_error = MMDB_open(filename, MMDB_MODE_MMAP, databases->mmdb);
    if (mmdb_error != MMDB_SUCCESS) {
        ERROR(cmd->server, "Opening %s failed: %s", filename,
              MMDB_strerror(mmdb_error));
        return NULL;
    }

    apr_pool_pre_cleanup_register(cmd->pool, databases->mmdb, cleanup_database);

    databases->name = (char *)apr_pstrdup(cmd->pool, database_name);
    databases->next = conf->databases;
    conf->databases = databases;
    INFO(cmd->server, "Insert db (%s)%s", database_name, filename);

    return NULL;
}

static apr_status_t cleanup_database(void *mmdb)
{
    MMDB_close((MMDB_s *)mmdb);

    return APR_SUCCESS;
}

static const char *set_maxminddb_env(cmd_parms *cmd, void *config,
                                     const char *env, const char *path)
{
    lookup_path_list *list = apr_palloc(cmd->pool, sizeof(lookup_path_list));
    list->env_key = env;
    list->next = NULL;
    list->path_segments = NULL;

    maxminddb_config *conf = (maxminddb_config *)config;

    INFO(cmd->server, "set_maxminddb_env (server) %s %s", env, path);

    const int max_path_segments = 80;
    char *path_segments[max_path_segments + 1];

    path_segments[0] = apr_pstrdup(cmd->pool, path);

    int i;
    char * strtok_last = NULL;

    char *token = apr_strtok(path_segments[0], "/", &strtok_last);
    for (i = 1; i <= max_path_segments && token; i++) {
        token = apr_strtok(NULL, "/", &strtok_last);
        path_segments[i] = token;
    }

    if (!i) {
        return NULL;
    }

    for (database_list *databases = conf->databases;
         databases;
         databases = databases->next) {
        if (!strcmp(path_segments[0], databases->name)) {
            // found
            list->next = databases->lookup_paths;
            databases->lookup_paths = list;
            list->path_segments = (const char **)apr_pmemdup(cmd->pool,
                                                             path_segments,
                                                             (1 + i) *
                                                             sizeof(char *));
            break;
        }
    }
    return NULL;
}

static int set_env(request_rec *r)
{
    INFO(r->server, "maxminddb_per_dir ( enabled )");
    maxminddb_config *conf =
        ap_get_module_config(r->per_dir_config, &maxminddb_module);
    if (!conf || conf->enabled != 1) {
        return DECLINED;
    }

    char *ip_address = get_client_ip(r);
    INFO(r->server, "maxminddb_header_parser %s", ip_address);

    if (NULL == ip_address) {
        return DECLINED;
    }

    apr_table_set(r->subprocess_env, "MMDB_ADDR", ip_address);

    for (database_list *databases = conf->databases; databases; databases =
             databases->next) {
        set_env_for_database(r, ip_address, databases);
    }

    return OK;
}

static void set_env_for_database(request_rec *r, const char *ip_address,
                                 database_list *databases)
{

    if (databases->lookup_paths == NULL) {
        return;
    }

    int gai_error, mmdb_error;
    MMDB_lookup_result_s lookup_result =
        MMDB_lookup_string(databases->mmdb, ip_address, &gai_error, &mmdb_error);

    if (0 != gai_error || MMDB_SUCCESS != mmdb_error) {
        const char *msg = 0 != gai_error ? "failed to resolve IP address" :
                          MMDB_strerror(mmdb_error);
        ERROR(r->server, "Error looking up '%s': %s", ip_address,
              msg);
        return;
    }

    apr_table_set(r->subprocess_env, "MMDB_INFO", "lookup success");

    INFO(r->server, "MMDB_lookup_string %s works", ip_address);

    if (lookup_result.found_entry) {
        set_env_for_lookup(r, ip_address, &lookup_result,
                           databases->lookup_paths);
    }
}

static void set_env_for_lookup(request_rec *r, const char *ip_address,
                               MMDB_lookup_result_s *lookup_result,
                               lookup_path_list *  lookup_paths)
{
    for (lookup_path_list *kv = lookup_paths; kv; kv = kv->next) {
        apr_table_set(r->subprocess_env, "MMDB_INFO", "result found");

        MMDB_entry_data_s result;
        int mmdb_error = MMDB_aget_value(
            &lookup_result->entry, &result,
            &kv->path_segments[1]);
        if (mmdb_error == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
            // INFO(r->server, MMDB_strerror(mmdb_error));
            continue;
        } else if (mmdb_error != MMDB_SUCCESS) {
            ERROR(r->server, "Error getting data for '%s': %s", ip_address,
                  MMDB_strerror(mmdb_error));
            continue;
        }
        if (result.offset > 0) {
            char *value = NULL;

            switch (result.type) {
            case MMDB_DATA_TYPE_BOOLEAN:
                value = apr_psprintf(r->pool, "%d", result.boolean);
                break;
            case MMDB_DATA_TYPE_UTF8_STRING:
                value = apr_pstrmemdup(r->pool, result.utf8_string,
                                       result.data_size);
                break;
            case MMDB_DATA_TYPE_BYTES:
                /* XXX - treating bytes as strings is broken.
                   They may contain null characters */
                value = apr_pstrmemdup(r->pool,
                                       (const char *)result.bytes,
                                       result.data_size);
                break;
            case MMDB_DATA_TYPE_FLOAT:
                value = apr_psprintf(r->pool, "%.5f",
                                     result.float_value);
                break;
            case MMDB_DATA_TYPE_DOUBLE:
                value = apr_psprintf(r->pool, "%.5f",
                                     result.double_value);
                break;
            case MMDB_DATA_TYPE_UINT16:
                value = apr_psprintf(r->pool, "%d", result.uint16);
                break;
            case MMDB_DATA_TYPE_UINT32:
                value = apr_psprintf(r->pool, "%u", result.uint32);
                break;
            case MMDB_DATA_TYPE_INT32:
                value = apr_psprintf(r->pool, "%d", result.int32);
                break;
            case MMDB_DATA_TYPE_UINT64:
                value = apr_psprintf(r->pool, "%" PRIu64, result.uint64);
                break;
            case MMDB_DATA_TYPE_UINT128:
                value = from_uint128(r->pool, &result);
                break;
            default:
                ERROR(r->server, "Database error: unknown data type");
                continue;
            }

            if (NULL != value) {
                apr_table_set(r->subprocess_env, kv->env_key, value);
            }
        }
    }
}

static char * from_uint128(apr_pool_t *pool,
                           const MMDB_entry_data_s *result)
{
#if MMDB_UINT128_IS_BYTE_ARRAY
    uint8_t *p = (uint8_t *)result->uint128;
    return apr_psprintf(pool, "0x"
                        "%02x%02x%02x%02x"
                        "%02x%02x%02x%02x"
                        "%02x%02x%02x%02x"
                        "%02x%02x%02x%02x",
                        p[0], p[1], p[2], p[3],
                        p[4], p[5], p[6], p[7],
                        p[8], p[9], p[10], p[11],
                        p[12], p[13], p[14], p[15]);
#else

    mmdb_uint128_t v = result->uint128;
    return apr_psprintf(pool,
                        "0x%016" PRIx64 "%016" PRIx64,
                        (uint64_t)(v >> 64),
                        (uint64_t)v);
#endif
}

static const command_rec maxminddb_directives[] = {
    AP_INIT_FLAG("MaxMindDBEnable",
                 set_maxminddb_enable,
                 NULL,
                 OR_FILEINFO,
                 "Turn on mod_maxminddb"),
    AP_INIT_TAKE2("MaxMindDBFile",
                  set_maxminddb_filename,
                  NULL,
                  OR_ALL,
                  "Path to the Database File"),
    AP_INIT_ITERATE2("MaxMindDBEnv",
                     set_maxminddb_env,
                     NULL,
                     OR_ALL,
                     "Set desired env var"),
    { NULL }
};

static void maxminddb_register_hooks(apr_pool_t *UNUSED(p))
{
    /* make sure we run before mod_rewrite's handler */
    static const char *const asz_succ[] =
    { "mod_setenvif.c", "mod_rewrite.c", NULL };

    ap_hook_header_parser(set_env, NULL, asz_succ, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA maxminddb_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,       /* create per-dir    config structures */
    merge_dir_config,        /* merge  per-dir    config structures */
    NULL,                    /* create per-server config structures */
    NULL,                    /* merge  per-server config structures */
    maxminddb_directives,    /* table of config file commands       */
    maxminddb_register_hooks /* register hooks                      */
};
