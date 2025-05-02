/* maxminddb module
 *
 * This module populates environment variable from a MaxMind DB database
 * using the requestor's IP address.
 *
 * Copyright 2013-2025, MaxMind Inc.
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

#include <ap_config.h>
#include <apr_hash.h>
#include <apr_strings.h>
#if APR_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <httpd.h>
 // Must come after httpd.h.
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
#include <inttypes.h>
#include <maxminddb.h>
#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if APR_HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <sys/types.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(maxminddb);
#endif

#if defined(MAXMINDDB_DEBUG)
#define INFO(server_rec, ...)                                                  \
    ap_log_error(APLOG_MARK,                                                   \
                 APLOG_DEBUG | APLOG_NOERRNO,                                  \
                 0,                                                            \
                 server_rec,                                                   \
                 "[mod_maxminddb]: " __VA_ARGS__)
#else
#define INFO(server_rec, ...)
#endif

#define ERROR(server_rec, ...)                                                 \
    ap_log_error(                                                              \
        APLOG_MARK, APLOG_ERR, 0, server_rec, "[mod_maxminddb]: " __VA_ARGS__)

#ifdef UNUSED
#elif defined(__GNUC__)
#define UNUSED(x) UNUSED_##x __attribute__((unused))
#else
#define UNUSED
#endif

typedef struct maxminddb_config {
    apr_hash_t *databases;
    apr_hash_t *lookups;
    apr_hash_t *database_to_network_variable;
    int enabled;
    int set_notes;
} maxminddb_config;

module AP_MODULE_DECLARE_DATA maxminddb_module;

static void *create_dir_config(apr_pool_t *pool, char *UNUSED(context));
static void *create_srv_config(apr_pool_t *pool, server_rec *s);
static void *create_config(apr_pool_t *pool);
static apr_status_t cleanup_database(void *mmdb);
static char *from_uint128(apr_pool_t *pool, const MMDB_entry_data_s *result);
static char const *get_client_ip(request_rec *r);
static void maxminddb_register_hooks(apr_pool_t *UNUSED(p));
static void *merge_config(apr_pool_t *pool, void *parent, void *child);
void *merge_lookups(apr_pool_t *pool,
                    const void *UNUSED(key),
                    apr_ssize_t UNUSED(klen),
                    const void *h1_val,
                    const void *h2_val,
                    const void *UNUSED(data));
static maxminddb_config *get_config(cmd_parms *cmd, void *dir_config);
static void maxminddb_kv_set(request_rec *r,
                             maxminddb_config *conf,
                             const char *key,
                             const char *val);
static int export_env(request_rec *r, maxminddb_config *conf);
static int export_env_for_dir(request_rec *r);
static int export_env_for_server(request_rec *r);
static void export_env_for_database(request_rec *r,
                                    maxminddb_config *conf,
                                    const char *ip_address,
                                    const char *database_name,
                                    MMDB_s *mmdb);
static void export_env_for_lookups(request_rec *r,
                                   maxminddb_config *conf,
                                   const char *ip_address,
                                   MMDB_lookup_result_s *lookup_result,
                                   apr_hash_t *lookups_for_db);
static const char *set_maxminddb_enable(cmd_parms *cmd, void *config, int arg);
static const char *
set_maxminddb_set_notes(cmd_parms *cmd, void *config, int arg);
static const char *set_maxminddb_env(cmd_parms *cmd,
                                     void *config,
                                     const char *env,
                                     const char *path);
static const char *set_maxminddb_filename(cmd_parms *cmd,
                                          void *config,
                                          const char *database_name,
                                          const char *filename);
static char const *set_maxminddb_network_env(cmd_parms *const cmd,
                                             void *const dir_config,
                                             char const *const database_name,
                                             char const *const env_variable);
static void
maybe_set_network_environment_variable(request_rec *const r,
                                       maxminddb_config *const conf,
                                       char const *const database_name,
                                       MMDB_s const *const mmdb,
                                       struct addrinfo const *const address,
                                       uint16_t const netmask);
static void set_network_environment_variable(request_rec *const r,
                                             maxminddb_config *conf,
                                             char const *const env_var,
                                             uint8_t const *const ip,
                                             int const prefix,
                                             int const family,
                                             uint8_t *const network_ip);

static const command_rec maxminddb_directives[] = {
    AP_INIT_FLAG("MaxMindDBEnable",
                 set_maxminddb_enable,
                 NULL,
                 OR_ALL,
                 "Turn on mod_maxminddb"),
    AP_INIT_FLAG("MaxMindDBSetNotes",
                 set_maxminddb_set_notes,
                 NULL,
                 OR_ALL,
                 "Set Notes alongside env vars"),
    AP_INIT_TAKE2("MaxMindDBFile",
                  set_maxminddb_filename,
                  NULL,
                  OR_ALL,
                  "Path to the Database File"),
    AP_INIT_TAKE2(
        "MaxMindDBEnv", set_maxminddb_env, NULL, OR_ALL, "Set desired env var"),
    AP_INIT_TAKE2("MaxMindDBNetworkEnv",
                  set_maxminddb_network_env,
                  NULL,
                  OR_ALL,
                  "Set desired env var for network"),
    {NULL}};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA maxminddb_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,       /* create per-dir    config structures */
    merge_config,            /* merge  per-dir    config structures */
    create_srv_config,       /* create per-server config structures */
    merge_config,            /* merge  per-server config structures */
    maxminddb_directives,    /* table of config file commands       */
    maxminddb_register_hooks /* register hooks                      */
};

static void maxminddb_kv_set(request_rec *r,
                             maxminddb_config *conf,
                             const char *key,
                             const char *val) {
    apr_table_set(r->subprocess_env, key, val);
    if (conf->set_notes) {
        apr_table_set(r->notes, key, val);
    }
}

static void maxminddb_register_hooks(apr_pool_t *UNUSED(p)) {
    /* make sure we run before mod_rewrite's handler */
    static const char *const asz_succ[] = {
        "mod_setenvif.c", "mod_rewrite.c", NULL};

    ap_hook_header_parser(export_env_for_dir, NULL, asz_succ, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(
        export_env_for_server, NULL, asz_succ, APR_HOOK_MIDDLE);
}

static void *create_srv_config(apr_pool_t *pool, server_rec *UNUSED(d)) {
    return create_config(pool);
}

static void *create_dir_config(apr_pool_t *pool, char *UNUSED(context)) {
    return create_config(pool);
}

static void *create_config(apr_pool_t *pool) {
    maxminddb_config *conf = apr_pcalloc(pool, sizeof(maxminddb_config));

    conf->databases = apr_hash_make(pool);
    conf->lookups = apr_hash_make(pool);
    conf->database_to_network_variable = apr_hash_make(pool);

    /* We use -1 for off but not set */
    conf->enabled = -1;

    conf->set_notes = 0; /* by default, don't set notes */

    return conf;
}

static void *merge_config(apr_pool_t *pool, void *parent, void *child) {
    maxminddb_config *child_conf = (maxminddb_config *)child;
    maxminddb_config *parent_conf = (maxminddb_config *)parent;

    maxminddb_config *conf = apr_pcalloc(pool, sizeof(maxminddb_config));

    conf->enabled =
        child_conf->enabled == -1 ? parent_conf->enabled : child_conf->enabled;

    conf->set_notes = child_conf->set_notes;
    conf->databases =
        apr_hash_overlay(pool, child_conf->databases, parent_conf->databases);
    conf->lookups = apr_hash_merge(
        pool, child_conf->lookups, parent_conf->lookups, merge_lookups, NULL);
    conf->database_to_network_variable =
        apr_hash_overlay(pool,
                         child_conf->database_to_network_variable,
                         parent_conf->database_to_network_variable);

    return conf;
}

void *merge_lookups(apr_pool_t *pool,
                    const void *UNUSED(key),
                    apr_ssize_t UNUSED(klen),
                    const void *h1_val,
                    const void *h2_val,
                    const void *UNUSED(data)) {
    return apr_hash_overlay(pool, h1_val, h2_val);
}

static maxminddb_config *get_config(cmd_parms *cmd, void *dir_config) {
    return cmd->path ? dir_config
                     : ap_get_module_config(cmd->server->module_config,
                                            &maxminddb_module);
}

static const char *
set_maxminddb_enable(cmd_parms *cmd, void *dir_config, int arg) {
    maxminddb_config *conf = get_config(cmd, dir_config);

    if (!conf) {
        return "mod_maxminddb: server structure not allocated";
    }
    conf->enabled = arg;
    INFO(cmd->server, "set_maxminddb_enable: (server) %d", arg);

    return NULL;
}

static const char *
set_maxminddb_set_notes(cmd_parms *cmd, void *dir_config, int arg) {
    maxminddb_config *conf = get_config(cmd, dir_config);

    if (!conf) {
        return "mod_maxminddb: server structure not allocated";
    }
    conf->set_notes = arg;
    INFO(cmd->server, "set_maxminddb_set_notes: (server) %d", arg);

    return NULL;
}

static const char *set_maxminddb_filename(cmd_parms *cmd,
                                          void *dir_config,
                                          const char *database_name,
                                          const char *filename) {
    maxminddb_config *conf = get_config(cmd, dir_config);

    INFO(cmd->server, "set_maxminddb_filename (server) %s", filename);

    MMDB_s *mmdb = apr_pcalloc(cmd->pool, sizeof(MMDB_s));
    int mmdb_error = MMDB_open(filename, MMDB_MODE_MMAP, mmdb);
    if (mmdb_error != MMDB_SUCCESS) {
        return apr_psprintf(cmd->temp_pool,
                            "MaxMindDBFile: Failed to open %s: %s",
                            filename,
                            MMDB_strerror(mmdb_error));
    }

    apr_pool_pre_cleanup_register(cmd->pool, mmdb, cleanup_database);

    apr_hash_set(conf->databases, database_name, APR_HASH_KEY_STRING, mmdb);
    INFO(cmd->server, "Insert db (%s)%s", database_name, filename);

    return NULL;
}

static apr_status_t cleanup_database(void *mmdb) {
    MMDB_close((MMDB_s *)mmdb);
    return APR_SUCCESS;
}

#define MAX_PATH_SEGMENTS 80

static const char *set_maxminddb_env(cmd_parms *cmd,
                                     void *dir_config,
                                     const char *env,
                                     const char *path) {
    maxminddb_config *conf = get_config(cmd, dir_config);

    INFO(cmd->server, "set_maxminddb_env (server) %s %s", env, path);

    char *path_segments[MAX_PATH_SEGMENTS + 1];

    char *tokenized_path = apr_pstrdup(cmd->pool, path);
    int i;
    char *strtok_last = NULL;
    char *token;
    const char *database_name = token =
        apr_strtok(tokenized_path, "/", &strtok_last);

    for (i = 0; i < MAX_PATH_SEGMENTS && token; i++) {
        token = apr_strtok(NULL, "/", &strtok_last);
        path_segments[i] = token;
    }
    path_segments[i] = NULL;

    if (!i) {
        return NULL;
    }
    char **new_path_segments = (char **)apr_pmemdup(
        cmd->pool, path_segments, (size_t)(1 + i) * sizeof(char *));
    apr_hash_t *lookups_for_db =
        apr_hash_get(conf->lookups, database_name, APR_HASH_KEY_STRING);
    if (NULL == lookups_for_db) {
        lookups_for_db = apr_hash_make(cmd->pool);
        apr_hash_set(
            conf->lookups, database_name, APR_HASH_KEY_STRING, lookups_for_db);
    }

    apr_hash_set(lookups_for_db, env, APR_HASH_KEY_STRING, new_path_segments);
    return NULL;
}

static char const *set_maxminddb_network_env(cmd_parms *const cmd,
                                             void *const dir_config,
                                             char const *const database_name,
                                             char const *const env_variable) {
    maxminddb_config *const conf = get_config(cmd, dir_config);

    INFO(cmd->server,
         "set_maxminddb_network_env (server) %s %s",
         database_name,
         env_variable);

    apr_hash_set(conf->database_to_network_variable,
                 database_name,
                 APR_HASH_KEY_STRING,
                 env_variable);
    INFO(cmd->server,
         "Insert network environment variable (%s)%s",
         database_name,
         env_variable);

    return NULL;
}

static int export_env_for_server(request_rec *r) {
    INFO(r->server, "maxminddb_per_server ( enabled )");
    return export_env(
        r, ap_get_module_config(r->server->module_config, &maxminddb_module));
}

static int export_env_for_dir(request_rec *r) {
    INFO(r->server, "maxminddb_per_dir ( enabled )");
    return export_env(
        r, ap_get_module_config(r->per_dir_config, &maxminddb_module));
}

static int export_env(request_rec *r, maxminddb_config *conf) {
    if (!conf || conf->enabled != 1) {
        return DECLINED;
    }
    char const *const ip_address = get_client_ip(r);
    INFO(r->server, "maxminddb_header_parser %s", ip_address);
    if (NULL == ip_address) {
        return DECLINED;
    }
    maxminddb_kv_set(r, conf, "MMDB_ADDR", ip_address);

    for (apr_hash_index_t *db_index = apr_hash_first(r->pool, conf->databases);
         db_index;
         db_index = apr_hash_next(db_index)) {
        const char *database_name;
        MMDB_s *mmdb;
        apr_hash_this(
            db_index, (const void **)&database_name, NULL, (void **)&mmdb);

        export_env_for_database(r, conf, ip_address, database_name, mmdb);
    }

    return OK;
}

static char const *get_client_ip(request_rec *r) {
    const char *addr = apr_table_get(r->subprocess_env, "MMDB_ADDR");
    if (addr) {
        return addr;
    }
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    return r->useragent_ip;
#else
    return r->connection->remote_ip;
#endif
}

static void export_env_for_database(request_rec *r,
                                    maxminddb_config *conf,
                                    const char *ip_address,
                                    const char *database_name,
                                    MMDB_s *mmdb) {
    apr_hash_t *lookups_for_db =
        apr_hash_get(conf->lookups, database_name, APR_HASH_KEY_STRING);
    if (NULL == lookups_for_db) {
        return;
    }

    struct addrinfo const hints = {
        .ai_family = AF_UNSPEC,
        .ai_flags = AI_NUMERICHOST,
        // We set ai_socktype so that we only get one result back
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *addresses = NULL;
    int const gai_status = getaddrinfo(ip_address, NULL, &hints, &addresses);
    if (gai_status != 0) {
        ERROR(r->server,
              "Error resolving IP address '%s': %s", ip_address,
              gai_strerror(gai_status));
        return;
    }
    if (!addresses || !addresses->ai_addr) {
        ERROR(r->server,
              "Error resolving IP address: Address unexpectedly not populated");
        if (addresses) {
            freeaddrinfo(addresses);
        }
        return;
    }

    int mmdb_error = 0;
    MMDB_lookup_result_s lookup_result =
        MMDB_lookup_sockaddr(mmdb, addresses->ai_addr, &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS) {
        ERROR(r->server,
              "Error looking up '%s': %s",
              ip_address,
              MMDB_strerror(mmdb_error));
        freeaddrinfo(addresses);
        return;
    }

    maxminddb_kv_set(r, conf, "MMDB_INFO", "lookup success");

    INFO(r->server, "MMDB_lookup_string %s works", ip_address);

    if (lookup_result.found_entry) {
        export_env_for_lookups(
            r, conf, ip_address, &lookup_result, lookups_for_db);
    }

    maybe_set_network_environment_variable(
        r, conf, database_name, mmdb, addresses, lookup_result.netmask);

    freeaddrinfo(addresses);
}

static void export_env_for_lookups(request_rec *r,
                                   maxminddb_config *conf,
                                   const char *ip_address,
                                   MMDB_lookup_result_s *lookup_result,
                                   apr_hash_t *lookups_for_db) {
    for (apr_hash_index_t *lp_index = apr_hash_first(r->pool, lookups_for_db);
         lp_index;
         lp_index = apr_hash_next(lp_index)) {

        char *env_key;
        const char **lookup_path;
        apr_hash_this(
            lp_index, (const void **)&env_key, NULL, (void **)&lookup_path);

        maxminddb_kv_set(r, conf, "MMDB_INFO", "result found");

        MMDB_entry_data_s result;
        int mmdb_error =
            MMDB_aget_value(&lookup_result->entry, &result, lookup_path);
        if (mmdb_error == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
            // INFO(r->server, MMDB_strerror(mmdb_error));
            continue;
        } else if (mmdb_error != MMDB_SUCCESS) {
            ERROR(r->server,
                  "Error getting data for '%s': %s",
                  ip_address,
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
                    value = apr_pstrmemdup(
                        r->pool, result.utf8_string, result.data_size);
                    break;
                case MMDB_DATA_TYPE_BYTES:
                    /* XXX - treating bytes as strings is broken as they may
                       contain null characters, but there may not be a good
                       fix (short of base 64 encoding it). */
                    value = apr_pstrmemdup(
                        r->pool, (const char *)result.bytes, result.data_size);
                    break;
                case MMDB_DATA_TYPE_FLOAT:
                    value = apr_psprintf(r->pool, "%.5f", result.float_value);
                    break;
                case MMDB_DATA_TYPE_DOUBLE:
                    value = apr_psprintf(r->pool, "%.5f", result.double_value);
                    break;
                case MMDB_DATA_TYPE_UINT16:
                    value = apr_psprintf(r->pool, "%" PRIu16, result.uint16);
                    break;
                case MMDB_DATA_TYPE_UINT32:
                    value = apr_psprintf(r->pool, "%" PRIu32, result.uint32);
                    break;
                case MMDB_DATA_TYPE_INT32:
                    value = apr_psprintf(r->pool, "%" PRIi32, result.int32);
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
                maxminddb_kv_set(r, conf, env_key, value);
            }
        }
    }
}

static char *from_uint128(apr_pool_t *pool, const MMDB_entry_data_s *result) {
#if MMDB_UINT128_IS_BYTE_ARRAY
    uint8_t *p = (uint8_t *)result->uint128;
    return apr_psprintf(pool,
                        "0x"
                        "%02x%02x%02x%02x"
                        "%02x%02x%02x%02x"
                        "%02x%02x%02x%02x"
                        "%02x%02x%02x%02x",
                        p[0],
                        p[1],
                        p[2],
                        p[3],
                        p[4],
                        p[5],
                        p[6],
                        p[7],
                        p[8],
                        p[9],
                        p[10],
                        p[11],
                        p[12],
                        p[13],
                        p[14],
                        p[15]);
#else
    mmdb_uint128_t v = result->uint128;
    return apr_psprintf(
        pool, "0x%016" PRIx64 "%016" PRIx64, (uint64_t)(v >> 64), (uint64_t)v);
#endif
}

static void
maybe_set_network_environment_variable(request_rec *const r,
                                       maxminddb_config *const conf,
                                       char const *const database_name,
                                       MMDB_s const *const mmdb,
                                       struct addrinfo const *const address,
                                       uint16_t prefix) {
    char const *const env_var = apr_hash_get(
        conf->database_to_network_variable, database_name, APR_HASH_KEY_STRING);
    if (!env_var) {
        return;
    }

    if (address->ai_family == AF_INET && mmdb->metadata.ip_version == 6) {
        // The prefix length given the IPv4 address. If there is no IPv4
        // subtree, we use a prefix length of 0.
        prefix = (uint16_t)(prefix >= 96 ? prefix - 96 : 0);
    }

    if (address->ai_family == AF_INET) {
        struct sockaddr_in const *const sin =
            (struct sockaddr_in *)address->ai_addr;
        uint8_t const *const ip = (uint8_t const *)&sin->sin_addr.s_addr;

        uint8_t network_ip[4] = {0};

        set_network_environment_variable(
            r, conf, env_var, ip, prefix, address->ai_family, network_ip);
        return;
    }

    if (address->ai_family == AF_INET6) {
        struct sockaddr_in6 const *const sin =
            (struct sockaddr_in6 *)address->ai_addr;
        uint8_t const *const ip = sin->sin6_addr.s6_addr;

        uint8_t network_ip[16] = {0};

        set_network_environment_variable(
            r, conf, env_var, ip, prefix, address->ai_family, network_ip);
        return;
    }
}

static void set_network_environment_variable(request_rec *const r,
                                             maxminddb_config *conf,
                                             char const *const env_var,
                                             uint8_t const *const ip,
                                             int const prefix,
                                             int const family,
                                             uint8_t *const network_ip) {
    size_t const n_bytes = family == AF_INET ? 4 : 16;
    int prefix2 = prefix;
    for (size_t i = 0; i < n_bytes && prefix2 > 0; i++) {
        uint8_t b = ip[i];
        if (prefix2 < 8) {
            int const shift_n = 8 - prefix2;
            b = (uint8_t)(0xff & (b >> shift_n) << shift_n);
        }
        network_ip[i] = b;
        prefix2 -= 8;
    }

    char ip_str[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(family, network_ip, ip_str, INET6_ADDRSTRLEN) == NULL) {
        return;
    }

    char network_str[256] = {0};
    snprintf(network_str, 256, "%s/%d", ip_str, prefix);

    maxminddb_kv_set(r, conf, env_var, network_str);
}
