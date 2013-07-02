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
#include "MMDB.h"

typedef struct {
    MMDB_s *mmdb;
    char *filename;
    int enabled;
    int flags;
} maxminddb_server_config_rec;

typedef maxminddb_server_config_rec maxminddb_dir_config_rec;

module AP_MODULE_DECLARE_DATA maxminddb_module;

static void set_env_for_ip(request_rec * r, const char *filename,
                           const char *ipaddr);

/* create a disabled directory entry */

static void *create_dir_config(apr_pool_t * p, char *d)
{

    maxminddb_dir_config_rec *dcfg;

    dcfg =
        (maxminddb_dir_config_rec *) apr_pcalloc(p,
                                                 sizeof
                                                 (maxminddb_dir_config_rec));
    dcfg->enabled = 0;

    return dcfg;
}

/* create a standard disabled server entry */

static void *create_server_config(apr_pool_t * p, server_rec * d)
{
    maxminddb_server_config_rec *conf =
        apr_pcalloc(p, sizeof(maxminddb_server_config_rec));
    if (!conf) {
        return NULL;
    }

    conf->mmdb = NULL;
    conf->enabled = 0;
    conf->flags = 0;
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

}

static void child_init(apr_pool_t * p, server_rec * s)
{
    maxminddb_server_config_rec *cfg;
    int i, flags;

    cfg = (maxminddb_server_config_rec *)
        ap_get_module_config(s->module_config, &maxminddb_module);

}

/* map into the first apache */
static int post_config(apr_pool_t * p, apr_pool_t * plog,
                       apr_pool_t * ptemp, server_rec * s)
{
    server_init(p, s);
    return OK;
}

static int maxminddb_header_parser(request_rec * r);

static int maxminddb_post_read_request(request_rec * r)
{
    maxminddb_server_config_rec *cfg;
    cfg = ap_get_module_config(r->server->module_config, &maxminddb_module);

    if (!cfg)
        return DECLINED;

    if (!cfg->enabled)
        return DECLINED;

    return maxminddb_header_parser(r);
}

static int maxminddb_per_dir(request_rec * r)
{

    maxminddb_dir_config_rec *dcfg;

    dcfg = ap_get_module_config(r->per_dir_config, &maxminddb_module);
    if (!dcfg)
        return DECLINED;

    if (!dcfg->enabled)
        return DECLINED;

    return maxminddb_header_parser(r);
}

char *_get_client_ip(request_rec * r)
{
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    return r->useragent_ip;
# else
    return r->connection->remote_ip;
#endif
}

static int maxminddb_header_parser(request_rec * r)
{
    char *ipaddr;
    char *free_me = NULL;

    maxminddb_server_config_rec *cfg;

    char *ipaddr_ptr = NULL;
    cfg = ap_get_module_config(r->server->module_config, &maxminddb_module);

    if (!cfg)
        return DECLINED;

    ipaddr = _get_client_ip(r);

//    if (!cfg->filename)
//        return DECLINED;

    set_env_for_ip(r, cfg->filename, ipaddr);
    return OK;
}

static void set_env_for_ip(request_rec * r, const char *filename,
                           const char *ipaddr)
{
    int bsize = 1024;
    char buffer[bsize];
    struct in6_addr v6;
    apr_table_set(r->subprocess_env, "MAXMINDDB_ADDR", ipaddr);
    MMDB_s *mmdb = MMDB_open(filename, MMDB_MODE_STANDARD);
    MMDB_root_entry_s root = {.entry.mmdb = mmdb };

    if (!mmdb)
        return;

    int ai_family = AF_INET6;
    int ai_flags = AI_V4MAPPED;

    if ((ipaddr != NULL)
        && (0 == MMDB_lookupaddressX(ipaddr, ai_family, ai_flags, &v6))) {

        int status = MMDB_lookup_by_ipnum_128(v6, &root);
        if (status == MMDB_SUCCESS && root.entry.offset > 0) {

            MMDB_return_s res_location;
            MMDB_get_value(&root.entry, &res_location, "location", NULL);
            MMDB_return_s lat, lon;
            MMDB_entry_s location = {.mmdb = root.entry.mmdb,.offset =
                    res_location.offset
            };
            if (res_location.offset) {
                MMDB_get_value(&location, &lat, "latitude", NULL);
                if (lat.offset > 0) {
                    snprintf(buffer, bsize, "%.5f", lat.double_value);
                    apr_table_set(r->subprocess_env, "MAXMINDDB_LATITUDE",
                                  buffer);
                }

                MMDB_get_value(&location, &lon, "longitude", NULL);
                if (lon.offset > 0) {
                    snprintf(buffer, bsize, "%.5f", lon.double_value);
                    apr_table_set(r->subprocess_env, "MAXMINDDB_LONGITUDE",
                                  buffer);
                }
            }
        }
    }
    MMDB_close(mmdb);
}

static const char *set_maxminddb_enable(cmd_parms * cmd, void *dummy, int arg)
{
    maxminddb_server_config_rec *conf;

    /* is per directory config? */
    if (cmd->path) {
        maxminddb_dir_config_rec *dcfg = dummy;
        dcfg->enabled = arg;
        return NULL;
    }
    /* no then it is server config */
    conf = (maxminddb_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &maxminddb_module);

    if (!conf)
        return "mod_maxminddb: server structure not allocated";

    conf->enabled = arg;
    return NULL;
}

static const char *set_maxminddb_filename(cmd_parms * cmd, void *dummy,
                                          const char *filename,
                                          const char *arg2)
{
    int i;
    maxminddb_server_config_rec *conf = (maxminddb_server_config_rec *)
        ap_get_module_config(cmd->server->module_config, &maxminddb_module);

    if (!filename)
        return NULL;

    conf->filename = (char *)apr_pstrdup(cmd->pool, filename);
    return NULL;
}

static void *make_maxminddb(apr_pool_t * p, server_rec * d)
{
    maxminddb_server_config_rec *dcfg;

    dcfg =
        (maxminddb_server_config_rec *) apr_pcalloc(p,
                                                    sizeof
                                                    (maxminddb_server_config_rec));
    dcfg->mmdb = NULL;
    dcfg->filename = NULL;
    dcfg->enabled = 0;
    return dcfg;
}

static const command_rec maxminddb_cmds[] = {
    AP_INIT_FLAG("MaxMindDBEnable", set_maxminddb_enable, NULL,
                 RSRC_CONF | OR_FILEINFO, "Turn on mod_maxminddb"),
    AP_INIT_TAKE12("MaxMindDBFile", set_maxminddb_filename, NULL,
                   RSRC_CONF | OR_FILEINFO,
                   "Path to the Database File"),
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
    ap_hook_header_parser(maxminddb_per_dir, NULL, aszSucc, APR_HOOK_FIRST);

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
    STANDARD20_MODULE_STUFF, create_dir_config, /* create per-dir    config structures */
        NULL,                   /* merge  per-dir    config structures */
        make_maxminddb,         /* create per-server config structures */
        NULL,                   /* merge  per-server config structures */
        maxminddb_cmds,         /* table of config file commands       */
        maxminddb_register_hooks        /* register hooks                      */
};
