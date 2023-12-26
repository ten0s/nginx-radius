#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include "logger.h"
#include "radius_client.h"

typedef struct {
    ngx_array_t             *servers;
    ngx_msec_t               timeout;
    ngx_uint_t               attempts;
    radius_str_t             secret;
} ngx_http_auth_radius_main_conf_t;

typedef struct {
    ngx_str_t                realm;
} ngx_http_auth_radius_loc_conf_t;

typedef struct ngx_http_auth_radius_ctx_t {
    u_char                   digest[32];
    uint8_t                  attempts;
    radius_req_queue_node_t *rqn;
    uint8_t                  done:1;
    uint8_t                  accepted:1;
    uint8_t                  timedout:1;
} ngx_http_auth_radius_ctx_t;

static void *
ngx_http_auth_radius_create_main_conf(ngx_conf_t *cf);

static void *
ngx_http_auth_radius_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_auth_radius_merge_loc_conf(ngx_conf_t *cf,
                                    void *parent,
                                    void *child);

static char *
ngx_http_auth_radius_set_auth_radius(ngx_conf_t *cf,
                                     ngx_command_t *cmd,
                                     void *conf);

static char *
ngx_http_auth_radius_set_radius_server(ngx_conf_t *cf,
                                       ngx_command_t *cmd,
                                       void *conf);
static char*
ngx_http_auth_radius_set_radius_timeout(ngx_conf_t *cf,
                                        ngx_command_t *cmd,
                                        void *conf);

static char*
ngx_http_auth_radius_set_radius_attempts(ngx_conf_t *cf,
                                         ngx_command_t *cmd,
                                         void *conf);

static ngx_int_t
ngx_http_auth_radius_init(ngx_conf_t *cf);

static ngx_int_t
ngx_http_auth_radius_init_servers(ngx_cycle_t *cycle);

static void
ngx_http_auth_radius_destroy_servers(ngx_cycle_t *cycle);

static ngx_int_t
ngx_http_auth_radius_send_radius_request(ngx_http_request_t *r,
                                         radius_req_queue_node_t *prev_req);

static ngx_int_t
ngx_http_auth_radius_set_realm(ngx_http_request_t *r,
                               const ngx_str_t *realm);

static void
ngx_http_auth_radius_read_handler(ngx_event_t *rev);


static ngx_command_t ngx_http_auth_radius_commands[] = {

    { ngx_string("radius_server"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE23,
      ngx_http_auth_radius_set_radius_server,
      0,
      0,
      NULL },

    { ngx_string("radius_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_radius_set_radius_timeout,
      0,
      0,
      NULL },

    { ngx_string("radius_attempts"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_radius_set_radius_attempts,
      0,
      0,
      NULL },

    { ngx_string("auth_radius"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_radius_set_auth_radius,
      0,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_radius_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_http_auth_radius_init,               /* postconfiguration */
    ngx_http_auth_radius_create_main_conf,   /* create main configuration */
    NULL,                                    /* init main configuration */
    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
    ngx_http_auth_radius_create_loc_conf,    /* create location configuration */
    ngx_http_auth_radius_merge_loc_conf,     /* merge location configuration */
};

ngx_module_t ngx_http_auth_radius_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_radius_module_ctx,        /* module context */
    ngx_http_auth_radius_commands,           /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    ngx_http_auth_radius_init_servers,       /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    ngx_http_auth_radius_destroy_servers,    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};

#define RADIUS_STR_FROM_NGX_STR_INITIALIZER(ns) .len = ns.len, .s = ns.data

static ngx_connection_t *
create_connection(struct sockaddr *sockaddr,
                  socklen_t socklen,
                  ngx_log_t *log)
{
    // Create UDP socket
    int sockfd = ngx_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        LOG_ERR(log, ngx_errno, "ngx_socket failed");
        return NULL;
    }

    // Set socket to non-blocking mode
    if (ngx_nonblocking(sockfd) == -1) {
        LOG_ERR(log, ngx_errno,
                "ngx_nonblocking failed, sockfd: %d", sockfd);
        ngx_close_socket(sockfd);
        return NULL;
    }

    // Connect socket to make it possible to use
    // recv(2)/send(2) instead of recvfrom(2)/sendto(2)
    if (connect(sockfd, sockaddr, socklen) == -1) {
        LOG_ERR(log, ngx_errno, "connect failed");
        ngx_close_socket(sockfd);
        return NULL;
    }

    // Get connection around socket
    ngx_connection_t *c = ngx_get_connection(sockfd, log);
    if (c == NULL) {
        LOG_ERR(log, ngx_errno,
                "ngx_get_connection failed, sockfd: %d", sockfd);
        ngx_close_socket(sockfd);
        return NULL;
    }

    c->log = log;
    c->data = NULL;
    c->read->handler = ngx_http_auth_radius_read_handler;
    c->read->log = c->log;

    // Subscribe to read data event
    if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) {
        LOG_ERR(log, ngx_errno,
                "ngx_add_event failed, sockfd: %d", sockfd);
        ngx_close_connection(c);
        return NULL;
    }

    return c;
}

static void
close_connection(ngx_connection_t *c)
{
    ngx_close_connection(c);
}

static void
ngx_http_auth_radius_read_handler(ngx_event_t *rev)
{
    ngx_log_t *log = rev->log;
    assert(log != NULL);

    ngx_connection_t *c = rev->data;

    radius_req_queue_node_t *rqn = c->data;

    ngx_http_request_t *r = rqn->data;
    assert(r != NULL);

    ngx_http_auth_radius_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_radius_module);
    if (ctx == NULL) {
        LOG_EMERG(log, 0, "ctx not found, r: 0x%xl", r);
        // TODO: free connection and req
        //return;
        goto cleanup;
    }

    assert(ctx->rqn == rqn);

    if (rev->timedout) {
        rev->timedout = 0;
        ctx->attempts--;
        LOG_DEBUG(log, "timeout 0x%xl, attempt: %d",
                  r, ctx->attempts);

        if (!ctx->attempts) {
            ctx->done = 1;
            ctx->accepted = 0;
            ctx->timedout = 1;
            ngx_post_event(r->connection->write, &ngx_posted_events);
            // TODO: free connection and req
            //close_connection(c);
            //return;
            goto cleanup;
        }

        // Re-send RADIUS Auth event
        ngx_http_auth_radius_send_radius_request(r, rqn);
        // TODO: free connection and req
        //close_connection(c);
        //return;
        goto cleanup;
    }

    if (rev->timer_set) {
        rev->timer_set = 0;
        ngx_del_timer(rev);
    }

    radius_server_t *rs = get_server_by_req(rqn, log);
    radius_req_queue_node_t *rqn2 = radius_recv_request(c, rs, log);
    if (rqn2 == NULL) {
        LOG_ERR(log, 0, "req not found");
        // TODO: propagate HTTP_TOO_MANY_REQUESTS
        // solution: increase queue size -> create config
        return;
    }

    if (rqn != rqn2) {
        LOG_ERR(log, 0, "req doesn't match");
        //return;
    }

    LOG_DEBUG(log,
              "r: 0x%xl, req: 0x%xl, req_id: %d, acc: %d",
              r, rqn, rqn->ident, rqn->accepted);

    ctx->done = 1;
    ctx->accepted = rqn->accepted;

    // Post RADIUS Auth done event
    ngx_post_event(r->connection->write, &ngx_posted_events);

cleanup:
    close_connection(c);
    release_req_queue_node(rqn, log);
}

static ngx_int_t
ngx_http_auth_radius_send_radius_request(ngx_http_request_t *r,
                                         radius_req_queue_node_t *prev_req)
{
    ngx_log_t *log = r->connection->log;

    LOG_INFO(log, "r: 0x%xl", r);

    ngx_http_auth_radius_main_conf_t *mcf;
    mcf = ngx_http_get_module_main_conf(r, ngx_http_auth_radius_module);

    ngx_http_auth_radius_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_radius_module);

    if (ctx == NULL) {
        LOG_EMERG(log, 0, "ctx not found");
        return NGX_ERROR;
    }

    radius_str_t user = {
        RADIUS_STR_FROM_NGX_STR_INITIALIZER(r->headers_in.user)
    };
    radius_str_t passwd = {
        RADIUS_STR_FROM_NGX_STR_INITIALIZER(r->headers_in.passwd)
    };

    // Send RADIUS Auth request

    // TODO:
    // For each server there should be N connections allocated

    radius_server_t *rss = mcf->servers->elts;
    radius_server_t *rs = &rss[0];
    ngx_connection_t *c = create_connection(rs->sockaddr, rs->socklen, log);

    radius_req_queue_node_t *rqn;
    rqn = radius_send_request(c,
                              mcf->servers,
                              prev_req,
                              &user, &passwd,
                              log);
    if (rqn == NULL) {
        LOG_ERR(log, 0, "rqn not found r: 0x%xl", r);
        return NGX_ERROR;
    }

    // DKL: what's going on here
    //radius_server_t *rs = get_server_by_req(rqn, log);
    LOG_DEBUG(log,
            "r: 0x%xl, req: 0x%xl, req_id: %d",
            r, rqn, rqn->ident);

    c->data = rqn;
    ctx->rqn = rqn;
    rqn->data = r;

    // DKL: move to create connection?
    // Subscribe to read timeout event
    ngx_event_t *rev = c->read;
    ngx_add_timer(rev, mcf->timeout);

    return NGX_AGAIN;
}

static ngx_int_t
ngx_http_auth_radius_set_realm(ngx_http_request_t *r,
                               const ngx_str_t *realm)
{
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t
ngx_http_auth_radius_handler(ngx_http_request_t *r)
{
    ngx_log_t *log = r->connection->log;

    ngx_http_auth_radius_main_conf_t *mcf;
    mcf = ngx_http_get_module_main_conf(r, ngx_http_auth_radius_module);

    ngx_http_auth_radius_loc_conf_t *lcf;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_radius_module);

    if (lcf->realm.data == NULL || lcf->realm.len == 0) {
        // No RADIUS realm defined
        return NGX_DECLINED;
    }

    ngx_http_auth_radius_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_radius_module);

    if (ctx == NULL) {
        // No RADIUS Auth request sent yet
        LOG_INFO(log, "started r: 0x%xl", r);

        // Parse credentials
        ngx_int_t rc = ngx_http_auth_basic_user(r);
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else if (rc == NGX_DECLINED) {
            return ngx_http_auth_radius_set_realm(r, &lcf->realm);
        }

        // TODO: move to _send_radius_request?

        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            LOG_ERR(log, ngx_errno, "nx_pcalloc failed r: 0x%xl", r);
            return NGX_ERROR;
        }

        ctx->attempts = mcf->attempts;
        ctx->done = 0;
        ctx->accepted = 0;
        ctx->timedout = 0;
        ngx_http_set_ctx(r, ctx, ngx_http_auth_radius_module);

        return ngx_http_auth_radius_send_radius_request(r, NULL);
    }

    if (!ctx->done) {
        LOG_INFO(log, "not done r: 0x%xl", r);
        return NGX_AGAIN;
    }

    if (!ctx->accepted) {
        if (ctx->timedout) {
            LOG_INFO(log, "timedout r: 0x%xl", r);
            return NGX_HTTP_SERVICE_UNAVAILABLE;
        } else {
            LOG_INFO(log, "rejected r: 0x%xl", r);
            return ngx_http_auth_radius_set_realm(r, &lcf->realm);
        }
    }

    LOG_INFO(log, "accepted r: 0x%xl", r);
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_radius_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno, "ngx_array_push failed");
        return NGX_ERROR;
    }

    *h = ngx_http_auth_radius_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_radius_init_servers(ngx_cycle_t *cycle)
{
    ngx_http_auth_radius_main_conf_t *mcf;
    mcf = ngx_http_cycle_get_module_main_conf(cycle,
                                              ngx_http_auth_radius_module);

    if (mcf == NULL) {
        return NGX_ERROR;
    }

    ngx_log_t *log = cycle->log;
    LOG_DEBUG(log, "");
    return radius_init_servers(mcf->servers, log);
}

static void
ngx_http_auth_radius_destroy_servers(ngx_cycle_t *cycle)
{
    ngx_http_auth_radius_main_conf_t *mcf;
    mcf = ngx_http_cycle_get_module_main_conf(cycle,
                                              ngx_http_auth_radius_module);

    if (mcf == NULL) {
        return;
    }

    ngx_log_t *log = cycle->log;
    LOG_DEBUG(log, "");
    radius_destroy_servers(mcf->servers, log);
}

static void *
ngx_http_auth_radius_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auth_radius_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_radius_main_conf_t));
    if (mcf == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno, "nx_pcalloc failed");
        return NGX_CONF_ERROR;
    }

    mcf->servers = ngx_array_create(cf->pool, 5, sizeof(radius_server_t));
    if (mcf->servers == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno, "nx_array_create failed");
        return NGX_CONF_ERROR;
    }

    mcf->attempts = NGX_CONF_UNSET;
    mcf->timeout = NGX_CONF_UNSET_MSEC;

    return mcf;
}

static void *
ngx_http_auth_radius_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_radius_loc_conf_t *lcf;
    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_radius_loc_conf_t));
    if (lcf == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno, "nx_pcalloc failed" );
        return NGX_CONF_ERROR;
    }

    lcf->realm.data = NULL;

    return lcf;
}

static char*
ngx_http_auth_radius_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    //ngx_http_auth_radius_main_conf_t *prev = parent;
    //ngx_http_auth_radius_loc_conf_t *conf = child;

    //ngx_conf_merge_str_value(conf->realm, prev->realm, "");

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_radius_set_radius_server(ngx_conf_t *cf,
                                       ngx_command_t *cmd,
                                       void *conf)
{
    ngx_str_t *value = cf->args->elts;

    if (cf->args->nelts != 3 && cf->args->nelts != 4) {
        CONF_LOG_EMERG(cf, 0,
                       "invalid \"%V\" config",
                       &value[0]);
        return NGX_CONF_ERROR;
    }

    ngx_http_auth_radius_main_conf_t *mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_radius_module);

    ngx_url_t u;
    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.uri_part = 1;
    u.default_port = RADIUS_DEFAULT_PORT;
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            CONF_LOG_EMERG(cf, ngx_errno,
                           "invalid \"%V\" \"url\" value: \"%V\"",
                           &value[0], &value[1]);
        }
        return NGX_CONF_ERROR;
    }

    radius_str_t secret;
    secret.s = value[2].data;
    secret.len = value[2].len;

    mcf->secret.s = secret.s;
    mcf->secret.len = secret.len;

    radius_str_t nas_id;
    nas_id.s = NULL;
    nas_id.len = 0;

    if (cf->args->nelts == 4) {
        nas_id.s = value[3].data;
        nas_id.len = value[3].len;
    }

    radius_server_t *rs = ngx_array_push(mcf->servers);
    if (rs == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno,
                       "\"%V\" nomem",
                       &value[0]);
        return NGX_CONF_ERROR;
    }

    int rs_id = mcf->servers->nelts;
    radius_add_server(rs, rs_id,
                      u.addrs[0].sockaddr, u.addrs[0].socklen,
                      &secret, &nas_id);

    return NGX_CONF_OK;
}

static char*
ngx_http_auth_radius_set_radius_timeout(ngx_conf_t *cf,
                                        ngx_command_t *cmd,
                                        void *conf)
{
    ngx_str_t* value = cf->args->elts;

    ngx_http_auth_radius_main_conf_t* mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_radius_module);

    ngx_int_t timeout = ngx_parse_time(&value[1], 0);
    if (timeout == NGX_ERROR) {
        CONF_LOG_EMERG(cf, ngx_errno,
                       "invalid \"radius_timeout\" value: \"%V\"",
                       &value[1]);
        return NGX_CONF_ERROR;
    }
    mcf->timeout = timeout;

    return NGX_CONF_OK;
}

static char*
ngx_http_auth_radius_set_radius_attempts(ngx_conf_t *cf,
                                         ngx_command_t *cmd,
                                         void *conf)
{
    ngx_str_t* value = cf->args->elts;

    ngx_http_auth_radius_main_conf_t* mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_radius_module);

    ngx_int_t attempts = ngx_atoi(value[1].data, value[1].len);
    if (attempts == NGX_ERROR) {
        CONF_LOG_EMERG(cf, ngx_errno,
                       "invalid \"radius_attempts\" value: \"%V\"",
                       &value[1]);
        return NGX_CONF_ERROR;
    }
    mcf->attempts = attempts;

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_radius_set_auth_radius(ngx_conf_t *cf,
                                     ngx_command_t *cmd,
                                     void *conf)
{
    ngx_str_t *value = cf->args->elts;

    if (ngx_strncmp(value[1].data, "off", 3) == 0) {
        return NGX_CONF_OK;
    }

    ngx_http_auth_radius_loc_conf_t *lcf =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_auth_radius_module);

    lcf->realm.len = sizeof("Basic realm=\"") - 1 + value[1].len + 1;
    lcf->realm.data = ngx_pcalloc(cf->pool, lcf->realm.len);
    if (lcf->realm.data == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno, "nx_pcalloc failed");
        return NGX_CONF_ERROR;
    }

    u_char *p;
    p = ngx_cpymem(lcf->realm.data,
                   "Basic realm=\"",
                   sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, value[1].data, value[1].len);
    *p = '"';

    return NGX_CONF_OK;
}
