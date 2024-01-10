#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "logger.h"
#include "radius_lib.h"

#define ARR_LEN(arr) sizeof(arr)/sizeof(arr[0])

#define RADIUS_DEFAULT_PORT 1812

struct radius_server_s;
typedef struct radius_req_s {
    uint8_t id;
    uint8_t buf[RADIUS_PKG_MAX];
    uint8_t auth[AUTH_BUF_SIZE];
    uint8_t active:1;
    uint8_t accepted:1;
    struct radius_server_s *rs;
    ngx_connection_t *conn;
    ngx_http_request_t *http_req;
    struct radius_req_s *next;
} radius_req_t;

typedef struct radius_server_s {
    uint8_t id;
    struct sockaddr *sockaddr;
    socklen_t socklen;
    ngx_str_t secret;
    ngx_str_t nas_id;
    // Effectively, the number of concurrent requests that can be
    // processed without retrying. See ngx_http_auth_radius_handler.
    // TODO: get 'queue_size' [1..255] from server config
    radius_req_t req_queue[10];
    radius_req_t *req_free_list;
    radius_req_t *req_last_list;
} radius_server_t;

typedef struct {
    ngx_array_t *servers;
    ngx_msec_t timeout;
    ngx_uint_t retries;
    ngx_str_t secret;
} ngx_http_auth_radius_main_conf_t;

typedef struct {
    ngx_str_t realm;
} ngx_http_auth_radius_loc_conf_t;

typedef struct {
    uint8_t rs_idx;
    uint8_t retries;
    radius_req_t *req;
    uint8_t done:1;
    uint8_t accepted:1;
    uint8_t timedout:1;
    uint8_t connection_refused:1;
    uint8_t internal_error:1;
} ngx_http_auth_radius_ctx_t;

static ngx_int_t
ngx_http_auth_radius_init(ngx_conf_t *cf);

static void *
ngx_http_auth_radius_create_main_conf(ngx_conf_t *cf);

static void *
ngx_http_auth_radius_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_auth_radius_merge_loc_conf(ngx_conf_t *cf,
                                    void *parent,
                                    void *child);

static char *
ngx_http_auth_radius_set_radius_server(ngx_conf_t *cf,
                                       ngx_command_t *cmd,
                                       void *conf);

static char *
ngx_http_auth_radius_set_radius_timeout(ngx_conf_t *cf,
                                        ngx_command_t *cmd,
                                        void *conf);

static char *
ngx_http_auth_radius_set_radius_retries(ngx_conf_t *cf,
                                         ngx_command_t *cmd,
                                         void *conf);

static char *
ngx_http_auth_radius_set_auth_radius(ngx_conf_t *cf,
                                     ngx_command_t *cmd,
                                     void *conf);

static ngx_int_t
ngx_http_auth_radius_init_servers(ngx_cycle_t *cycle);

static void
ngx_http_auth_radius_destroy_servers(ngx_cycle_t *cycle);

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

    { ngx_string("radius_retries"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_radius_set_radius_retries,
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

static void
radius_read_handler(ngx_event_t *ev);

static void
radius_retry_handler(ngx_event_t *ev);

static ngx_int_t
init_radius_servers(ngx_array_t *servers, ngx_log_t *log);

static void
destroy_radius_servers(ngx_array_t* servers, ngx_log_t *log);

static ngx_connection_t *
create_radius_connection(struct sockaddr *sockaddr,
                         socklen_t socklen,
                         ngx_log_t *log);

static void
close_radius_connection(ngx_connection_t *c);

static void
add_radius_server(radius_server_t *rs,
                  int rs_id,
                  struct sockaddr *sockaddr,
                  socklen_t socklen,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id);

static ngx_int_t
select_radius_server(ngx_http_request_t *r,
                     ngx_http_auth_radius_main_conf_t *mcf,
                     ngx_http_auth_radius_ctx_t *ctx);

static ngx_int_t
send_radius_request(ngx_http_request_t *r,
                    ngx_http_auth_radius_main_conf_t *mcf,
                    ngx_http_auth_radius_ctx_t *ctx,
                    radius_req_t *req);

static ngx_int_t
set_realm(ngx_http_request_t *r, const ngx_str_t *realm);

static radius_req_t *
acquire_radius_req(radius_server_t* rs);

static void
release_radius_req(radius_req_t *req);

static int
send_radius_pkg(radius_req_t *req,
                const ngx_str_t *user,
                const ngx_str_t *passwd,
                ngx_msec_t timeout,
                ngx_log_t *log);
static int
recv_radius_pkg(radius_req_t *req,
                radius_server_t *rs,
                ngx_log_t *log);

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
            return set_realm(r, &lcf->realm);
        }

        // Create and store context
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            LOG_ERR(log, ngx_errno, "ngx_pcalloc failed r: 0x%xl", r);
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_auth_radius_module);
    }

    if (ctx->done) {
        if (ctx->internal_error) {
            LOG_INFO(log, "internal error r: 0x%xl", r);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ctx->timedout || ctx->connection_refused) {
            if (ctx->timedout) {
                LOG_INFO(log, "timedout r: 0x%xl", r);
            } else {
                LOG_INFO(log, "connection refused r: 0x%xl", r);
            }
            ctx->rs_idx++;
            if (ctx->rs_idx >= mcf->servers->nelts) {
                LOG_INFO(log, "no more servers r: 0x%xl", r);
                return NGX_HTTP_SERVICE_UNAVAILABLE;
            } else {
                LOG_INFO(log, "try next server r: 0x%xl", r);
                return select_radius_server(r, mcf, ctx);
            }
        }

        if (!ctx->accepted) {
            LOG_INFO(log, "rejected r: 0x%xl", r);
            return set_realm(r, &lcf->realm);
        }

        LOG_INFO(log, "accepted r: 0x%xl", r);
        return NGX_OK;
    }

    return select_radius_server(r, mcf, ctx);
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

static void *
ngx_http_auth_radius_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auth_radius_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_radius_main_conf_t));
    if (mcf == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno, "ngx_pcalloc failed");
        return NGX_CONF_ERROR;
    }

    mcf->servers = ngx_array_create(cf->pool, 5, sizeof(radius_server_t));
    if (mcf->servers == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno, "ngx_array_create failed");
        return NGX_CONF_ERROR;
    }

    mcf->timeout = 5000;
    mcf->retries = 3;

    return mcf;
}

static void *
ngx_http_auth_radius_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_radius_loc_conf_t *lcf;
    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_radius_loc_conf_t));
    if (lcf == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno, "ngx_pcalloc failed");
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

    ngx_str_t *secret = &value[2];

    ngx_str_t *nas_id = NULL;
    if (cf->args->nelts == 4) {
        nas_id = &value[3];
    }

    radius_server_t *rs = ngx_array_push(mcf->servers);
    if (rs == NULL) {
        CONF_LOG_EMERG(cf, ngx_errno,
                       "\"%V\" nomem",
                       &value[0]);
        return NGX_CONF_ERROR;
    }

    int rs_id = mcf->servers->nelts;
    add_radius_server(rs, rs_id,
                      u.addrs[0].sockaddr,
                      u.addrs[0].socklen,
                      secret, nas_id);

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
ngx_http_auth_radius_set_radius_retries(ngx_conf_t *cf,
                                         ngx_command_t *cmd,
                                         void *conf)
{
    ngx_str_t* value = cf->args->elts;

    ngx_http_auth_radius_main_conf_t* mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_radius_module);

    ngx_int_t retries = ngx_atoi(value[1].data, value[1].len);
    if (retries == NGX_ERROR) {
        CONF_LOG_EMERG(cf, ngx_errno,
                       "invalid \"radius_retries\" value: \"%V\"",
                       &value[1]);
        return NGX_CONF_ERROR;
    }

    mcf->retries = retries;

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
        CONF_LOG_EMERG(cf, ngx_errno, "ngx_pcalloc failed");
        return NGX_CONF_ERROR;
    }

    uint8_t *p;
    p = ngx_cpymem(lcf->realm.data,
                   "Basic realm=\"",
                   sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, value[1].data, value[1].len);
    *p = '"';

    return NGX_CONF_OK;
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
    return init_radius_servers(mcf->servers, log);
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
    destroy_radius_servers(mcf->servers, log);
}

static ngx_int_t
init_radius_servers(ngx_array_t *servers, ngx_log_t *log)
{
    if (servers == NULL) {
        LOG_EMERG(log, 0, "no radius servers");
        return NGX_ERROR;
    }

    size_t i, j;
    radius_server_t *rss = servers->elts;
    for (i = 0; i < servers->nelts; ++i) {
        radius_server_t *rs = &rss[i];

        sa_family_t family = rs->sockaddr->sa_family;
        char host[INET6_ADDRSTRLEN] = "";
        uint16_t port = 0;
        if (family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)rs->sockaddr;
            inet_ntop(family, &sa->sin_addr, host, sizeof(host)),
            port = ntohs(sa->sin_port);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)rs->sockaddr;
            inet_ntop(family, &sa->sin6_addr, host, sizeof(host)),
            port = ntohs(sa->sin6_port);
        } else {
            LOG_ERR(log, 0, "unknown family: %d", family);
        }
        LOG_DEBUG(log, "server: %d, addr: %s:%d", i, host, port);

        for (j = 0; j < ARR_LEN(rs->req_queue); ++j) {
            radius_req_t *req = &rs->req_queue[j];
            ngx_connection_t *c = create_radius_connection(rs->sockaddr,
                                                           rs->socklen, log);
            if (c == NULL) {
                destroy_radius_servers(servers, log);
                return NGX_ERROR;
            }
            req->conn = c;
            c->data = req;
            req->rs = rs;
        }
    }

    return NGX_OK;
}

static void
destroy_radius_servers(ngx_array_t* servers, ngx_log_t *log)
{
    if (servers == NULL) {
        LOG_EMERG(log, 0, "no radius servers");
        return;
    }

    size_t i, j;
    radius_server_t *rss = servers->elts;
    for (i = 0; i < servers->nelts; ++i) {
        radius_server_t *rs = &rss[i];
        for (j = 0; j < ARR_LEN(rs->req_queue); ++j) {
           radius_req_t *req = &rs->req_queue[j];
            if (req->conn) {
                close_radius_connection(req->conn);
                req->conn = NULL;
                req->rs = NULL;
            }
        }
    }

    // No need to free the array, since the pool
    // should free it automatically
}

static ngx_connection_t *
create_radius_connection(struct sockaddr *sockaddr,
                         socklen_t socklen,
                         ngx_log_t *log)
{
    // Create UDP socket
    int sockfd = ngx_socket(sockaddr->sa_family, SOCK_DGRAM, 0);
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
    c->read->handler = radius_read_handler;
    c->read->log = c->log;

    // Subscribe to read data event
    if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) {
        LOG_ERR(log, ngx_errno,
                "ngx_add_event failed, sockfd: %d", sockfd);
        ngx_close_connection(c);
        return NULL;
    }

    sa_family_t family = sockaddr->sa_family;
    char host[INET6_ADDRSTRLEN] = "";
    uint16_t port = 0;
    if (family == AF_INET) {
        struct sockaddr_in sa;
        ngx_memset(&sa, 0, sizeof(sa));
        if (getsockname(sockfd, (struct sockaddr *)&sa, &socklen) != -1) {
            inet_ntop(family, &sa.sin_addr, host, sizeof(host)),
            port = ntohs(sa.sin_port);
        } else {
            LOG_ERR(log, ngx_errno, "getsockname sockaddr_in failed");
        }
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sa;
        ngx_memset(&sa, 0, sizeof(sa));
        if (getsockname(sockfd, (struct sockaddr *)&sa, &socklen) != -1) {
            inet_ntop(family, &sa.sin6_addr, host, sizeof(host)),
            port = ntohs(sa.sin6_port);
        } else {
            LOG_ERR(log, ngx_errno, "getsockname sockaddr_in6 failed");
        }
    } else {
        LOG_ERR(log, 0, "unknown family: %d", family);
    }
    LOG_DEBUG(log, "sockfd: %d, addr: %s:%d", sockfd, host, port);

    return c;
}

static void
close_radius_connection(ngx_connection_t *c)
{
    ngx_close_connection(c);
}

static void
add_radius_server(radius_server_t *rs,
                  int rs_id,
                  struct sockaddr *sockaddr,
                  socklen_t socklen,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id)
{
    rs->id = rs_id;
    rs->sockaddr = sockaddr;
    rs->socklen = socklen;
    rs->secret = *secret;
    if (nas_id) {
        rs->nas_id = *nas_id;
    }
    ngx_memset(rs->req_queue, 0, sizeof(rs->req_queue));

    size_t i;
    radius_req_t *req;
    for (i = 1; i < ARR_LEN(rs->req_queue); ++i) {
        req = &rs->req_queue[i];
        req->id = i;
        rs->req_queue[i - 1].next = req;
    }
    rs->req_free_list = &rs->req_queue[0];
    rs->req_last_list = req;
}

static ngx_int_t
select_radius_server(ngx_http_request_t *r,
                     ngx_http_auth_radius_main_conf_t *mcf,
                     ngx_http_auth_radius_ctx_t *ctx)
{
    ngx_log_t *log = r->connection->log;

    radius_server_t *rss = mcf->servers->elts;
    radius_server_t *rs = &rss[ctx->rs_idx];

    radius_req_t *req = acquire_radius_req(rs);
    if (req == NULL) {
        LOG_NOTICE(log, 0, "requests queue is full, retrying...");
        // TODO: log message about increasing 'queue_size'

        // Subscribe to retry timeout event
        ngx_event_t *ev = ngx_pcalloc(r->pool, sizeof(ngx_event_t));
        if (ev == NULL) {
            LOG_ERR(log, ngx_errno, "ngx_pcalloc failed r: 0x%xl", r);
            return NGX_ERROR;
        }
        ev->data = r;
        ev->handler = radius_retry_handler;
        ev->log = r->connection->log;
        ngx_add_timer(ev, 100);

        return NGX_AGAIN;
    }

    ctx->retries = mcf->retries;
    ctx->req = req;
    ctx->done = 0;
    ctx->accepted = 0;
    ctx->timedout = 0;
    ctx->connection_refused = 0;
    ctx->internal_error = 0;

    req->http_req = r;

    LOG_DEBUG(log, "r: 0x%xl, rs: 0x%xl, req: 0x%xl, req_id: %d",
              r, rs, req, req->id);
    int rc = send_radius_request(r, mcf, ctx, req);
    if (rc == NGX_ERROR) {
        LOG_INFO(log, "internal error r: 0x%xl", r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_AGAIN;
}

static ngx_int_t
send_radius_request(ngx_http_request_t *r,
                    ngx_http_auth_radius_main_conf_t *mcf,
                    ngx_http_auth_radius_ctx_t *ctx,
                    radius_req_t *req)
{
    ngx_log_t *log = r->connection->log;

    // Send RADIUS Auth request
    int rc = send_radius_pkg(req,
                             &r->headers_in.user,
                             &r->headers_in.passwd,
                             mcf->timeout,
                             log);
    if (rc == -1) {
        LOG_ERR(log, 0, "req failed r: 0x%xl, req: 0x%xl, req_id: %d",
                r, req, req->id);
        return NGX_ERROR;
    }

    LOG_DEBUG(log,
              "r: 0x%xl, req: 0x%xl, req_id: %d",
              r, req, req->id);

    return NGX_AGAIN;
}

static ngx_int_t
set_realm(ngx_http_request_t *r, const ngx_str_t *realm)
{
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (uint8_t *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

static radius_req_t *
acquire_radius_req(radius_server_t* rs)
{
    radius_req_t *req = rs->req_free_list;
    if (req) {
        rs->req_free_list = req->next;
        req->active = 1;
        if (rs->req_free_list == NULL) {
            rs->req_last_list = NULL;
        }
    }
    return req;
}

static void
release_radius_req(radius_req_t *req)
{
    radius_server_t *rs = req->rs;
    req->active = 0;
    req->next = NULL;
    req->http_req = NULL;

    if (rs->req_last_list) {
        rs->req_last_list->next = req;
        rs->req_last_list = req;
        return;
    }

    assert(rs->req_free_list == rs->req_last_list &&
           rs->req_free_list == NULL);
    rs->req_free_list = rs->req_last_list = req;
}

static int
send_radius_pkg(radius_req_t *req,
                const ngx_str_t *user,
                const ngx_str_t *passwd,
                ngx_msec_t timeout,
                ngx_log_t *log)
{
    size_t len = create_radius_pkg(req->buf, sizeof(req->buf),
                                   req->id,
                                   user, passwd,
                                   &req->rs->secret,
                                   &req->rs->nas_id,
                                   req->auth);

    int rc = send(req->conn->fd, req->buf, len, 0);
    if (rc == -1) {
        LOG_ERR(log, ngx_errno,
                "send failed, fd: %d, r: 0x%xl, len: %u",
                req->conn->fd, req->http_req, len);
        return -1;
    }

    // Subscribe to read timeout event
    ngx_add_timer(req->conn->read, timeout);

    return 0;
}

static int
recv_radius_pkg(radius_req_t *req,
                radius_server_t *rs,
                ngx_log_t *log)
{
    // Read as much as possible
    int prev_rc = -1;
    for (;;) {
        ssize_t len = recv(req->conn->fd,
                           req->buf, sizeof(req->buf),
                           MSG_TRUNC);
        if (len == -1) {
            if (ngx_errno != EAGAIN) {
                LOG_ERR(log, ngx_errno, "recv failed, r: 0x%xl, req: 0x%xl",
                        req->http_req, req);
            }
            // Nothing can be received any more, exit
            return prev_rc;
        }

        if (len > (ssize_t) sizeof(req->buf)) {
            LOG_ERR(log, 0, "recv buf too small, r: 0x%xl, req: 0x%xl",
                    req->http_req, req);
            continue;
        }

        int rc = parse_radius_pkg(req->buf, len,
                                  req->id,
                                  req->auth,
                                  &req->rs->secret);
        if (rc < 0) {
            switch (rc) {
            case -1:
                LOG_ERR(log, 0,
                        "parse pkg error: incorrect pkg len: %d, r: 0x%xl, req: 0x%xl",
                        len, req->http_req, req);
                break;
            case -2:
                LOG_ERR(log, 0,
                        "parse pkg error: req_id doesn't match, r: 0x%xl, req: 0x%xl",
                        req->http_req, req);
                break;
            case -3:
                LOG_ERR(log, 0,
                        "parse pkg error: incorrect auth, r: 0x%xl, req: 0x%xl",
                        req->http_req, req);
                break;
            default:
                LOG_ERR(log, 0,
                        "parse pkg error: unknown rc: %d, r: 0x%xl, req: 0x%xl",
                        rc, req->http_req, req);
                break;
            }

            continue;
        }

        req->accepted = rc == RADIUS_AUTH_ACCEPTED;
        return rc;
    }
}

static void
radius_retry_handler(ngx_event_t *ev)
{
    ngx_http_request_t *r = ev->data;
    ngx_post_event(r->connection->write, &ngx_posted_events);
}

static void
radius_read_handler(ngx_event_t *ev)
{
    ngx_log_t *log = ev->log;

    ngx_connection_t *c = ev->data;
    radius_req_t *req = c->data;
    ngx_http_request_t *r = req->http_req;

    if (r == NULL) {
        LOG_ERR(log, 0, "r == NULL, unexpected data received, flush it");
        uint8_t buf[RADIUS_PKG_MAX];
        for (;;) {
            ssize_t len = recv(req->conn->fd,
                               buf, sizeof(buf),
                               MSG_TRUNC);
            if (len == -1) {
                if (ngx_errno != EAGAIN) {
                    LOG_ERR(log, ngx_errno,
                            "recv failed, r: 0x%xl, req: 0x%xl",
                            req->http_req, req);
                }
                break;
            }
        }
        return;
    }

    ngx_http_auth_radius_main_conf_t *mcf;
    mcf = ngx_http_get_module_main_conf(r, ngx_http_auth_radius_module);

    ngx_http_auth_radius_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_radius_module);
    if (ctx == NULL) {
        LOG_EMERG(log, 0, "ctx not found r: 0x%xl", r);
        release_radius_req(req);
        return;
    }

    assert(ctx->req == req);

    if (ev->timedout) {
        ev->timedout = 0;

        ctx->retries--;
        LOG_DEBUG(log, "timedout r: 0x%xl, retries: %d", r, ctx->retries);

        if (!ctx->retries) {
            ctx->done = 1;
            ctx->timedout = 1;
            goto auth_done;
        }

        // Re-send RADIUS Auth event
        ngx_int_t rc = send_radius_request(r, mcf, ctx, req);
        if (rc == NGX_ERROR) {
            ctx->done = 1;
            ctx->internal_error = 1;
            goto auth_done;
        }
        return;
    }

    radius_server_t *rs = req->rs;
    int rc = recv_radius_pkg(req, rs, log);
    if (rc == -1) {
        if (ngx_errno == ECONNREFUSED) {
            LOG_ERR(log, 0, "recv radius pkg: connection refused r: 0x%xl", r);
            ctx->done = 1;
            ctx->connection_refused = 1;
            goto auth_done;
        } else {
            LOG_ERR(log, 0, "recv radius pkg: bad pkg r: 0x%xl", r);
            // Handle error in read timeout
            return;
        }
    } else {
        // Remove read timeout event
        if (req->conn->read->timer_set) {
            req->conn->read->timer_set = 0;
            ngx_del_timer(req->conn->read);
        }
    }

    LOG_DEBUG(log,
              "accepted: %d, r: 0x%xl, req: 0x%xl, req_id: %d",
              req->accepted, r, req, req->id);

    ctx->done = 1;
    ctx->accepted = req->accepted;

auth_done:
    // Post RADIUS Auth done event
    ngx_post_event(r->connection->write, &ngx_posted_events);
    release_radius_req(req);
}
