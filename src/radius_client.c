#include <assert.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include "logger.h"
#include "radius_client.h"

#define RADIUS_PKG_MAX  4096
#define RADIUS_STR_INIT(str) .s = str, .len = strlen(str)

typedef struct radius_auth_t {
    unsigned char   d[16]; // DKL: what's this?
} radius_auth_t;

typedef struct radius_hdr_t {
    uint8_t         code;
    uint8_t         ident;
    uint16_t        len;
    radius_auth_t   auth;
} radius_hdr_t;

typedef struct radius_attr_hdr_t {
    uint8_t         type;
    uint8_t         len;
} radius_attr_hdr_t;

typedef struct radius_pkg_t {
    radius_hdr_t    hdr;
    unsigned char   attrs[RADIUS_PKG_MAX - sizeof(radius_hdr_t)];
} radius_pkg_t;

typedef struct radius_pkg_builder_t {
    radius_pkg_t   *pkg;
    unsigned char  *pos;
} radius_pkg_builder_t;

static unsigned char
radius_random() {
    return (unsigned char)(random() & UCHAR_MAX);
}

typedef enum {
    radius_attr_type_str,
    radius_attr_type_address,
    radius_attr_type_integer,
    radius_attr_type_time,
    radius_attr_type_chap_passwd,
} radius_attr_type_t;

typedef enum {
    radius_err_ok,
    radius_err_range,
    radius_err_mem,
} radius_error_t;

typedef struct radius_attr_chap_passwd_t {
    uint8_t chap_ident;
    unsigned char chap_data[16];
} radius_attr_chap_passwd_t;

typedef struct radius_attr_desc_t {
    radius_attr_type_t type;
    uint8_t            len_min;
    uint8_t            len_max;
} radius_attr_desc_t;

#define RADIUS_CODE_ACCESS_REQUEST      1
#define RADIUS_CODE_ACCESS_ACCEPT       2
#define RADIUS_CODE_ACCESS_REJECT       3
#define RADIUS_CODE_ACCESS_CHALLENGE    4

#define RADIUS_ATTR_USER_NAME           1
#define RADIUS_ATTR_USER_PASSWORD       2
#define RADIUS_ATTR_CHAP_PASSWORD       3
#define RADIUS_ATTR_NAS_IP_ADDRESS      4
#define RADIUS_ATTR_NAS_PORT            5
#define RADIUS_ATTR_NAS_IDENTIFIER      32

#define RADIUS_SERVER_MAGIC_HDR     0x55AA00FF

#define RADIUS_ATTR_DESC_ITEM(t, lmin, lmax) .type = t, .len_min =  lmin, .len_max = lmax

static radius_attr_desc_t attrs_desc[] = {
    [RADIUS_ATTR_USER_NAME]         { RADIUS_ATTR_DESC_ITEM(radius_attr_type_str, 1, 61) },
    [RADIUS_ATTR_USER_PASSWORD]     { RADIUS_ATTR_DESC_ITEM(radius_attr_type_str, 16, 128) },
    [RADIUS_ATTR_CHAP_PASSWORD]     { RADIUS_ATTR_DESC_ITEM(radius_attr_type_chap_passwd,
                                                            sizeof(radius_attr_chap_passwd_t),
                                                            sizeof(radius_attr_chap_passwd_t)) },
    [RADIUS_ATTR_NAS_IP_ADDRESS]    { RADIUS_ATTR_DESC_ITEM(radius_attr_type_address, 4, 4) },
    [RADIUS_ATTR_NAS_PORT]          { RADIUS_ATTR_DESC_ITEM(radius_attr_type_address, 4, 4) },
    [RADIUS_ATTR_NAS_IDENTIFIER]    { RADIUS_ATTR_DESC_ITEM(radius_attr_type_str, 3, 64) },
};

radius_server_t *
radius_add_server(radius_server_t *rs,
                  int rs_id,
                  struct sockaddr *sockaddr,
                  socklen_t socklen,
                  radius_str_t *secret,
                  radius_str_t *nas_id)
{
    rs->magic = RADIUS_SERVER_MAGIC_HDR;
    rs->id = rs_id;
    rs->sockfd = -1;
    rs->sockaddr = sockaddr;
    rs->socklen = socklen;
    rs->secret = *secret;
    rs->nas_id = *nas_id;
    ngx_memset(rs->req_queue, 0, sizeof(rs->req_queue));

    size_t i;
    radius_req_queue_node_t *rqn;
    for (i = 1; i < sizeof(rs->req_queue)/sizeof(rs->req_queue[0]); ++i) {
        rqn = &rs->req_queue[i];
        rqn->ident = i;
        rs->req_queue[i - 1].next = rqn;
    }
    rs->req_free_list = &rs->req_queue[0];
    rs->req_last_list = rqn;

    return rs;
}

ngx_int_t
radius_init_servers(ngx_array_t *radius_servers, ngx_log_t *log)
{
    size_t i;
    radius_server_t *rss;
    radius_server_t *rs;

    if (radius_servers == NULL) {
        LOG_EMERG(log, 0, "no radius_servers");
        return NGX_ERROR;
    }

    rss = radius_servers->elts;
    for (i = 0; i < radius_servers->nelts; i++) {
        rs = &rss[i];
        int sockfd = ngx_socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            LOG_ERR(log, ngx_errno, "ngx_socket failed");
            return NGX_ERROR;
        }

        // Get connection around socket
        ngx_connection_t *c = ngx_get_connection(sockfd, log);
        if (c == NULL) {
            LOG_ERR(log, ngx_errno,
                    "ngx_get_connection failed, sockfd: %d", sockfd);
            ngx_close_socket(sockfd);
            return NGX_ERROR;
        }

        if (ngx_nonblocking(sockfd) == -1) {
            LOG_ERR(log, ngx_errno,
                    "ngx_nonblocking failed, sockfd: %d", sockfd);
            ngx_free_connection(c);
            ngx_close_socket(sockfd);
            return NGX_ERROR;
        }

        // Subscribe to read data event
        if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) {
            LOG_ERR(log, ngx_errno,
                    "ngx_add_event failed, sockfd: %d", sockfd);
            ngx_free_connection(c);
            ngx_close_socket(sockfd);
            return NGX_ERROR;
        }

        rs->sockfd = sockfd;
        rs->data = c;
        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    }

    return NGX_OK;
}

void radius_destroy_servers(ngx_array_t* radius_servers, ngx_log_t *log)
{
    size_t i;
    radius_server_t *rss;
    radius_server_t *rs;

    if (radius_servers == NULL) {
        LOG_EMERG(log, 0, "no radius_servers");
        return;
    }

    rss = radius_servers->elts;
    for (i = 0; i < radius_servers->nelts; i++) {
        rs = &rss[i];
        ngx_connection_t *c = rs->data;
        int sockfd = rs->sockfd;

        ngx_del_event(c->read, NGX_READ_EVENT, NGX_LEVEL_EVENT);
        ngx_free_connection(c); // TODO: ngx_close_connection?
        ngx_close_socket(sockfd);

        rs->sockfd = -1;
        rs->data = NULL;
    }

    // No need to free the array, since the pool
    // should free it automatically
}

radius_req_queue_node_t *
acquire_req_queue_node(radius_server_t* rs, ngx_log_t *log)
{
    radius_req_queue_node_t *rqn = rs->req_free_list;
    if (rqn) {
        rs->req_free_list = rqn->next;
        rqn->active = 1;
        if (rs->req_free_list == NULL)
            rs->req_last_list = NULL;
    }
    return rqn;
}

radius_server_t *
get_server_by_req(radius_req_queue_node_t *rqn, ngx_log_t *log)
{
    radius_server_t *rs;
    radius_req_queue_node_t *base = rqn - rqn->ident;
    rs = (radius_server_t *) ((char *)base - offsetof(radius_server_t, req_queue));
    if (rs->magic != RADIUS_SERVER_MAGIC_HDR) {
        LOG_EMERG(log, 0, "invalid magic hdr");
        abort();
    }
    return rs;
}

void
release_req_queue_node(radius_req_queue_node_t *rqn, ngx_log_t *log)
{
    ngx_http_request_t *r = rqn->data;

    radius_server_t *rs;
    rs = get_server_by_req(rqn, log);
    if (rs == NULL) {
        LOG_ERR(log, 0, "rs not found, r: 0x%xl, req: 0x%xl, req_id: %d",
                r, rqn, rqn->ident);
        return;
    }

    LOG_DEBUG(log, "r: 0x%xl, req: 0x%xl, req_id: %d", r, rqn, rqn->ident);

    rqn->active = 0;
    rqn->next = NULL;
    rqn->data = NULL;

    if (rs->req_last_list) {
        rs->req_last_list->next = rqn;
        rs->req_last_list = rqn;
        return;
    }

    assert(rs->req_free_list == rs->req_last_list &&
           rs->req_free_list == NULL);
    rs->req_free_list = rs->req_last_list = rqn;
}

radius_req_queue_node_t *
radius_recv_request(radius_server_t *rs, ngx_log_t *log)
{
    ssize_t len = recv(rs->sockfd,
                       rs->process_buf, sizeof(rs->process_buf),
                       MSG_TRUNC);
    if (len < 0 || len > (int) sizeof(rs->process_buf)) {
        LOG_ERR(log, ngx_errno, "recv failed");
        return NULL;
    }

    radius_pkg_t *pkg = (radius_pkg_t *) rs->process_buf;
    uint16_t pkg_len = ntohs(pkg->hdr.len);
    if (len != pkg_len) {
        LOG_ERR(log, 0, "incorrect pkg len: %d | %d", len, pkg_len);
        return NULL;
    }

    radius_req_queue_node_t *rqn;
    rqn = &rs->req_queue[pkg->hdr.ident];
    if (rqn->active == 0) {
        LOG_ERR(log, 0, "active = 0, 0x%xl, r: 0x%xl", rqn, rqn->data);
        return NULL;
    }

    ngx_md5_t ctx;
    ngx_md5_init(&ctx);

    char save_auth[sizeof(pkg->hdr.auth)];
    unsigned char check[sizeof(pkg->hdr.auth)];

    ngx_memcpy(save_auth, &pkg->hdr.auth, sizeof(save_auth));
    ngx_memcpy(&pkg->hdr.auth, &rqn->auth, sizeof(pkg->hdr.auth));
    ngx_md5_update(&ctx, pkg, len);
    ngx_md5_update(&ctx, rs->secret.s, rs->secret.len);
    ngx_md5_final(check, &ctx);

    if (ngx_memcmp(save_auth, check, sizeof(save_auth)) != 0) {
        LOG_ERR(log, 0, "incorrect auth, r: 0x%xl", rqn->data);
        return NULL;
    }

    rqn->accepted = pkg->hdr.code == RADIUS_CODE_ACCESS_ACCEPT;
    return rqn;
}

radius_req_queue_node_t *
radius_send_request(ngx_array_t * radius_servers,
                    radius_req_queue_node_t * prev_req,
                    radius_str_t *user,
                    radius_str_t *passwd,
                    ngx_log_t *log)
{
    radius_server_t *rss = radius_servers->elts;
    radius_server_t *rs;

    if (prev_req == NULL) {
        rs = &rss[0];
    } else {
        rs = get_server_by_req(prev_req, log);
        rs = &rss[(rs->id + 1) % radius_servers->nelts];
        release_req_queue_node(prev_req, log);
    }

    radius_req_queue_node_t *rqn;
    rqn = acquire_req_queue_node(rs, log);
    if (rqn == NULL) {
        LOG_ERR(log, 0, "req not found");
        // TODO: try next server?
        return NULL;
    }

    LOG_DEBUG(log, "req: 0x%xl, req_id: %d", rqn, rqn->ident);

    int len = create_radius_req(rs->process_buf, sizeof(rs->process_buf),
                                rqn->ident, user, passwd,
                                &rs->secret, &rs->nas_id, rqn->auth);

    int rc = sendto(rs->sockfd,
                    rs->process_buf, len,
                    0, rs->sockaddr, rs->socklen);
    if (rc == -1) {
        LOG_ERR(log, ngx_errno,
                "sendto failed, fd: %d, r: 0x%xl, len: %u",
                rs->sockfd, rqn->data, len);
        release_req_queue_node(rqn, log);
        return NULL;
    }

    return rqn;
}

static void
init_radius_pkg(radius_pkg_builder_t *b, void *buf, int len)
{
    b->pkg = buf;
    assert(len == RADIUS_PKG_MAX); // TODO
    b->pos = b->pkg->attrs;
}

static void
gen_authenticator(radius_auth_t *auth)
{
    uint8_t i;
    for(i = 0; i < sizeof(radius_auth_t); i++)
        auth->d[i] = radius_random();
}

static radius_error_t
check_str_attr_range_mem(radius_pkg_builder_t *b, int radius_attr_id, uint16_t len)
{
    if (len < attrs_desc[radius_attr_id].len_min
                    || len > attrs_desc[radius_attr_id].len_max)
        return radius_err_range;
    size_t remain = sizeof(b->pkg->attrs) - (b->pos - b->pkg->attrs);
    size_t str_attr_len_need = sizeof(radius_attr_hdr_t) + len;
    if (str_attr_len_need > remain)
        return radius_err_mem;
    return radius_err_ok;

}

static radius_error_t
put_passwd_crypt(radius_pkg_builder_t *b, radius_str_t *secret, radius_str_t *passwd)
{
    uint8_t pwd_padded_len = 16 * (1 + passwd->len / 16);
    radius_error_t rc = check_str_attr_range_mem(b, RADIUS_ATTR_USER_PASSWORD, pwd_padded_len);
    if (rc != radius_err_ok)
        return rc;

    ngx_md5_t ctx;
    ngx_md5_t s_ctx;

    ngx_md5_init(&s_ctx);
    ngx_md5_update(&s_ctx, secret->s, secret->len);

    ctx = s_ctx;
    ngx_md5_update(&ctx, &b->pkg->hdr.auth, sizeof(b->pkg->hdr.auth));

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *)b->pos;

    ah->type = RADIUS_ATTR_USER_PASSWORD;
    b->pos += sizeof(radius_attr_hdr_t);

    ngx_md5_final(b->pos, &ctx);

    uint8_t pwd_remain = passwd->len;
    uint8_t pwd_padded_remain = pwd_padded_len;
    unsigned char *p = passwd->s;
    unsigned char *c = b->pos;

    ah->len = sizeof(radius_attr_hdr_t) + pwd_padded_remain;

    uint8_t i;
    for(; pwd_padded_remain ;) {
        for(i = 0; i < 16; i++) {
            *c++ ^= pwd_remain ? *p++ : 0;
            if (pwd_remain)
                pwd_remain--;
        }
        ctx = s_ctx;
        pwd_padded_remain -= 16;
        if (!pwd_padded_remain) {
            b->pos += 16;
            break;
        }
        ngx_md5_update(&ctx, b->pos, c - b->pos);
        b->pos += 16;
        ngx_md5_final(b->pos, &ctx);
    }

    return radius_err_ok;
}

static int
put_str_attr(radius_pkg_builder_t *b, int radius_attr_id, radius_str_t *str)
{
    radius_error_t rc = check_str_attr_range_mem(b, radius_attr_id, str->len);
    if (rc != radius_err_ok)
        return rc;

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *)b->pos;
    ah->type = radius_attr_id;
    ah->len = str->len + sizeof(radius_attr_hdr_t);
    b->pos += sizeof(radius_attr_hdr_t);
    ngx_memcpy(b->pos, str->s, str->len);
    b->pos += str->len;
    return radius_err_ok;
}

#if 0
static radius_error_t
put_addr_attr(radius_pkg_builder_t* b, int radius_attr_id, uint32_t addr)
{
    size_t remain = sizeof(b->pkg->attrs) - (b->pos - b->pkg->attrs);
    size_t attr_len_need = sizeof(radius_attr_hdr_t) + sizeof(addr);
    if (attr_len_need > remain)
        return radius_err_mem;

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *)b->pos;
    ah->type = radius_attr_id;
    ah->len = attr_len_need;
    b->pos += sizeof(radius_attr_hdr_t);
    uint32_t *v = (uint32_t *)b->pos;
    *v = addr;
    b->pos += sizeof(addr);

    return radius_err_ok;
}
#endif

static radius_error_t
make_access_request_pkg(radius_pkg_builder_t *b,
                        uint8_t ident,
                        radius_str_t *secret,
                        radius_str_t *user,
                        radius_str_t *passwd,
                        radius_str_t *nas_id)
{
    assert(b && user && passwd);
    b->pkg->hdr.code = RADIUS_CODE_ACCESS_REQUEST;
    b->pkg->hdr.ident = ident;

    radius_error_t rc;
    rc = put_str_attr(b, RADIUS_ATTR_USER_NAME, user);
    if (rc != radius_err_ok)
        return rc;

    rc = put_passwd_crypt(b, secret, passwd);
    if (rc != radius_err_ok)
        return rc;

    if (nas_id->len >= 3) {
        rc = put_str_attr(b, RADIUS_ATTR_NAS_IDENTIFIER, nas_id);
        if (rc != radius_err_ok)
            return rc;
    }

    return radius_err_ok;
}

static radius_error_t
update_pkg_len(radius_pkg_builder_t *b)
{
    uint16_t l = b->pos - (unsigned char*)&b->pkg->hdr;
    b->pkg->hdr.len = htons(l);
    return radius_err_ok;
}

uint16_t
create_radius_req(void *buf, size_t len,
                  uint8_t ident,
                  radius_str_t *user,
                  radius_str_t *passwd,
                  radius_str_t *secret,
                  radius_str_t *nas_id,
                  unsigned char *auth)
{
    radius_pkg_builder_t b;

    init_radius_pkg(&b, buf, len);
    gen_authenticator(&b.pkg->hdr.auth);
    if (auth)
        ngx_memcpy(auth, &b.pkg->hdr.auth, sizeof(b.pkg->hdr.auth));
    make_access_request_pkg(&b, ident, secret, user, passwd, nas_id);

    update_pkg_len(&b);

    return b.pos - (unsigned char *)b.pkg;
}
