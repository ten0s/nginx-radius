#include <assert.h>
#include <ngx_md5.h>
#include "radius_lib.h"

typedef struct radius_auth_t {
    uint8_t         d[16];
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
    uint8_t         attrs[RADIUS_PKG_MAX - sizeof(radius_hdr_t)];
} radius_pkg_t;

typedef struct radius_pkg_builder_t {
    radius_pkg_t   *pkg;
    uint8_t        *pos;
} radius_pkg_builder_t;

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
    uint8_t chap_data[16];
} radius_attr_chap_passwd_t;

typedef struct radius_attr_desc_t {
    radius_attr_type_t type;
    uint8_t            len_min;
    uint8_t            len_max;
} radius_attr_desc_t;

#define RADIUS_ATTR_USER_NAME           1
#define RADIUS_ATTR_USER_PASSWORD       2
#define RADIUS_ATTR_CHAP_PASSWORD       3
#define RADIUS_ATTR_NAS_IP_ADDRESS      4
#define RADIUS_ATTR_NAS_PORT            5
#define RADIUS_ATTR_NAS_IDENTIFIER      32

#define RADIUS_ATTR_DESC_ITEM(t, lmin, lmax) \
    .type = t,                               \
    .len_min = lmin,                         \
    .len_max = lmax

static radius_attr_desc_t attrs_desc[] = {
    [RADIUS_ATTR_USER_NAME] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_str, 1, 61)
    },
    [RADIUS_ATTR_USER_PASSWORD] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_str, 16, 128)
    },
    [RADIUS_ATTR_CHAP_PASSWORD] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_chap_passwd,
                              sizeof(radius_attr_chap_passwd_t),
                              sizeof(radius_attr_chap_passwd_t))
    },
    [RADIUS_ATTR_NAS_IP_ADDRESS] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_address, 4, 4)
    },
    [RADIUS_ATTR_NAS_PORT] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_address, 4, 4)
    },
    [RADIUS_ATTR_NAS_IDENTIFIER] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_str, 3, 64)
    },
};

static void
init_radius_pkg(radius_pkg_builder_t *b, void *buf, int len);

static void
gen_authenticator(radius_auth_t *auth);

static radius_error_t
check_str_attr_range_mem(radius_pkg_builder_t *b,
                         int radius_attr_id,
                         uint16_t len);

static radius_error_t
make_access_request_pkg(radius_pkg_builder_t *b,
                        uint8_t ident,
                        const ngx_str_t *secret,
                        const ngx_str_t *user,
                        const ngx_str_t *passwd,
                        const ngx_str_t *nas_id);

static radius_error_t
update_pkg_len(radius_pkg_builder_t *b);

size_t
create_radius_pkg(void *buf, size_t len,
                  uint8_t ident,
                  const ngx_str_t *user,
                  const ngx_str_t *passwd,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id,
                  uint8_t *auth)
{
    radius_pkg_builder_t b;

    init_radius_pkg(&b, buf, len);
    gen_authenticator(&b.pkg->hdr.auth);
    if (auth) {
        ngx_memcpy(auth, &b.pkg->hdr.auth, sizeof(b.pkg->hdr.auth));
    }
    make_access_request_pkg(&b, ident, secret, user, passwd, nas_id);

    update_pkg_len(&b);

    return b.pos - (uint8_t *)b.pkg;
}

int
parse_radius_pkg(const void *buf, size_t len,
                 uint8_t ident,
                 const ngx_str_t *secret,
                 const uint8_t *auth)
{
    radius_pkg_t *pkg = (radius_pkg_t *) buf;
    uint16_t pkg_len = ntohs(pkg->hdr.len);
    if (len != pkg_len) {
        return -1;
    }

    // Check correlation id matches
    if (ident != pkg->hdr.ident) {
        return -2;
    }

    ngx_md5_t ctx;
    ngx_md5_init(&ctx);

    char save_auth[sizeof(pkg->hdr.auth)];
    uint8_t check[sizeof(pkg->hdr.auth)];

    ngx_memcpy(save_auth, &pkg->hdr.auth, sizeof(save_auth));
    ngx_memcpy(&pkg->hdr.auth, auth, sizeof(pkg->hdr.auth));
    ngx_md5_update(&ctx, pkg, len);
    ngx_md5_update(&ctx, secret->data, secret->len);
    ngx_md5_final(check, &ctx);

    if (ngx_memcmp(save_auth, check, sizeof(save_auth)) != 0) {
        return -3;
    }

    return pkg->hdr.code;
}

static void
init_radius_pkg(radius_pkg_builder_t *b, void *buf, int len)
{
    b->pkg = buf;
    assert(len == RADIUS_PKG_MAX);
    b->pos = b->pkg->attrs;
}

static void
gen_authenticator(radius_auth_t *auth)
{
    uint8_t i;
    for(i = 0; i < sizeof(radius_auth_t); i++) {
        auth->d[i] = (uint8_t)(random() & UCHAR_MAX);
    }
}

static radius_error_t
check_str_attr_range_mem(radius_pkg_builder_t *b,
                         int radius_attr_id,
                         uint16_t len)
{
    if (len < attrs_desc[radius_attr_id].len_min ||
        len > attrs_desc[radius_attr_id].len_max) {
        return radius_err_range;
    }

    size_t remain = sizeof(b->pkg->attrs) - (b->pos - b->pkg->attrs);
    size_t str_attr_len_need = sizeof(radius_attr_hdr_t) + len;
    if (str_attr_len_need > remain) {
        return radius_err_mem;
    }

    return radius_err_ok;
}

static radius_error_t
put_passwd_crypt(radius_pkg_builder_t *b,
                 const ngx_str_t *secret,
                 const ngx_str_t *passwd)
{
    uint8_t pwd_padded_len = 16 * (1 + passwd->len / 16);
    radius_error_t rc = check_str_attr_range_mem(b,
                                                 RADIUS_ATTR_USER_PASSWORD,
                                                 pwd_padded_len);
    if (rc != radius_err_ok) {
        return rc;
    }

    ngx_md5_t ctx;
    ngx_md5_t s_ctx;

    ngx_md5_init(&s_ctx);
    ngx_md5_update(&s_ctx, secret->data, secret->len);

    ctx = s_ctx;
    ngx_md5_update(&ctx, &b->pkg->hdr.auth, sizeof(b->pkg->hdr.auth));

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *)b->pos;

    ah->type = RADIUS_ATTR_USER_PASSWORD;
    b->pos += sizeof(radius_attr_hdr_t);

    ngx_md5_final(b->pos, &ctx);

    uint8_t pwd_remain = passwd->len;
    uint8_t pwd_padded_remain = pwd_padded_len;
    uint8_t *p = passwd->data;
    uint8_t *c = b->pos;

    ah->len = sizeof(radius_attr_hdr_t) + pwd_padded_remain;

    uint8_t i;
    for(; pwd_padded_remain ;) {
        for(i = 0; i < 16; i++) {
            *c++ ^= pwd_remain ? *p++ : 0;
            if (pwd_remain) {
                pwd_remain--;
            }
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
put_str_attr(radius_pkg_builder_t *b, int radius_attr_id, const ngx_str_t *str)
{
    radius_error_t rc = check_str_attr_range_mem(b, radius_attr_id, str->len);
    if (rc != radius_err_ok) {
        return rc;
    }

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *) b->pos;
    ah->type = radius_attr_id;
    ah->len = str->len + sizeof(radius_attr_hdr_t);
    b->pos += sizeof(radius_attr_hdr_t);
    ngx_memcpy(b->pos, str->data, str->len);
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

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *) b->pos;
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
                        const ngx_str_t *secret,
                        const ngx_str_t *user,
                        const ngx_str_t *passwd,
                        const ngx_str_t *nas_id)
{
    assert(b && user && passwd);
    b->pkg->hdr.code = RADIUS_CODE_ACCESS_REQUEST;
    b->pkg->hdr.ident = ident;

    radius_error_t rc;
    rc = put_str_attr(b, RADIUS_ATTR_USER_NAME, user);
    if (rc != radius_err_ok) {
        return rc;
    }

    rc = put_passwd_crypt(b, secret, passwd);
    if (rc != radius_err_ok) {
        return rc;
    }

    if (nas_id->len >= 3) {
        rc = put_str_attr(b, RADIUS_ATTR_NAS_IDENTIFIER, nas_id);
        if (rc != radius_err_ok) {
            return rc;
        }
    }

    return radius_err_ok;
}

static radius_error_t
update_pkg_len(radius_pkg_builder_t *b)
{
    uint16_t len = b->pos - (uint8_t *) &b->pkg->hdr;
    b->pkg->hdr.len = htons(len);
    return radius_err_ok;
}
