#include <assert.h>
#include <ngx_md5.h>
#include "radius_lib.h"

typedef struct {
    uint8_t         d[16];
} radius_auth_t;

typedef struct {
    uint8_t         code;
    uint8_t         id;
    uint16_t        len;
    radius_auth_t   auth;
} radius_hdr_t;

typedef struct {
    uint8_t         type;
    uint8_t         len;
} radius_attr_hdr_t;

typedef struct {
    radius_hdr_t    hdr;
    uint8_t         attrs[RADIUS_PKG_MAX - sizeof(radius_hdr_t)];
} radius_pkg_t;

typedef struct {
    radius_pkg_t   *pkg;
    uint8_t        *pos;
} radius_pkg_builder_t;

// Data Type Definitions
// https://www.rfc-editor.org/rfc/rfc8044#section-3
typedef enum {
    radius_attr_type_integer,
    radius_attr_type_string,
} radius_attr_type_t;

typedef enum {
    radius_err_ok,
    radius_err_range,
    radius_err_mem,
} radius_error_t;

typedef struct {
    radius_attr_type_t type;
    uint8_t            len_min;
    uint8_t            len_max;
} radius_attr_desc_t;

// Packet Types
// https://www.rfc-editor.org/rfc/rfc2865#section-4
#define RADIUS_CODE_ACCESS_REQUEST      1
#define RADIUS_CODE_ACCESS_ACCEPT       2
#define RADIUS_CODE_ACCESS_REJECT       3

// Attributes
// https://www.rfc-editor.org/rfc/rfc2865#section-5
#define RADIUS_ATTR_USER_NAME           1
#define RADIUS_ATTR_USER_PASSWORD       2
#define RADIUS_ATTR_SERVICE_TYPE        6
#define RADIUS_ATTR_NAS_IDENTIFIER      32

#define RADIUS_AUTHENTICATE_ONLY        8

#define RADIUS_ATTR_DESC_ITEM(t, lmin, lmax) \
    .type = t,                               \
    .len_min = lmin,                         \
    .len_max = lmax

static radius_attr_desc_t attrs_desc[] = {
    [RADIUS_ATTR_USER_NAME] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_string, 1, 63)
    },
    [RADIUS_ATTR_USER_PASSWORD] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_string, 16, 128)
    },
    [RADIUS_ATTR_SERVICE_TYPE] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_integer,
                              sizeof(uint32_t), sizeof(uint32_t))
    },
    [RADIUS_ATTR_NAS_IDENTIFIER] {
        RADIUS_ATTR_DESC_ITEM(radius_attr_type_string, 3, 64)
    },
};

static void
init_radius_pkg(radius_pkg_builder_t *b, void *buf, int len);

static void
gen_authenticator(radius_auth_t *auth);

static radius_error_t
check_attr_len_needed(radius_pkg_builder_t *b,
                      uint16_t len);

static radius_error_t
check_string_attr_len_range(radius_pkg_builder_t *b,
                            int radius_attr_id,
                            uint16_t len);

static radius_error_t
make_access_request_pkg(radius_pkg_builder_t *b,
                        uint8_t req_id,
                        const ngx_str_t *secret,
                        const ngx_str_t *user,
                        const ngx_str_t *passwd,
                        const ngx_str_t *nas_id);

static radius_error_t
update_pkg_len(radius_pkg_builder_t *b);

size_t
create_radius_pkg(void *buf, size_t len,
                  uint8_t req_id,
                  const ngx_str_t *user,
                  const ngx_str_t *passwd,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id,
                  uint8_t /*out*/ *req_auth)
{
    radius_pkg_builder_t b;

    init_radius_pkg(&b, buf, len);
    gen_authenticator(&b.pkg->hdr.auth);
    if (req_auth) {
        ngx_memcpy(req_auth, &b.pkg->hdr.auth, sizeof(b.pkg->hdr.auth));
    }
    make_access_request_pkg(&b, req_id, secret, user, passwd, nas_id);

    update_pkg_len(&b);

    return b.pos - (uint8_t *)b.pkg;
}

int
parse_radius_pkg(const void *buf, size_t len,
                 uint8_t req_id,
                 const uint8_t *req_auth,
                 const ngx_str_t *secret)
{
    radius_pkg_t *pkg = (radius_pkg_t *) buf;
    uint16_t pkg_len = ntohs(pkg->hdr.len);
    if (len != pkg_len) {
        return -1;
    }

    // Check correlation id matches
    if (req_id != pkg->hdr.id) {
        return -2;
    }

    // Save actual response authenticator
    uint8_t act_auth[sizeof(pkg->hdr.auth)];
    ngx_memcpy(act_auth, &pkg->hdr.auth, sizeof(act_auth));

    // Calculate expected authenticator
    ngx_memcpy(&pkg->hdr.auth, req_auth, sizeof(pkg->hdr.auth));

    ngx_md5_t ctx;
    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, pkg, len);
    ngx_md5_update(&ctx, secret->data, secret->len);

    uint8_t exp_auth[sizeof(pkg->hdr.auth)];
    ngx_md5_final(exp_auth, &ctx);

    // Check actual and expected authenticators match
    if (ngx_memcmp(act_auth, exp_auth, sizeof(act_auth)) != 0) {
        return -3;
    }

    if (pkg->hdr.code == RADIUS_CODE_ACCESS_ACCEPT) {
        return RADIUS_AUTH_ACCEPTED;
    } else {
        return RADIUS_AUTH_REJECTED;
    }
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
check_attr_len_needed(radius_pkg_builder_t *b,
                      uint16_t len)
{
    size_t remain = sizeof(b->pkg->attrs) - (b->pos - b->pkg->attrs);
    size_t attr_len_need = sizeof(radius_attr_hdr_t) + len;
    if (attr_len_need > remain) {
        return radius_err_mem;
    }

    return radius_err_ok;
}

static radius_error_t
check_string_attr_len_range(radius_pkg_builder_t *b,
                            int radius_attr_id,
                            uint16_t len)
{
    if (len < attrs_desc[radius_attr_id].len_min ||
        len > attrs_desc[radius_attr_id].len_max) {
        return radius_err_range;
    }

    return check_attr_len_needed(b, len);
}

static radius_error_t
put_passwd_crypt(radius_pkg_builder_t *b,
                 const ngx_str_t *secret,
                 const ngx_str_t *passwd)
{
    uint8_t pwd_padded_len = 16 * (1 + passwd->len / 16);
    radius_error_t rc = check_string_attr_len_range(b,
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
    while (pwd_padded_remain) {
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
put_string_attr(radius_pkg_builder_t *b,
                int radius_attr_id,
                const ngx_str_t *str)
{
    radius_error_t rc = check_string_attr_len_range(b,
                                                    radius_attr_id,
                                                    str->len);
    if (rc != radius_err_ok) {
        return rc;
    }

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *) b->pos;
    ah->type = radius_attr_id;
    ah->len = sizeof(radius_attr_hdr_t) + str->len;
    b->pos += sizeof(radius_attr_hdr_t);
    ngx_memcpy(b->pos, str->data, str->len);
    b->pos += str->len;

    return radius_err_ok;
}

static radius_error_t
put_integer_attr(radius_pkg_builder_t* b,
                 int radius_attr_id,
                 uint32_t value)
{
    radius_error_t rc = check_attr_len_needed(b, sizeof(value));
    if (rc != radius_err_ok) {
        return rc;
    }

    radius_attr_hdr_t *ah = (radius_attr_hdr_t *) b->pos;
    ah->type = radius_attr_id;
    ah->len = sizeof(radius_attr_hdr_t) + sizeof(value);
    b->pos += sizeof(radius_attr_hdr_t);
    uint32_t *v = (uint32_t *)b->pos;
    *v = htobe32(value);
    b->pos += sizeof(value);

    return radius_err_ok;
}

static radius_error_t
make_access_request_pkg(radius_pkg_builder_t *b,
                        uint8_t req_id,
                        const ngx_str_t *secret,
                        const ngx_str_t *user,
                        const ngx_str_t *passwd,
                        const ngx_str_t *nas_id)
{
    assert(b && user && passwd);
    b->pkg->hdr.code = RADIUS_CODE_ACCESS_REQUEST;
    b->pkg->hdr.id = req_id;

    radius_error_t rc;
    // User-Name
    // https://www.rfc-editor.org/rfc/rfc2865#section-5.1
    rc = put_string_attr(b, RADIUS_ATTR_USER_NAME, user);
    if (rc != radius_err_ok) {
        return rc;
    }

    // User-Password
    // https://www.rfc-editor.org/rfc/rfc2865#section-5.2
    rc = put_passwd_crypt(b, secret, passwd);
    if (rc != radius_err_ok) {
        return rc;
    }

    // Service-Type
    // https://www.rfc-editor.org/rfc/rfc2865#section-5.6
    rc = put_integer_attr(b, RADIUS_ATTR_SERVICE_TYPE,
                          RADIUS_AUTHENTICATE_ONLY);
    if (rc != radius_err_ok) {
        return rc;
    }

    // NAS-Identifier
    // https://www.rfc-editor.org/rfc/rfc2865#section-5.32
    if (nas_id->len >= 3) {
        rc = put_string_attr(b, RADIUS_ATTR_NAS_IDENTIFIER, nas_id);
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
    b->pkg->hdr.len = htobe16(len);
    return radius_err_ok;
}
