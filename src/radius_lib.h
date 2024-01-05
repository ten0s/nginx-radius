#ifndef __RADIUS_LIB_H__
#define __RADIUS_LIB_H__

// https://www.rfc-editor.org/rfc/rfc2865#section-3
// The minimum length is 20 and maximum length is 4096.
#define RADIUS_PKG_MAX 4096

#define AUTH_BUF_SIZE 16 // MD5_DIGEST_LENGTH

size_t
create_radius_pkg(void *buf, size_t len,
                  uint8_t req_id,
                  const ngx_str_t *user,
                  const ngx_str_t *passwd,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id,
                  uint8_t /*out*/ *req_auth);

#define RADIUS_AUTH_ACCEPTED 0
#define RADIUS_AUTH_REJECTED 1

int
parse_radius_pkg(const void *buf, size_t len,
                 uint8_t req_id,
                 const uint8_t *req_auth,
                 const ngx_str_t *secret);

#endif // __RADIUS_LIB_H__
