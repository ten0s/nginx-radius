#ifndef __RADIUS_LIB_H__
#define __RADIUS_LIB_H__

#define RADIUS_PKG_MAX 256

size_t
create_radius_pkg(void *buf, size_t len,
                  uint8_t req_id,
                  const ngx_str_t *user,
                  const ngx_str_t *passwd,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id,
                  uint8_t /*out*/ *auth);

#define RADIUS_AUTH_ACCEPTED 0
#define RADIUS_AUTH_REJECTED 1

int
parse_radius_pkg(const void *buf, size_t len,
                 uint8_t req_id,
                 const ngx_str_t *secret,
                 const uint8_t *auth);

#endif // __RADIUS_LIB_H__
