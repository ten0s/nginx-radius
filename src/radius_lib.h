#ifndef __RADIUS_LIB_H__
#define __RADIUS_LIB_H__

#define RADIUS_PKG_MAX 1024

#define RADIUS_CODE_ACCESS_REQUEST      1
#define RADIUS_CODE_ACCESS_ACCEPT       2
#define RADIUS_CODE_ACCESS_REJECT       3
#define RADIUS_CODE_ACCESS_CHALLENGE    4

size_t
create_radius_pkg(void *buf, size_t len,
                  uint8_t ident,
                  const ngx_str_t *user,
                  const ngx_str_t *passwd,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id,
                  uint8_t *auth);

int
parse_radius_pkg(void *buf, size_t len,
                 uint8_t ident,
                 const ngx_str_t *secret,
                 const uint8_t *auth);

#endif // __RADIUS_LIB_H__
