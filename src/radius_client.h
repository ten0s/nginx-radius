
size_t
create_radius_pkg(void *buf, size_t len,
                  uint8_t ident,
                  const ngx_str_t *user,
                  const ngx_str_t *passwd,
                  const ngx_str_t *secret,
                  const ngx_str_t *nas_id,
                  uint8_t *auth);
