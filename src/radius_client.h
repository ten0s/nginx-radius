
#define RADIUS_DEFAULT_PORT             1812

typedef struct {
    uint16_t len;
    u_char* s;
} radius_str_t;

struct radius_server_s;

typedef struct radius_req_s {
    // Should be big enough to address req_queue
    uint8_t ident;
    u_char auth[16];
    uint8_t active:1;
    uint8_t accepted:1;
    struct radius_server_s *rs;
    ngx_connection_t *conn;
    ngx_http_request_t *http_req;
    struct radius_req_s *next;
} radius_req_t;

typedef struct radius_server_s {
    uint32_t magic;
    uint8_t id;
    struct sockaddr *sockaddr;
    socklen_t socklen;
    radius_str_t secret;
    radius_str_t nas_id;

    // Effectively, the number of concurrent requests
    // TODO: get it from server config
    radius_req_t req_queue[10/*UCHAR_MAX + 1*/];
    radius_req_t *req_free_list;
    radius_req_t *req_last_list;
    void *data;
} radius_server_t;

size_t
create_radius_pkg(void *buf, size_t len,
                  uint8_t ident,
                  radius_str_t *user,
                  radius_str_t *passwd,
                  radius_str_t *secret,
                  radius_str_t *nas_id,
                  unsigned char *auth);
