
#define RADIUS_DEFAULT_PORT             1812

typedef struct radius_str_t {
    uint16_t len;
    unsigned char* s;
} radius_str_t;

typedef struct radius_req_queue_node_t {
    uint8_t                             ident;
    u_char                              auth[16];
    uint8_t                             active:1;
    uint8_t                             accepted:1;
    void                               *data;
    struct radius_req_queue_node_t     *next;
} radius_req_queue_node_t;

typedef struct {
    uint32_t                    magic;
    uint8_t                     id;
    struct  sockaddr           *sockaddr;
    socklen_t                   socklen;
    int                         sockfd;
    radius_str_t                secret;
    radius_str_t                nas_id;

    radius_req_queue_node_t     req_queue[UCHAR_MAX + 1];
    radius_req_queue_node_t    *req_free_list;
    radius_req_queue_node_t    *req_last_list;
    u_char                      process_buf[4096];
    void                       *data;
} radius_server_t;

radius_req_queue_node_t *
radius_send_request(ngx_array_t *servers,
                    radius_req_queue_node_t *prev_req,
                    radius_str_t *user,
                    radius_str_t *passwd,
                    ngx_log_t *log);

radius_server_t *
get_server_by_req(radius_req_queue_node_t *rqn, ngx_log_t *log);

radius_server_t *
radius_add_server(radius_server_t *rs,
                  int rs_id,
                  struct sockaddr *sockaddr,
                  socklen_t socklen,
                  radius_str_t *secret,
                  radius_str_t *nas_id);

ngx_int_t
radius_init_servers(ngx_array_t *servers, ngx_log_t *log);

void
radius_destroy_servers(ngx_array_t *servers, ngx_log_t *log);

radius_req_queue_node_t *
radius_recv_request(radius_server_t *rs, ngx_log_t *log);

uint16_t
create_radius_req(void *buf, size_t len,
                  uint8_t ident,
                  radius_str_t *user,
                  radius_str_t *passwd,
                  radius_str_t *secret,
                  radius_str_t *nas_id,
                  unsigned char *auth);

void
release_req_queue_node(radius_req_queue_node_t *rqn, ngx_log_t *log);
