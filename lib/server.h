#ifndef NAIVE_HTTPSERVER_H
#define NAIVE_HTTPSERVER_H

#include <stddef.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <resolv.h>

/**
 * Exported Types
 **/

typedef struct {
    char const *value;
    size_t len;
} nh_string_t;

typedef struct {
    char *buf;
    uint32_t capacity;
    uint32_t length;
    uint32_t index;
} nh_stream_t;

typedef struct nh_header_s {
    char const *key;
    char const *value;
    struct nh_header_s *next;
} nh_header_t;

typedef struct nh_context_s nh_context_t;
struct nh_context_s;

typedef struct nh_server_s nh_server_t;
struct nh_server_s;

/**
 * Exported Functions
**/

/** MAIN ENTRY **/
nh_server_t *httpserver_init(void (*handler)(nh_context_t *));

int httpserver_listen(nh_server_t *server, int port);

int httpserver_listen_ip(nh_server_t *server, char const *ip, int port);

/** REQUEST UTILS **/
nh_string_t get_request_header(nh_context_t *ctx, const char *key);

nh_string_t get_request_path(nh_context_t *ctx);

nh_string_t get_request_method(nh_context_t *ctx);

nh_string_t get_request_body(nh_context_t *ctx);

/** RESPONSE UTILS **/
// status
void set_response_status(nh_context_t *ctx, uint16_t status);

// - headers
void set_response_header(nh_context_t *ctx, const char *key, const char *value);

// - body
void set_response_body(nh_context_t *ctx, const char *body);

void set_response_body_string(nh_context_t *ctx, nh_string_t body);

/** COMMON UTILS **/
char *string_to_chars(nh_string_t string);

int string_cmp_chars(nh_string_t string, char const *chars);

#endif //NAIVE_HTTPSERVER_H