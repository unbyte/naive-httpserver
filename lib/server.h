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
} http_string_t;

typedef struct http_context_s http_context_t;
struct http_context_s;

typedef struct httpserver_s httpserver_t;
struct httpserver_s;

/**
 * Exported Functions
**/

/** MAIN ENTRY **/
httpserver_t *httpserver_init(void (*handler)(http_context_t *));

int httpserver_listen(httpserver_t *server, int port);

int httpserver_listen_ip(httpserver_t *server, char const *ip, int port);

/** REQUEST UTILS **/
http_string_t get_request_header(http_context_t *ctx, const char *key);

http_string_t get_request_path(http_context_t *ctx);

http_string_t get_request_method(http_context_t *ctx);

http_string_t get_request_body(http_context_t *ctx);

/** RESPONSE UTILS **/
// status
void set_response_status(http_context_t *ctx, uint16_t status);

// - headers
void set_response_header(http_context_t *ctx, const char *key, const char *value);

// - body
void set_response_body(http_context_t *ctx, const char *body);

void set_response_body_string(http_context_t *ctx, http_string_t body);

/** COMMON UTILS **/
char *string_to_chars(http_string_t string);

int string_cmp_chars(http_string_t string, char const *chars);

#endif //NAIVE_HTTPSERVER_H