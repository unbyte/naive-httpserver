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

typedef struct httpserver_option_s {
    void (*handler)(http_context_t *);

    uint16_t timeout;
    uint16_t keep_alive_timeout;

    char *ip_addr;
    int port;
} httpserver_option_t;

/**
 * Exported Functions
**/

/** MAIN ENTRY **/
int httpserver_listen(httpserver_option_t server);

/** REQUEST UTILS **/
http_string_t get_request_header(http_context_t *ctx, char const key[static 1]);

http_string_t get_request_path(http_context_t *ctx);

http_string_t get_request_method(http_context_t *ctx);

http_string_t get_request_body(http_context_t *ctx);

/** RESPONSE UTILS **/
// status
void set_response_status(http_context_t *ctx, uint16_t status);

// - headers
void set_response_header(http_context_t *ctx, char const key[static 1], char const value[static 1]);

// - body
void set_response_body(http_context_t *ctx, char const body[static 1]);

void set_response_body_string(http_context_t *ctx, http_string_t body);

/** COMMON UTILS **/
char *string_to_chars(http_string_t string);

int string_cmp_chars(http_string_t string, char const chars[static 1]);

int string_cmp_chars_case_insensitive(http_string_t string, char const chars[static 1]);

// auto free memory after responding
void* malloc_on_context(http_context_t *ctx, size_t size);

/** EXTERNAL - WEBSOCKET UTILS **/
#ifndef DISABLE_WEBSOCKET
typedef struct ws_context_s ws_context_t;
struct ws_context_s;

ws_context_t *serve_websocket(http_context_t *context, void (*receiver)(ws_context_t *));

#endif

#endif //NAIVE_HTTPSERVER_H