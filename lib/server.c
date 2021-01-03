#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include "server.h"

#define NIL ((void*)0)

#define LOWER_CHAR(c) (c >= 'A' && c <= 'Z' ? c + 32 : c)

#define SESSION_TIMEOUT 10
#define SESSION_KEEP_ALIVE_TIMEOUT 30
#define SESSION_KEEP_ALIVE_TIMEOUT_RESPONSE "timeout=30, max=1000"

#define REQUEST_BUFFER_SIZE (1<<10)
#define MAX_REQUEST_BUFFER_SIZE (1<<23)

#define REQUEST_HEADER_INIT_SIZE (1<<3)


#define SESSION_FLAG_KEEP_ALIVE (1<<1)

#define FLAG_SET(v, flag) v |= flag
#define FLAG_CLEAR(v, flag) v &= ~flag
#define FLAG_CHECK(v, flag) (v & flag)

char const *const nh_http_status[600] = {
    [0 ... 599] = "",
    [100] = "Continue",
    [101] = "Switching Protocols",
    [102] = "Processing",

    [200] = "OK",
    [201] = "Created",
    [202] = "Accepted",
    [203] = "Non-Authoritative Information",
    [204] = "No Content",
    [205] = "Reset Content",
    [206] = "Partial Content",
    [207] = "Multi-Status",

    [300] = "Multiple Choices",
    [301] = "Moved Permanently",
    [302] = "Move temporarily",
    [303] = "See Other",
    [304] = "Not Modified",
    [305] = "Use Proxy",
    [306] = "Switch Proxy",
    [307] = "Temporary Redirect",

    [400] = "Bad Request",
    [401] = "Unauthorized",
    [402] = "Payment Required",
    [403] = "Forbidden",
    [404] = "Not Found",
    [405] = "Method Not Allowed",
    [406] = "Not Acceptable",
    [407] = "Proxy Authentication Required",
    [408] = "Request Timeout",
    [409] = "Conflict",
    [410] = "Gone",
    [411] = "Length Required",
    [412] = "Precondition Failed",
    [413] = "Request Entity Too Large",
    [414] = "Request - URI Too Long",
    [415] = "Unsupported Media Type",
    [416] = "Requested Range Not Satisfiable",
    [417] = "Expectation Failed",
    [421] = "Misdirected Request",
    [422] = "Unprocessable Entity",
    [423] = "Locked",
    [424] = "Failed Dependency",
    [425] = "Unordered Collection",
    [426] = "Upgrade Required",
    [449] = "Retry With",

    [500] = "Internal Server Error",
    [501] = "Not Implemented",
    [502] = "Bad Gateway",
    [503] = "Service Unavailable",
    [504] = "Gateway Timeout",
    [505] = "HTTP Version Not Supported",
    [506] = "Variant Also Negotiates",
    [507] = "Insufficient Storage",
    [509] = "Bandwidth Limit Exceeded",
    [510] = "Not Extended",
};

/**
 * Internal Types
**/

typedef void (*ev_handler_t)(struct epoll_event *);

typedef struct {
    ev_handler_t handler;
} ev_cb_t;

typedef enum {
    SESSION_READ,
    SESSION_WRITE,
    SESSION_END
} nh_session_state_t;

typedef struct {
    uint16_t status;
    nh_header_t *header;
    nh_string_t body;
    nh_stream_t raw;
} nh_response_t;

typedef struct {
    uint32_t index;
    uint32_t len;
} nh_anchor_t;

typedef struct {
    nh_anchor_t key;
    nh_anchor_t value;
} nh_kv_anchor_t;

struct nh_context_s {
    nh_anchor_t method;
    nh_anchor_t path;
    nh_anchor_t body;
    nh_kv_anchor_t *header;
    uint32_t header_len;
    uint32_t header_capacity;
    nh_stream_t raw;
    nh_response_t response;
};

typedef struct {
    // for processing sessions
    ev_handler_t handler;
    ev_handler_t timer_handler;
    int socket;
    int timer_fd;
    nh_session_state_t state;
    nh_context_t context;
    uint8_t flags;
    uint8_t timeout;

    nh_server_t *server;
} nh_session_t;

struct nh_server_s {
    // for accepting and handling sessions
    ev_handler_t handler;
    int socket;
    int loop;

    void (*request_handler)(nh_context_t *);

    struct sockaddr_in addr;
    socklen_t addr_len;
};

/**
 * Internal Utils
**/

int nh_string_cmp_case_insensitive(char const a[static 1], char const b[static 1], int len) {
    for (int i = 0; i < len; i++) {
        if (LOWER_CHAR(a[i]) != LOWER_CHAR(b[i])) return 0;
    }
    return 1;
}

int nh_string_cmp(char const a[static 1], char const b[static 1], int len) {
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

void nh_stream_free(nh_stream_t *stream) {
    if (stream->buf != NIL) {
        free(stream->buf);
        stream->buf = NIL;
    }
}

void nh_stream_init(nh_stream_t *stream) {
    if (stream->buf == NIL) {
        stream->buf = (char *) calloc(1, REQUEST_BUFFER_SIZE);
        assert(stream->buf != NIL);
        stream->capacity = REQUEST_BUFFER_SIZE;
    }
}

void nh_string_free(nh_string_t *string) {
    if (string->value != NIL) {
        free((void *) string->value);
        string->value = NIL;
    }
}

void nh_context_free(nh_context_t *ctx) {
    if (ctx->header != NIL) {
        free(ctx->header);
        ctx->header = NIL;
    }
    nh_header_t *header = ctx->response.header;
    nh_header_t *tmp;
    while (header != NIL) {
        tmp = header;
        header = tmp->next;
        free(tmp);
    }
    nh_stream_free(&ctx->response.raw);
    nh_stream_free(&ctx->raw);
}

// returns 0 means no new bytes
int nh_read_socket(nh_stream_t *buf, int socket) {
    nh_stream_init(buf);
    // still remain some buffer
    if (buf->index < buf->length) return 1;
    int bytes;
    while (buf->capacity < MAX_REQUEST_BUFFER_SIZE
           && (bytes = read(socket, buf->buf + buf->length, buf->capacity - buf->length)) > 0) {
        if (bytes > 0) buf->length += bytes;
        if (buf->length == buf->capacity && buf->capacity != MAX_REQUEST_BUFFER_SIZE) {
            buf->capacity = buf->capacity * 2 > MAX_REQUEST_BUFFER_SIZE
                            ? MAX_REQUEST_BUFFER_SIZE
                            : buf->capacity * 2;
            buf->buf = (char *) realloc(buf->buf, buf->capacity);
            assert(buf->buf != NIL);
        }
    }
    return bytes == 0 ? 0 : 1;
}

int nh_write_socket(nh_stream_t *buf, int socket) {
    int bytes = write(
        socket,
        buf->buf + buf->index,
        buf->length - buf->index
    );
    if (bytes > 0) buf->index += bytes;
    return errno == EPIPE ? 0 : 1;
}

// help find next char's position in http request, -1 means not found after max chars
int nh_stream_find_next(nh_stream_t *stream, char next, uint32_t max) {
    for (uint32_t i = 0; i < max; ++i) {
        if (stream->buf[stream->index + i] == next) {
            return i;
        }
    }
    return -1;
}

// help find next char tuple's position in http request, -1 means not found after max chars
int nh_stream_find_next_char_tuple(nh_stream_t *stream, char const next[2], uint32_t max) {
    for (uint32_t i = 0; i < max; ++i) {
        if (stream->buf[stream->index + i] == next[0]) {
            if (stream->buf[stream->index + i + 1] == next[1])
                return i;
        }
    }
    return -1;
}

void nh_stream_write(nh_stream_t *stream, char const *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    int bytes = vsnprintf(stream->buf + stream->length, stream->capacity - stream->length, fmt, args);
    if (bytes + stream->length > stream->capacity) {
        while (bytes + stream->length > stream->capacity) stream->capacity *= 2;
        stream->buf = (char *) realloc(stream->buf, stream->capacity);
        assert(stream->buf != NIL);
        bytes += vsnprintf(stream->buf + stream->length, stream->capacity - stream->length, fmt, args);
    }
    stream->length += bytes;

    va_end(args);
}

void nh_stream_copy(nh_stream_t *stream, char const src[static 1], uint32_t size) {
    if (stream->length + size > stream->capacity) {
        stream->capacity = stream->length + size;
        stream->buf = (char *) realloc(stream->buf, stream->capacity);
        assert(stream->buf != NIL);
    }
    memcpy(stream->buf + stream->length, src, size);
    stream->length += size;
}

/**
 * Utils Implement
**/

nh_string_t get_request_header(nh_context_t *ctx, const char *key) {
    size_t len = strlen(key);
    nh_kv_anchor_t cur;
    for (uint32_t i = 0; i < ctx->header_len; ++i) {
        cur = ctx->header[i];
        if (cur.key.len == len && nh_string_cmp_case_insensitive(key, &ctx->raw.buf[cur.key.index], len)) {
            return (nh_string_t) {
                .value = &ctx->raw.buf[cur.value.index],
                .len = cur.value.len,
            };
        }
    }
    return (nh_string_t) {};
}

nh_string_t get_request_path(nh_context_t *ctx) {
    return (nh_string_t) {
        .value = &ctx->raw.buf[ctx->path.index],
        .len = ctx->path.len
    };
}

nh_string_t get_request_method(nh_context_t *ctx) {
    return (nh_string_t) {
        .value = &ctx->raw.buf[ctx->method.index],
        .len = ctx->method.len
    };
}

nh_string_t get_request_body(nh_context_t *ctx) {
    return (nh_string_t) {
        .value = &ctx->raw.buf[ctx->body.index],
        .len = ctx->body.len
    };
}

void set_response_status(nh_context_t *ctx, uint16_t status) {
    ctx->response.status = status > 599 || status < 100 ? 500 : status;
}

void set_response_header(nh_context_t *ctx, const char *key, const char *value) {
    nh_header_t *h = (nh_header_t *) malloc(sizeof(nh_header_t));
    assert(h != NIL);
    h->key = key;
    h->value = value;
    h->next = ctx->response.header;
    ctx->response.header = h;
}

void set_response_body(nh_context_t *ctx, char const *body) {
    ctx->response.body = (nh_string_t) {
        .value = body,
        .len = strlen(body)
    };
}

void set_response_body_string(nh_context_t *ctx, nh_string_t body) {
    ctx->response.body = body;
}

char *string_to_chars(nh_string_t string) {
    char *result = malloc(sizeof(char) * (string.len + 1));
    assert(result != NIL);
    strcpy(result, string.value);
    result[string.len] = '\0';
    return result;
}

int string_cmp_chars(nh_string_t string, char const *chars) {
    return strlen(chars) == string.len && nh_string_cmp(string.value, chars, string.len);
}

/**
 * Server Internal Function
**/

// help parse header in http request, return 0 means error
int nh_http_parse_consume_header(nh_context_t *ctx);

// parse http request
int nh_http_parse(nh_context_t *ctx);

// generate http response
void nh_generate_http_response(nh_context_t *ctx);

// init session and read and parse raw to request
void nh_session_read(nh_session_t *session);

// write response for session
void nh_session_write(nh_session_t *session);

// end a session and clear resources
void nh_session_clear(nh_session_t *session);

// handler before user's
void nh_session_pre_handler(nh_session_t *session);

// process session according to session state
void nh_session_handler(nh_session_t *session);

// epoll event callback for session
void nh_session_event_cb(struct epoll_event *ev);

// epoll event callback for session timer
void nh_session_event_timer_cb(struct epoll_event *ev);

// add session events on epoll (socket and timer)
void nh_session_register_events(nh_session_t *session);

// epoll event callback for server
void nh_server_events_cb(struct epoll_event *ev);

// bind socket with ip&port and save ip&port into *server as addr
void nh_server_bind(int socket, struct sockaddr_in *addr, const char *ip, int port);

// add server events on epoll (accept)
void nh_server_listen(nh_server_t *server, char const *ip, int port);

/**
 * Server Internal Function Implements
**/

int nh_http_parse_consume_header(nh_context_t *ctx) {
    if (ctx->header == NIL) {
        ctx->header = (nh_kv_anchor_t *) malloc(sizeof(nh_kv_anchor_t) * REQUEST_HEADER_INIT_SIZE);
        ctx->header_capacity = REQUEST_HEADER_INIT_SIZE;
        ctx->header_len = 0;
    }

    nh_stream_t *stream = &ctx->raw;
    uint32_t key_index = stream->index;
    int key_offset;
    if ((key_offset = nh_stream_find_next_char_tuple(stream, ": ", 128)) < 0) return 0;

    stream->index += key_offset + 2;
    uint32_t value_index = stream->index;

    int value_offset;
    if ((value_offset = nh_stream_find_next(stream, '\r', 1024)) <= 0) return 0;

    stream->index += value_offset;

    if (ctx->header_len == ctx->header_capacity) {
        ctx->header_capacity *= 2;
        ctx->header = (nh_kv_anchor_t *) realloc(ctx->header, ctx->header_capacity * sizeof(nh_kv_anchor_t));
        assert(ctx->header != NIL);
    }

    ctx->header[ctx->header_len] = (nh_kv_anchor_t) {
        .key = {.index = key_index, .len = key_offset},
        .value = {.index = value_index, .len = value_offset}
    };
    ctx->header_len++;
    return 1;
}

typedef enum {
    PARSE_LINE_END,
    PARSE_METHOD, PARSE_PATH, PARSE_VERSION,
    PARSE_HEADER,
    PARSE_BODY
} nh_http_parse_state_t;

// 0 means error
int nh_http_parse(nh_context_t *ctx) {
    //         Request       = Request-Line
    //                        *(( general-header
    //                         | request-header
    //                         | entity-header ) CRLF)
    //                        CRLF
    //                        [ message-body ]
    //
    // Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
    nh_stream_t *stream = &ctx->raw;
    stream->index = 0;
    nh_http_parse_state_t state = PARSE_METHOD;
    int offset;
    while (stream->index < stream->length) {
        switch (state) {
            case PARSE_METHOD:
                if ((offset = nh_stream_find_next(stream, ' ', 16)) <= 0) return 0;
                ctx->method = (nh_anchor_t) {.index = stream->index, .len = offset};
                state = PARSE_PATH;
                stream->index += offset + 1;
                break;
            case PARSE_PATH:
                if ((offset = nh_stream_find_next(stream, ' ', 2048)) <= 0) return 0;
                ctx->path = (nh_anchor_t) {.index = stream->index, .len = offset};
                state = PARSE_VERSION;
                stream->index += offset + 1;
                break;
            case PARSE_VERSION:
                if (!nh_string_cmp("HTTP/1.", &stream->buf[stream->index], 7)) return 0;
                stream->index += 7;
                if (stream->buf[stream->index] != '0' && stream->buf[stream->index] != '1') return 0;
                state = PARSE_LINE_END;
                stream->index += 1;
                break;
            case PARSE_LINE_END:
                if (!nh_string_cmp("\r\n", &stream->buf[stream->index], 2)) return 0;
                stream->index += 2;
                if (nh_string_cmp("\r\n", &stream->buf[stream->index], 2)) {
                    // no head, parse body directly
                    stream->index += 2;
                    state = PARSE_BODY;
                } else {
                    state = PARSE_HEADER;
                }
                break;
            case PARSE_HEADER:
                if (!nh_http_parse_consume_header(ctx)) return 0;
                state = PARSE_LINE_END;
                break;
            case PARSE_BODY:
                ctx->body = (nh_anchor_t) {.index = stream->index, .len = stream->length - stream->index};
                stream->index = stream->length;
                break;
            default:
                break;
        }
    }
    return 1;
}

void nh_generate_http_response(nh_context_t *ctx) {
    nh_stream_t *stream = &ctx->response.raw;
    nh_response_t *response = &ctx->response;

    // meta line
    nh_stream_write(stream, "HTTP/1.1 %u %s\r\n", response->status, nh_http_status[response->status]);

    // headers
    nh_header_t *header = response->header;
    while (header != NIL) {
        nh_stream_write(stream, "%s: %s\r\n", header->key, header->value);
        header = header->next;
    }
    // content-length
    if (response->body.len) {
        nh_stream_write(stream, "Content-Length: %zu\r\n", response->body.len);
    }
    nh_stream_write(stream, "\r\n");

    // body
    if (response->body.len) {
        nh_stream_copy(stream, response->body.value, response->body.len);
    }
}

void nh_session_pre_handler(nh_session_t *session) {
    // just for keep alive now
    // TODO add more feature
    nh_stream_t *stream = &session->context.raw;
    nh_kv_anchor_t *h;
    for (uint32_t i = 0; i < session->context.header_len; ++i) {
        h = &session->context.header[i];
        if (h->key.len == 10
            && nh_string_cmp_case_insensitive("Connection", &stream->buf[h->key.index], 10)
            && h->value.len == 10
            && nh_string_cmp_case_insensitive("keep-alive", &stream->buf[h->value.index], 10)) {
            // is KeepAlive
            FLAG_SET(session->flags, SESSION_FLAG_KEEP_ALIVE);
            // add header
            set_response_header(&session->context, "Connection", "Keep-Alive");
            set_response_header(&session->context, "Keep-Alive", SESSION_KEEP_ALIVE_TIMEOUT_RESPONSE);
            return;
        }
    }
    FLAG_CLEAR(session->flags, SESSION_FLAG_KEEP_ALIVE);
    set_response_header(&session->context, "Connection", "Close");
}

void nh_session_read(nh_session_t *session) {
    session->state = SESSION_READ;
    session->timeout = SESSION_TIMEOUT;
    nh_context_free(&session->context);
    session->context = (nh_context_t) {0};

    if (nh_read_socket(&session->context.raw, session->socket) == 0) {
        session->state = SESSION_END;
        return;
    }

    // init response
    session->context.response = (nh_response_t) {};

    // parse http
    if (nh_http_parse(&session->context)) {
        // success, process
        nh_session_pre_handler(session);
        session->server->request_handler(&session->context);
    } else {
        // fail, report error
        set_response_status(&session->context, 400);
        set_response_body(&session->context, "Bad Request");
    }
    nh_session_write(session);
}

void nh_session_write(nh_session_t *session) {
    session->state = SESSION_WRITE;
    nh_stream_t *stream = &session->context.response.raw;
    if (stream->buf == NIL) {
        nh_stream_init(stream);
        nh_generate_http_response(&session->context);
    }

    if (!nh_write_socket(stream, session->socket)) {
        // pipe error
        session->state = SESSION_END;
        return;
    }

    if (stream->index != stream->length) {
        // need wait writable
        struct epoll_event ev;
        ev.events = EPOLLOUT | EPOLLET;
        ev.data.ptr = session;
        epoll_ctl(session->server->loop, EPOLL_CTL_MOD, session->socket, &ev);
        return;
    }

    if (FLAG_CHECK(session->flags, SESSION_FLAG_KEEP_ALIVE)) {
        session->state = SESSION_READ;
        session->timeout = SESSION_KEEP_ALIVE_TIMEOUT;
    } else {
        session->state = SESSION_END;
    }
}

void nh_session_clear(nh_session_t *session) {
    // clear events
    epoll_ctl(session->server->loop, EPOLL_CTL_DEL, session->socket, NIL);
    epoll_ctl(session->server->loop, EPOLL_CTL_DEL, session->timer_fd, NIL);
    // close fd
    close(session->timer_fd);
    close(session->socket);
    // free memory
    nh_context_free(&session->context);
    free(session);
}

void nh_session_handler(nh_session_t *session) {
    switch (session->state) {
        case SESSION_READ:
            nh_session_read(session);
            break;
        case SESSION_WRITE:
            nh_session_write(session);
            break;
        case SESSION_END:
            break;
    }
    if (session->state == SESSION_END) nh_session_clear(session);
}

void nh_server_events_cb(struct epoll_event *ev) {
    nh_server_t *server = (nh_server_t *) ev->data.ptr;
    int socket;
    while ((socket = accept(server->socket, (struct sockaddr *) &server->addr, &server->addr_len)) > 0) {
        // init session
        nh_session_t *session = (nh_session_t *) calloc(1, sizeof(nh_session_t));
        assert(session != NIL);
        session->socket = socket;
        session->timeout = SESSION_TIMEOUT;
        session->handler = nh_session_event_cb;
        session->server = server;
        // add events on epoll
        nh_session_register_events(session);
        // start process
        session->state = SESSION_READ;
        nh_session_handler(session);
    }
}

void nh_session_event_cb(struct epoll_event *ev) {
    nh_session_handler((nh_session_t *) ev->data.ptr);
}

void nh_session_event_timer_cb(struct epoll_event *ev) {
    // data.ptr = &session->timer_handler
    // data.ptr - sizeof(ev_handler_t) = &session
    nh_session_t *session = (nh_session_t *) (ev->data.ptr - sizeof(ev_handler_t));
    uint64_t res;
    session->timeout -= 1;
    if (session->timeout == 0) nh_session_clear(session);
}

void nh_session_register_events(nh_session_t *session) {
    struct epoll_event ev;

    // add socket event on epoll
    int flags = fcntl(session->socket, F_GETFL, 0);
    fcntl(session->socket, F_SETFL, flags | O_NONBLOCK);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = session;
    epoll_ctl(session->server->loop, EPOLL_CTL_ADD, session->socket, &ev);

    // init timer
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec ts = {};
    ts.it_value.tv_sec = 1;
    ts.it_interval.tv_sec = 1;
    timerfd_settime(timer_fd, 0, &ts, NIL);

    session->timer_fd = timer_fd;
    session->timer_handler = nh_session_event_timer_cb;

    // add timer event on epoll
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = &session->timer_handler;
    epoll_ctl(session->server->loop, EPOLL_CTL_ADD, timer_fd, &ev);
}

void nh_server_bind(int socket, struct sockaddr_in *addr, const char *ip, int port) {
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip == NIL ? INADDR_ANY : inet_addr(ip);
    addr->sin_port = htons(port);
    if (bind(socket, (struct sockaddr *) addr, sizeof(struct sockaddr_in)) < 0) {
        exit(1);
    }
}

void nh_server_listen(nh_server_t *server, char const *ip, int port) {
    // socket init
    signal(SIGPIPE, SIG_IGN);
    server->socket = socket(AF_INET, SOCK_STREAM, 0);
    int flag = 1;
    setsockopt(server->socket, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag));
    // bind
    nh_server_bind(server->socket, &server->addr, ip, port);
    // listen
    server->addr_len = sizeof(server->addr);
    int flags = fcntl(server->socket, F_GETFL, 0);
    fcntl(server->socket, F_SETFL, flags | O_NONBLOCK);
    listen(server->socket, 128);
    // epoll event
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = server;
    epoll_ctl(server->loop, EPOLL_CTL_ADD, server->socket, &ev);
}

/**
 * Entry Implement
 **/

nh_server_t *httpserver_init(void (*handler)(nh_context_t *)) {
    nh_server_t *server = (nh_server_t *) malloc(sizeof(nh_server_t));
    assert(server != NIL);
    server->handler = nh_server_events_cb;
    server->request_handler = handler;
    server->loop = epoll_create1(0);
    return server;
}

int httpserver_listen(nh_server_t *server, int port) {
    return httpserver_listen_ip(server, NIL, port);
}

int httpserver_listen_ip(nh_server_t *server, const char *ip, int port) {
    nh_server_listen(server, ip, port);
    struct epoll_event ev_list[1];
    while (1) {
        int events = epoll_wait(server->loop, ev_list, 1, -1);
        for (int i = 0; i < events; i++) {
            ev_cb_t *ev_cb = (ev_cb_t *) ev_list[i].data.ptr;
            ev_cb->handler(&ev_list[i]);
        }
    }
    return 0;
}