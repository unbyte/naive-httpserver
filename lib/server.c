#include <string.h>
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

#define LOWER_CHAR(c) (c <= 'Z' && c >= 'A' ? c + 32 : c)

#define DEFAULT_TIMEOUT 10
#define WEBSOCKET_TIMEOUT 3600

#define REQUEST_BUFFER_SIZE (1<<10)
#define MAX_REQUEST_BUFFER_SIZE (1<<23)

#define REQUEST_HEADER_INIT_SIZE (1<<3)

#define SESSION_FLAG_KEEP_ALIVE (1<<1)
#define SESSION_FLAG_UPGRADED (1<<2)

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
    http_string_t body;
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

typedef struct nh_malloced_s {
    char *ptr;
    struct nh_malloced_s *next;
} nh_malloced_t;

typedef struct nh_session_s nh_session_t;
typedef struct nh_server_s nh_server_t;

typedef enum {
    HTTP_1_0,
    HTTP_1_1
} nh_http_version;

typedef enum {
    PARSE_METHOD, PARSE_PATH, PARSE_VERSION,
    PARSE_HEADER,
    PARSE_SECOND_LINE_END,
    PARSE_BODY,
    PARSE_LINE_END,
    PARSE_DONE,
} nh_http_parse_state;

struct http_context_s {
    nh_http_version version;
    nh_anchor_t method;
    nh_anchor_t path;
    nh_anchor_t body;
    nh_kv_anchor_t *header;

    uint32_t header_len;
    uint32_t header_capacity;

    uint32_t body_len;
    // raw stream
    nh_stream_t raw;
    // parse
    nh_http_parse_state parse_state;

    nh_response_t response;
    nh_session_t *session;

    // memory malloced on context
    nh_malloced_t *malloced;
};

struct nh_session_s {
    // for processing sessions
    ev_handler_t handler;
    ev_handler_t timer_handler;
    int socket;
    int timer_fd;
    nh_session_state_t state;
    http_context_t context;
    uint8_t flags;
    uint16_t timeout;

    nh_server_t *server;
};

struct nh_server_s {
    // for accepting and handling sessions
    ev_handler_t handler;
    int socket;
    int loop;

    void (*request_handler)(http_context_t *);

    struct sockaddr_in addr;
    socklen_t addr_len;

    uint16_t timeout;
    uint16_t keep_alive_timeout;
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
    if (stream->buf != NULL) {
        free(stream->buf);
        stream->buf = NULL;
        stream->length = 0;
        stream->index = 0;
    }
}

void nh_stream_init(nh_stream_t *stream) {
    if (stream->buf == NULL) {
        stream->buf = (char *) calloc(1, REQUEST_BUFFER_SIZE);
        assert(stream->buf != NULL);
        stream->capacity = REQUEST_BUFFER_SIZE;
    }
}

uint32_t nh_string_to_uint(http_string_t string) {
    if (string.value == NULL) {
        return 0;
    }
    uint32_t result = 0;
    uint32_t index = 0;
    while (index < string.len && string.value[index] >= '0' && string.value[index] <= '9') {
        result = result * 10 + string.value[index] - 48;
        ++index;
    }
    return result;
}

void nh_context_clear(http_context_t *ctx) {
    if (ctx->header != NULL) free(ctx->header);

    nh_header_t *header = ctx->response.header;
    nh_header_t *temp_h;
    while (header != NULL) {
        temp_h = header;
        header = temp_h->next;
        free(temp_h);
    }

    nh_malloced_t *malloced = ctx->malloced;
    nh_malloced_t *temp_m;
    while (malloced != NULL) {
        temp_m = malloced;
        malloced = temp_m->next;
        free(temp_m->ptr);
        free(temp_m);
    }

    nh_stream_free(&ctx->response.raw);
    nh_stream_free(&ctx->raw);

    *ctx = (http_context_t) {
        .session = ctx->session
    };
}

// returns 0 means no new bytes
int nh_read_socket(nh_stream_t *buf, int socket) {
    nh_stream_init(buf);
    // still remain some buffer
    if (buf->index < buf->length) return 1;
    int bytes;
    while (buf->capacity < MAX_REQUEST_BUFFER_SIZE
           && (bytes = read(socket, buf->buf + buf->length, buf->capacity - buf->length)) > 0) {
        buf->length += bytes;
        if (buf->length == buf->capacity && buf->capacity != MAX_REQUEST_BUFFER_SIZE) {
            buf->capacity = buf->capacity * 2 > MAX_REQUEST_BUFFER_SIZE
                            ? MAX_REQUEST_BUFFER_SIZE
                            : buf->capacity * 2;
            buf->buf = (char *) realloc(buf->buf, buf->capacity);
            assert(buf->buf != NULL);
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

void nh_stream_write(nh_stream_t *stream, char const fmt[static 1], ...) {
    va_list args;
    va_start(args, fmt);

    int bytes = vsnprintf(stream->buf + stream->length, stream->capacity - stream->length, fmt, args);
    if (bytes + stream->length > stream->capacity) {
        while (bytes + stream->length > stream->capacity) stream->capacity *= 2;
        stream->buf = (char *) realloc(stream->buf, stream->capacity);
        assert(stream->buf != NULL);
        bytes += vsnprintf(stream->buf + stream->length, stream->capacity - stream->length, fmt, args);
    }
    stream->length += bytes;

    va_end(args);
}

void nh_stream_copy(nh_stream_t *stream, char const src[static 1], uint32_t size) {
    if (stream->length + size > stream->capacity) {
        stream->capacity = stream->length + size;
        stream->buf = (char *) realloc(stream->buf, stream->capacity);
        assert(stream->buf != NULL);
    }
    memcpy(stream->buf + stream->length, src, size);
    stream->length += size;
}

/**
 * Utils Implement
**/

http_string_t get_request_header(http_context_t *ctx, char const key[static 1]) {
    size_t len = strlen(key);
    nh_kv_anchor_t cur;
    for (uint32_t i = 0; i < ctx->header_len; ++i) {
        cur = ctx->header[i];
        if (cur.key.len == len && nh_string_cmp_case_insensitive(key, &ctx->raw.buf[cur.key.index], len)) {
            return (http_string_t) {
                .value = &ctx->raw.buf[cur.value.index],
                .len = cur.value.len,
            };
        }
    }
    return (http_string_t) {};
}

http_string_t get_request_path(http_context_t *ctx) {
    return (http_string_t) {
        .value = &ctx->raw.buf[ctx->path.index],
        .len = ctx->path.len
    };
}

http_string_t get_request_method(http_context_t *ctx) {
    return (http_string_t) {
        .value = &ctx->raw.buf[ctx->method.index],
        .len = ctx->method.len
    };
}

http_string_t get_request_body(http_context_t *ctx) {
    return (http_string_t) {
        .value = &ctx->raw.buf[ctx->body.index],
        .len = ctx->body.len
    };
}

void set_response_status(http_context_t *ctx, uint16_t status) {
    ctx->response.status = status > 599 || status < 100 ? 500 : status;
}

void set_response_header(http_context_t *ctx, const char key[static 1], const char value[static 1]) {
    nh_header_t *h = (nh_header_t *) malloc(sizeof(nh_header_t));
    assert(h != NULL);
    h->key = key;
    h->value = value;
    h->next = ctx->response.header;
    ctx->response.header = h;
}

void set_response_body(http_context_t *ctx, char const body[static 1]) {
    ctx->response.body = (http_string_t) {
        .value = body,
        .len = strlen(body)
    };
}

void set_response_body_string(http_context_t *ctx, http_string_t body) {
    ctx->response.body = body;
}

char *string_to_chars(http_string_t string) {
    char *result = malloc(sizeof(char) * (string.len + 1));
    assert(result != NULL);
    strcpy(result, string.value);
    result[string.len] = '\0';
    return result;
}

int string_cmp_chars(http_string_t string, char const chars[static 1]) {
    return strlen(chars) == string.len && nh_string_cmp(string.value, chars, string.len);
}

int string_cmp_chars_case_insensitive(http_string_t string, char const chars[static 1]) {
    return strlen(chars) == string.len && nh_string_cmp_case_insensitive(string.value, chars, string.len);
}

void *malloc_on_context(http_context_t *ctx, size_t size) {
    nh_malloced_t *m = (nh_malloced_t *) malloc(sizeof(nh_malloced_t));
    assert(m != NULL);
    m->ptr = malloc(size);
    m->next = ctx->malloced;
    ctx->malloced = m;
    return m->ptr;
}

/**
 * Server Internal Function
**/

// help parse header in http request, return 0 means error
int nh_http_parse_consume_header(http_context_t *ctx);

// help parse body in http request, return 0 means not complete
int nh_http_parse_consume_body(http_context_t *ctx);

// help get content-length
void nh_http_parse_get_body_len(http_context_t *ctx);

// parse http request
int nh_http_parse(http_context_t *ctx);

// generate http response
void nh_generate_http_response(http_context_t *ctx);

// init session and read and parse raw to request
void nh_session_read(nh_session_t *session);

// write response for session
void nh_session_write(nh_session_t *session);

// end a session and clear resources
void nh_session_free(nh_session_t *session);

// handler before user's
void nh_keep_alive_handler(http_context_t *context);

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

int nh_http_parse_consume_header(http_context_t *ctx) {
    if (ctx->header == NULL) {
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
        assert(ctx->header != NULL);
    }

    ctx->header[ctx->header_len] = (nh_kv_anchor_t) {
        .key = {.index = key_index, .len = key_offset},
        .value = {.index = value_index, .len = value_offset}
    };
    ctx->header_len++;
    return 1;
}

void nh_http_parse_get_body_len(http_context_t *ctx) {
    http_string_t length_str = get_request_header(ctx, "Content-Length");
    if (length_str.len == 0) {
        ctx->body_len = 0;
    } else {
        uint32_t length = nh_string_to_uint(length_str);
        ctx->body_len = length > 0 ? length : 0;
    }
}

int nh_http_parse_consume_body(http_context_t *ctx) {
    uint32_t length = ctx->body_len;
    nh_stream_t *stream = &ctx->raw;
    if (ctx->body.index == 0) ctx->body.index = stream->index;
    if (stream->length - ctx->body.index > length) {
        ctx->body.len = length;
    } else if (ctx->body.len < length) {
        ctx->body.len = stream->length - ctx->body.index;
    }
    stream->index = ctx->body.index + ctx->body.len;
    return ctx->body.len == length;
}

// 0 means error, -1 means not complete, 1 means success and complete
int nh_http_parse(http_context_t *ctx) {
    //         Request       = Request-Line
    //                        *(( general-header
    //                         | request-header
    //                         | entity-header ) CRLF)
    //                        CRLF
    //                        [ message-body ]
    //
    // Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
    nh_stream_t *stream = &ctx->raw;
    int offset;
    while (stream->index < stream->length) {
        switch (ctx->parse_state) {
            case PARSE_METHOD:
                if ((offset = nh_stream_find_next(stream, ' ', 16)) <= 0) return 0;
                ctx->method = (nh_anchor_t) {.index = stream->index, .len = offset};
                ctx->parse_state = PARSE_PATH;
                stream->index += offset + 1;
                break;
            case PARSE_PATH:
                if ((offset = nh_stream_find_next(stream, ' ', 2048)) <= 0) return 0;
                ctx->path = (nh_anchor_t) {.index = stream->index, .len = offset};
                ctx->parse_state = PARSE_VERSION;
                stream->index += offset + 1;
                break;
            case PARSE_VERSION:
                if (!nh_string_cmp("HTTP/1.", &stream->buf[stream->index], 7)) return 0;
                stream->index += 7;
                switch (stream->buf[stream->index]) {
                    case '0':
                        ctx->version = HTTP_1_0;
                        break;
                    case '1':
                        ctx->version = HTTP_1_1;
                        break;
                    default:
                        return 0;
                }
                ctx->parse_state = PARSE_LINE_END;
                stream->index += 1;
                break;
            case PARSE_LINE_END:
                if (!nh_string_cmp("\r\n", &stream->buf[stream->index], 2)) return 0;
                stream->index += 2;
                ctx->parse_state = PARSE_SECOND_LINE_END;
                break;
            case PARSE_SECOND_LINE_END:
                if (!nh_string_cmp("\r\n", &stream->buf[stream->index], 2)) {
                    ctx->parse_state = PARSE_HEADER;
                    break;
                }
                // parse body
                stream->index += 2;
                ctx->parse_state = PARSE_BODY;
                // get body length before consume body
                nh_http_parse_get_body_len(ctx);
                // fallthrough
            case PARSE_BODY:
                if (nh_http_parse_consume_body(ctx)) ctx->parse_state = PARSE_DONE;
                break;
            case PARSE_HEADER:
                if (!nh_http_parse_consume_header(ctx)) return 0;
                ctx->parse_state = PARSE_LINE_END;
                break;
            case PARSE_DONE:
                return 1;
        }
    }
    return 1;
}

void nh_generate_http_response(http_context_t *ctx) {
    nh_stream_t *stream = &ctx->response.raw;
    nh_response_t *response = &ctx->response;

    // meta line
    nh_stream_write(stream, "HTTP/1.1 %u %s\r\n", response->status, nh_http_status[response->status]);

    // headers
    nh_header_t *header = response->header;
    while (header != NULL) {
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

void nh_keep_alive_handler(http_context_t *context) {
    if (FLAG_CHECK(context->session->flags, SESSION_FLAG_UPGRADED)) return;
    // just for keep alive now
    if (context->version == HTTP_1_1) {
        http_string_t connection = get_request_header(context, "Connection");
        if (connection.len > 5) {
            // not "close"
            FLAG_SET(context->session->flags, SESSION_FLAG_KEEP_ALIVE);
            set_response_header(context, "Connection", "keep-alive");
            return;
        }
    }
    FLAG_CLEAR(context->session->flags, SESSION_FLAG_KEEP_ALIVE);
    set_response_header(context, "Connection", "close");
}

void nh_session_read(nh_session_t *session) {
    session->state = SESSION_READ;
    session->timeout = session->server->timeout;
    if (nh_read_socket(&session->context.raw, session->socket) == 0) {
        session->state = SESSION_END;
        return;
    }

    int result = nh_http_parse(&session->context);
    if (session->context.parse_state != PARSE_DONE) return;
    if (result) {
        // success, process
        session->server->request_handler(&session->context);
        nh_keep_alive_handler(&session->context);
    } else {
        // fail, report error
        set_response_status(&session->context, 400);
        set_response_body(&session->context, "Bad Request");
    }
    nh_stream_init(&session->context.response.raw);
    nh_generate_http_response(&session->context);
    nh_session_write(session);
}

void nh_session_write(nh_session_t *session) {
    session->state = SESSION_WRITE;
    nh_stream_t *stream = &session->context.response.raw;
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
    if (FLAG_CHECK(session->flags, SESSION_FLAG_UPGRADED)) {
        // events will be handled by other protocols so just do noop
        nh_context_clear(&session->context);
        return;
    }

    if (FLAG_CHECK(session->flags, SESSION_FLAG_KEEP_ALIVE)) {
        nh_context_clear(&session->context);
        session->state = SESSION_READ;
        session->timeout = session->server->keep_alive_timeout;
    } else {
        session->state = SESSION_END;
    }
}

void nh_session_free(nh_session_t *session) {
    // clear events
    epoll_ctl(session->server->loop, EPOLL_CTL_DEL, session->socket, NULL);
    epoll_ctl(session->server->loop, EPOLL_CTL_DEL, session->timer_fd, NULL);
    // close fd
    close(session->timer_fd);
    close(session->socket);
    // free memory
    nh_context_clear(&session->context);
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
    if (session->state == SESSION_END) nh_session_free(session);
}

void nh_server_events_cb(struct epoll_event *ev) {
    nh_server_t *server = (nh_server_t *) ev->data.ptr;
    int socket;
    while ((socket = accept(server->socket, (struct sockaddr *) &server->addr, &server->addr_len)) > 0) {
        // init session
        nh_session_t *session = (nh_session_t *) calloc(1, sizeof(nh_session_t));
        assert(session != NULL);
        session->socket = socket;
        session->timeout = server->timeout;
        session->handler = nh_session_event_cb;
        session->server = server;
        session->context.session = session;
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
    read(session->timer_fd, &res, sizeof(res));
    if (--session->timeout == 0) {
        nh_session_free(session);
    }
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
    timerfd_settime(timer_fd, 0, &ts, NULL);

    session->timer_fd = timer_fd;
    session->timer_handler = nh_session_event_timer_cb;

    // add timer event on epoll
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = &session->timer_handler;
    epoll_ctl(session->server->loop, EPOLL_CTL_ADD, timer_fd, &ev);
}

void nh_server_bind(int socket, struct sockaddr_in *addr, const char *ip, int port) {
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip == NULL ? INADDR_ANY : inet_addr(ip);
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

int httpserver_listen(httpserver_option_t option) {
    nh_server_t *server = (nh_server_t *) malloc(sizeof(nh_server_t));
    assert(server != NULL);
    server->handler = nh_server_events_cb;
    server->request_handler = option.handler;
    server->timeout = option.timeout > 0 ? option.timeout : DEFAULT_TIMEOUT;
    server->keep_alive_timeout = MAX(server->timeout, option.keep_alive_timeout);
    server->loop = epoll_create1(0);

    nh_server_listen(server, option.ip_addr, option.port);

    struct epoll_event ev_list[1];
    int events;
    while ((events = epoll_wait(server->loop, ev_list, 1, -1)) > -1) {
        for (int i = 0; i < events; i++) {
            ev_cb_t *ev_cb = (ev_cb_t *) ev_list[i].data.ptr;
            ev_cb->handler(&ev_list[i]);
        }
    }
    return 0;
}

/**
 * External - Websocket Utils
 **/
#ifndef DISABLE_WEBSOCKET

#include <openssl/sha.h>

#define WEBSOCKET_MAGIC_NUMBER "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

struct ws_context_s {
    ev_handler_t handler;
    nh_session_t *session;
};

unsigned char const base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encode(unsigned char const src[static 1], size_t src_len, unsigned char dest[static 1]) {
    // modified from http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
    size_t olen = src_len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
    olen++; /* nul termination */
    if (olen < src_len) return 0;

    unsigned char const *end = src + src_len;
    unsigned char const *in = src;
    unsigned char *pos = dest;
    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    *pos = '\0';
    return pos - dest;
}

// 1 - success; 0 - fail
int nh_ws_handle_handshake(http_context_t *context) {
    http_string_t key;
    if (context->version == HTTP_1_0
        || !string_cmp_chars_case_insensitive(get_request_header(context, "Connection"), "upgrade")
        || !string_cmp_chars_case_insensitive(get_request_header(context, "Upgrade"), "websocket")
        || !string_cmp_chars_case_insensitive(get_request_header(context, "Sec-WebSocket-Version"), "13")
        // skip check about Sec-WebSocket-Protocol and Sec-WebSocket-Extension
        // base64(16bit) = 24bit
        || (key = get_request_header(context, "Sec-WebSocket-Key")).len != 24) {
        set_response_status(context, 400);
        return 0;
    }
    char raw[61] = {0};
    unsigned char sha1_encoded[SHA_DIGEST_LENGTH + 1] = {0};
    strncpy(raw, key.value, 24);
    strcpy(&raw[24], WEBSOCKET_MAGIC_NUMBER);
    SHA1((unsigned char const *) raw, 60, (unsigned char *) sha1_encoded);
    char *result = (char *) malloc_on_context(context, sizeof(char) * 31);
    base64_encode(sha1_encoded, SHA_DIGEST_LENGTH, (unsigned char *) result);
    set_response_status(context, 101);
    set_response_header(context, "Upgrade", "websocket");
    set_response_header(context, "Connection", "Upgrade");
    set_response_header(context, "Sec-WebSocket-Accept", result);
    return 1;
}


void nh_ws_event_cb(struct epoll_event *ev) {

}

ws_context_t *nh_ws_context_init(nh_session_t *session) {
    ws_context_t *context = (ws_context_t *) calloc(1, sizeof(ws_context_t));
    assert(context != NULL);
    context->session = session;
    context->handler = nh_ws_event_cb;
    return context;
}


void nh_ws_register_events(nh_session_t *session, ws_context_t *context) {
    // remove socket from epoll
    epoll_ctl(session->server->loop, EPOLL_CTL_DEL, session->socket, NULL);
    // keep timer on epoll and change timeout
    session->timeout = WEBSOCKET_TIMEOUT;
    // add new events to epoll for socket
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = context;
    epoll_ctl(session->server->loop, EPOLL_CTL_ADD, session->socket, &ev);
}

// ws_context_t will be returned for send message; return null pointer if fail to handshake
ws_context_t *serve_websocket(http_context_t *context, void (*receiver)(ws_context_t *)) {
    nh_session_t *session = context->session;
    if (!nh_ws_handle_handshake(context)) return NULL;
    // generate ws context
    ws_context_t *ws_context = nh_ws_context_init(session);
    // register epoll events based on old epoll events
    nh_ws_register_events(session, ws_context);
    // set flag upgraded
    FLAG_SET(session->flags, SESSION_FLAG_UPGRADED);

    return ws_context;
}

#endif