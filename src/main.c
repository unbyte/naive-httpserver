#include "../lib/server.h"

void ws_connect_handler(ws_session_t *session) {
    printf("connected\n");
}

void ws_message_handler(ws_context_t *ctx, ws_session_t *session) {
    websocket_emit_text(session, 12, "have message");
}

void ws_close_handler(ws_session_t *session) {
    printf("closed!\n");
}

ws_handler_t *handlers = &(ws_handler_t) {
    .on_message = ws_message_handler,
    .on_close = ws_close_handler,
    .on_connect = ws_connect_handler,
};

void handler(http_context_t *ctx) {
    http_string_t path = get_request_path(ctx);
    http_string_t method = get_request_method(ctx);
    if (string_cmp_chars(method, "GET") && string_cmp_chars(path, "/")) {
        set_response_status(ctx, 200);
        set_response_header(ctx, "Content-Type", "text/html");
        set_response_body(ctx, "<h1>Hello World</h1>\n");
        return;
    }
    if (string_cmp_chars(method, "POST") && string_cmp_chars(path, "/echo")) {
        set_response_status(ctx, 200);
        set_response_body_string(ctx, get_request_body(ctx));
        return;
    }
    if (string_cmp_chars(path, "/ws")) {
        websocket_serve(ctx, handlers);
        return;
    }
    set_response_status(ctx, 404);
    set_response_header(ctx, "Content-Type", "text/html");
    set_response_body(ctx, "<h1>NOT FOUND</h1>\n");
}

int main() {
    httpserver_listen((httpserver_option_t) {
        .handler = handler,
        .port = 4399
    });
}