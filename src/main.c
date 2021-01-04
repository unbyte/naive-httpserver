#include "../lib/server.h"

void handler(http_context_t *ctx) {
    http_string_t path = get_request_path(ctx);
    http_string_t method = get_request_method(ctx);
    if (string_cmp_chars(method, "GET") && string_cmp_chars(path, "/")) {
        set_response_status(ctx, 200);
        set_response_header(ctx, "Content-Type", "text/html");
        set_response_body(ctx, "<h1>Hello World</h1>");
        return;
    }
    if (string_cmp_chars(method, "POST") && string_cmp_chars(path, "/echo")) {
        set_response_status(ctx, 200);
        set_response_body_string(ctx, get_request_body(ctx));
        return;
    }
    set_response_status(ctx, 404);
    set_response_header(ctx, "Content-Type", "text/html");
    set_response_body(ctx, "<h1>NOT FOUND</h1>");
}

int main() {
    httpserver_t *http = httpserver_init(handler);
    httpserver_listen(http, 4399);
}