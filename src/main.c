#include "../lib/server.h"

void handler(nh_context_t *ctx) {
    nh_string_t path = get_request_path(ctx);
    nh_string_t method = get_request_method(ctx);
    if (string_cmp_chars(method, "GET")) {
        if (string_cmp_chars(path, "/")) {
            set_response_status(ctx, 200);
            set_response_body(ctx, "Hello World");
        } else if (string_cmp_chars(path, "/404")) {
            set_response_status(ctx, 404);
            set_response_body(ctx, "Not Found");
        } else if (string_cmp_chars(path, "/error")) {
            set_response_status(ctx, 500);
        } else {
            set_response_status(ctx, 200);
            set_response_body_string(ctx, path);
        }
    } else {
        if (string_cmp_chars(path, "/auth")) {
            nh_string_t auth = get_request_header(ctx, "X-Auth-Token");
            if (!string_cmp_chars(auth, "unbyte")) {
                set_response_status(ctx, 403);
                set_response_body(ctx, "Forbidden");
            } else {
                set_response_status(ctx, 200);
                set_response_body(ctx, ":)");
            }
        } else if (string_cmp_chars(path, "/echo")) {
            nh_string_t body = get_request_body(ctx);
            set_response_status(ctx, 200);
            set_response_body_string(ctx, body);
        } else {
            set_response_status(ctx, 200);
            set_response_body_string(ctx, path);
        }
    }
}

int main() {
    nh_server_t *http = httpserver_init(handler);
    httpserver_listen(http, 4399);
}