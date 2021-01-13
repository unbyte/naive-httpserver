#include <stdlib.h>
#include <memory.h>
#include "server.h"

#define STORE_KEY_USER_ID 0

#define MAX_USER 512

struct {
    ws_session_t *users[MAX_USER];
    uint16_t users_count;
} room = {0};

void ws_connect_handler(ws_session_t *session) {
    if (room.users_count == MAX_USER) {
        websocket_emit_text(session, 9, "max users");
        websocket_close(session);
        return;
    }
    room.users[room.users_count] = session;
    uint16_t *id = malloc(sizeof(uint16_t));
    *id = room.users_count++;
    websocket_store_set(session, STORE_KEY_USER_ID, id);
}

void ws_close_handler(ws_session_t *session) {
    uint16_t *id = (uint16_t *) websocket_store_get(session, STORE_KEY_USER_ID);
    if (id == NULL) return;
    char buf[16];
    sprintf(buf, "#%u has quit", *id);
    room.users[*id] = NULL;
    for (uint16_t i = 0; i < room.users_count; ++i) {
        if (i == *id || room.users[i] == NULL) continue;
        websocket_emit_text(room.users[i], strlen(buf), buf);
    }
}

void ws_message_handler(ws_context_t *ctx, ws_session_t *session) {
    uint16_t *id = (uint16_t *) websocket_store_get(session, STORE_KEY_USER_ID);
    if (id == NULL) return;
    http_string_t payload = websocket_get_payload(ctx);
    if (string_cmp_chars(payload, "quit")) {
        ws_close_handler(session);
        websocket_close(session);
        return;
    }
    char *raw = string_to_chars(payload);
    char buf[payload.len + 10];

    sprintf(buf, "#%u: %s", *id, raw);
    for (uint16_t i = 0; i < room.users_count; ++i) {
        if (i == *id || room.users[i] == NULL) continue;
        websocket_emit_text(room.users[i], strlen(buf), buf);
    }
}

ws_handler_t *handlers = &(ws_handler_t) {
    .on_message = ws_message_handler,
    .on_close = ws_close_handler,
    .on_connect = ws_connect_handler,
};

void handler(http_context_t *ctx) {
    http_string_t path = get_request_path(ctx);
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