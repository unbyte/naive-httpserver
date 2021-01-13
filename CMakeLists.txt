cmake_minimum_required(VERSION 3.17)
project(naive_httpserver C)

set(CMAKE_C_STANDARD 11)

include_directories(lib)
include_directories(src)

set(CMAKE_C_FLAGS "-Wall -Wextra -lssl -lcrypto")
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-O3")

add_executable(example_http
        examples/http/main.c
        lib/server.c
        lib/server.h)

add_executable(example_ws
        examples/websocket/main.c
        lib/server.c
        lib/server.h)