cmake_minimum_required(VERSION 3.17)
project(naive_httpserver C)

set(CMAKE_C_STANDARD 11)

include_directories(lib)
include_directories(src)

add_executable(naive-httpserver
        src/main.c
        lib/server.c
        lib/server.h)