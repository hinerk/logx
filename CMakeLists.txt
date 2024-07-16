cmake_minimum_required(VERSION 3.14.1)
project(logx C)

set(CMAKE_C_STANDARD 11)

add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=)

add_library(
        logx
        STATIC
        src/logx.c
        src/logx.h
)


target_compile_definitions(
        logx

        PUBLIC LOGX_HEXDUMP
        PUBLIC LOGX_COLORED_OUTPUT
        PUBLIC LOGX_LOG_TO_LOGFILE
        PUBLIC LOGX_LOG_SOURCE_FILE
        PUBLIC LOGX_LOG_LINE_NUMBER
        PUBLIC LOGX_LOG_FUNC_NAME
)

add_executable(
        logx_app

        src/logx.c
        src/logx.h
        src/main.c
)

set_property(TARGET logx_app PROPERTY OUTPUT_NAME logx)

target_compile_definitions(
        logx_app

        PUBLIC LOGX_COLORED_OUTPUT
        PUBLIC LOGX_LOG_TO_LOGFILE
        PUBLIC LOGX_LOG_TAG
)

add_executable(logx-tests src/tests.c)
target_link_libraries(logx-tests logx)

