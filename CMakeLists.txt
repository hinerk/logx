cmake_minimum_required(VERSION 3.14.1)
project(logx C)

set(CMAKE_C_STANDARD 11)

option(LOGX_ENABLE_FEATURE_HEXDUMP "whether logx_hexdump is available" OFF)
option(LOGX_ENABLE_COLORED_OUTPUT "whether log is colored" OFF)
option(LOGX_LOG_TO_LOGFILE "whether to log also to a logfile" OFF)
option(LOGX_LOG_SOURCE_FILE
        "whether to log the source file a message originated from" OFF)
option(LOGX_LOG_LINE_NUMBER
        "whether to log the line number a message originated from" OFF)
option(LOGX_LOG_FUNC_NAME
        "whether to log the line number a message originated from" OFF)
option(LOGX_DEFAULT_THRESHOLD
        "set default threshold to be exceeded to display the message")
option(LOGX_THRESHOLD_LEVEL_ENV_VAR
        "alter the name of the environment variable controlling the threshold
        at runtime")
option(LOGX_LOGFILE_LOCATION_ENV_VAR
        "specify name of the environment variable that specifies the log file
        location")
option(LOGX_DEFAULT_TAG
        "specify the default tag used by logx if no other tag is provided
        via command line")
option(LOGX_LOGFILE_DEFAULT
        "alter default logfile name")


if (LOGX_ENABLE_FEATURE_HEXDUMP)
    add_compile_definitions(LOGX_HEXDUMP)
endif()

if (LOGX_ENABLE_COLORED_OUTPUT)
    add_compile_definitions(LOGX_COLORED_OUTPUT)
endif()

if (LOGX_LOG_TO_LOGFILE)
    add_compile_definitions(LOGX_LOG_TO_LOGFILE)
endif()

if (LOGX_LOG_SOURCE_FILE)
    add_compile_definitions(LOGX_LOG_SOURCE_FILE)
endif()

if (LOGX_LOG_LINE_NUMBER)
    add_compile_definitions(LOGX_LOG_LINE_NUMBER)
endif()

if (LOGX_LOG_FUNC_NAME)
    add_compile_definitions(LOGX_LOG_FUNC_NAME)
endif()


if (LOGX_DEFAULT_THRESHOLD)
    add_compile_definitions(LOGX_DEFAULT_THRESHOLD=${LOGX_DEFAULT_THRESHOLD})
endif()

if (LOGX_THRESHOLD_LEVEL_ENV_VAR)
    add_compile_definitions(LOGX_THRESHOLD_LEVEL_ENV_VAR=${LOGX_THRESHOLD_LEVEL_ENV_VAR})
endif()

if (LOGX_DEFAULT_TAG)
    add_compile_definitions(LOGX_DEFAULT_TAG=${LOGX_DEFAULT_TAG})
endif()

if (LOGX_LOGFILE_DEFAULT)
    add_compile_definitions(LOGX_LOGFILE_DEFAULT=${LOGX_LOGFILE_DEFAULT})
endif()



add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=)

add_library(
        logx
        STATIC
        src/logx.c
        src/logx.h
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
        PUBLIC LOGX_LOG_TAG
)

add_executable(logx-tests src/tests.c)
target_link_libraries(logx-tests logx)

