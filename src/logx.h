#ifndef LOGX_H
#define LOGX_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>


#if defined(_WIN32) || defined(_WIN64)
#define IS_WINDOWS
#elif defined(__linux__) || defined(__unix__)
#define IS_POSIX
#endif


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)


/**
 * @def LOGX_COLORED_OUTPUT
 * @brief whether to color stderr output
 */


/**
 * @def LOGX_LOG_TO_LOGFILE
 * @brief whether to log to a logfile
 */


/**
 * @def LOGX_HEXDUMP
 * @brief whether to enable hexdump feature
 */


/**
 * @def LOGX_LOG_DATE
 * @brief whether to log the date along with the time
 */

/**
 * @def LOGX_LOG_SOURCE_FILE
 * @brief whether to log the source file
 */


/**
 * @def LOGX_LOG_LINE_NUMBER
 * @brief whether to log the line number
 */


/**
 * @def LOGX_LOG_FUNC_NAME
 * @brief whether to log the function name
 */


/**
 * @def LOGX_DEFAULT_THRESHOLD
 * @brief Minimum log level which is printed on stderr.
 *
 * This macro defines the default minimum log level for messages that will be
 * printed to `stderr`. Messages with a log level below this threshold will
 * be ignored and not printed.
 *
 * The log levels in this application are defined as follows:
 * - 0: TRACE
 * - 1: DEBUG
 * - 2: INFORMAL
 * - 3: NOTICE
 * - 4: WARNING
 * - 5: ERROR
 * - 6: CRITICAL
 * - 7: ALERT
 * - 8: EMERGENCY
 *
 * By default, this threshold is set to 4, meaning only messages with a log
 * level of WARNING (4) or higher will be printed.
 *
 * This default can be overridden at runtime by setting the environment
 * variable specified by `LOGX_THRESHOLD_LEVEL_ENV_VAR`.
 *
 * Default value: 4 (WARNING)
 */
#ifndef LOGX_DEFAULT_THRESHOLD
#define LOGX_DEFAULT_THRESHOLD 4
#endif

/**
 * @def LOGX_THRESHOLD_LEVEL_ENV_VAR
 * @brief Name of the environment variable that alters the log threshold level
 *        at runtime.
 *
 * This macro defines the name of the environment variable which can be used
 * to override the default log threshold level (`LOGX_DEFAULT_THRESHOLD`) at
 * runtime.
 *
 * The log threshold level determines the minimum severity level of messages
 * that will be logged. This allows dynamic configuration of logging
 * behavior without modifying the source code.
 *
 * Default value: "DEBUG"
 */
#ifndef LOGX_THRESHOLD_LEVEL_ENV_VAR
#define LOGX_THRESHOLD_LEVEL_ENV_VAR "DEBUG"
#endif


/**
 * @def LOGX_LOGFILE_LOCATION_ENV_VAR
 * @brief Name of the environment variable that specifies the log file
 *        location.
 *
 * This macro defines the name of the environment variable which can be used
 * to specify the location of the log file. If this environment variable is
 * set, its value will override the default log file location defined by
 * `LOGX_LOGFILE_DEFAULT`.
 *
 * The default name for this environment variable is "LOGX_LOGFILE".
 */
#ifndef LOGX_LOGFILE_LOCATION_ENV_VAR
#define LOGX_LOGFILE_LOCATION_ENV_VAR "LOGX_LOGFILE"
#endif


/**
 * @def LOGX_DEFAULT_TAG
 * @brief specifies the default tag used by logx if no other tag is provided
 * via command line
 */
#ifndef LOGX_DEFAULT_TAG
#define LOGX_DEFAULT_TAG "logx"
#endif


/**
 * @def LOGX_ORIGIN_BUFFER_SIZE
 * @brief specifies the size of the buffer used when compiling the log
 *        messages origin. Should be allocated dynamically.
 */
#ifndef LOGX_ORIGIN_BUFFER_SIZE
#define LOGX_ORIGIN_BUFFER_SIZE 512
#endif


typedef enum Priority {
    Trace = 0,
    Debug,
    Informal,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
    LOGX_TOTAL_NUMBER_OF_PRIORITY_LEVELS,
} Priority;


/**
 * @brief array holding the log level names ordered by increasing severity
 */
extern const char *logx_priority_names[];


/**
 * @brief variable holding the logfile location
 */
extern const char *logx_logfile;


/**
 * @brief Converts a string representation of a priority level to the
 *        corresponding Priority enum value.
 *
 * This function takes a string that represents a priority level (e.g.,
 * "Emergency", "Alert", "Critical", etc.) and converts it into the
 * corresponding `Priority` enum value. It returns true if the conversion
 * is successful, and false otherwise, regardless of the case of the input
 * string
 * .
 * @param[out] priority A pointer to the `Priority` variable where the
 *                      converted priority value will be stored.
 * @param[in]  priority_str A string representing the priority level to be
 *                          converted.
 *
 * @return true if the conversion is successful, false if the string does not
 *         match any known priority level.
 *
 * @note The function assumes that the input string is case-insensitive and
 *       will convert it to the appropriate `Priority` enum value regardless
 *       of the case of the input string.
 */
bool logx_string_to_priority(Priority *priority, const char *priority_str);


/**
 * @brief Logs a formatted message to stderr and if compiled with
 *        LOGX_LOG_TO_LOGFILE to logfile.
 *
 * This intermediate function is used internally by the logging system to
 * log messages with various metadata such as priority, tag, source file,
 * line number, and function name. It is not intended to be used directly
 * by users.
 *
 * @param[in] priority The priority level of the log message.
 * @param[in] tag A string representing the tag associated with the log
 *                message.
 * @param[in] file A string representing the source file from which the log
 *                 message originated.
 * @param[in] line A string representing the line number in the source file
 *                 from which the log message originated.
 * @param[in] func A string representing the function name from which the
 *                 log message originated.
 * @param[in] msg The format string for the log message.
 * @param[in] ... Additional arguments for the format string.
 * @param ...
 */
void logx(Priority priority, const char *tag, const char *file,
          const char *line, const char* func, const char *msg, ...);


/**
 * @def logx_log_tag
 * @brief completes call to logx for usage with tag information. This macro
 *        is intended for usage from logx app only.
 */
#define logx_log_tag(tag, priority, msg) \
    logx(priority, tag, "", "", "", msg, NULL)


/**
 * @def logx_log_location
 * @brief completes call to logx with information about the origin of the
 *        log message (source file, line number and function name)
 */
#define logx_log_location(priority, msg, ...) \
    logx(priority, "", __FILE__, TOSTRING(__LINE__), \
    __FUNCTION__, msg, ##__VA_ARGS__)


/**
 * @def logx_emergency
 * @brief Logs a message with emergency severity, allowing numbers and strings
 *        to be formatted into msg, analogous to printf.
 */
#define logx_emergency(msg, ...) \
    logx_log_location(Emergency, msg, ##__VA_ARGS__)

/**
 * @def logx_alert
 * @brief Logs a message with alert severity, allowing numbers and strings
 *        to be formatted into msg, analogous to printf.
 */
#define logx_alert(msg, ...) \
    logx_log_location(Alert, msg, ##__VA_ARGS__)

/**
 * @def logx_critical
 * @brief Logs a message with critical severity, allowing numbers and strings
 *        to be formatted into msg, analogous to printf.
 */
#define logx_critical(msg, ...) \
    logx_log_location(Critical, msg, ##__VA_ARGS__)

/**
 * @def logx_error
 * @brief Logs a message with error severity, allowing numbers and strings
 *        to be formatted into msg, analogous to printf.
 */
#define logx_error(msg, ...) \
    logx_log_location(Error, msg, ##__VA_ARGS__)

/**
 * @def logx_warning
 * @brief Logs a message with warning severity, allowing numbers and strings
 *        to be formatted into msg, analogous to printf.
 */
#define logx_warning(msg, ...) \
    logx_log_location(Warning, msg, ##__VA_ARGS__)

/**
 * @def logx_notice
 * @brief Logs a message with notice severity, allowing numbers and strings
 *        to be formatted into msg, analogous to printf.
 */
#define logx_notice(msg, ...) \
    logx_log_location(Notice, msg, ##__VA_ARGS__)

/**
 * @def logx_info
 * @brief Logs a message with informational severity, allowing numbers and
 *        strings to be formatted into msg, analogous to printf.
 */
#define logx_info(msg, ...) \
    logx_log_location(Informal, msg, ##__VA_ARGS__)

/**
 * @def logx_debug
 * @brief Logs a message with debug severity, allowing numbers and strings
 *        to be formatted into msg, analogous to printf.
 */
#define logx_debug(msg, ...) \
    logx_log_location(Debug, msg, ##__VA_ARGS__)

/**
 * @def logx_trace
 * @brief Logs a message with trace severity, allowing numbers and strings
 *        to be formatted into msg, analogous to printf.
 */
#define logx_trace(msg, ...) \
    logx_log_location(Trace, msg, ##__VA_ARGS__)


#ifdef LOGX_HEXDUMP
/**
 * @brief log a hexdump along with a message
 *
 * @note intended for internal usage only.
 *
 * @param[in] priority The priority level of the log message.
 * @param[in] tag A string representing the tag associated with the log
 *                message.
 * @param[in] file A string representing the source file from which the log
 *                 message originated.
 * @param[in] line A string representing the line number in the source file
 *                 from which the log message originated.
 * @param[in] func A string representing the function name from which the
 *                 log message originated.
 * @param[in] bytes the bytes of which a hexdump is provided along with the
 *                  message
 * @param[in] total_bytes the total number of bytes covered in the hexdump
 * @param[in] msg The format string for the log message.
 * @param[in] ... Additional arguments for the format string.
 */
void logx_log_hexdump(Priority priority, const char *tag, const char *file,
                      const char *line, const char* func,
                      const uint8_t *bytes, int total_bytes,
                      const char *msg, ...);


#define logx_hexdump(priority, bytes, bytes_size, msg, ...) \
    logx_log_hexdump(priority, "", __FILE__, TOSTRING(__LINE__), \
                     __FUNCTION__, bytes, bytes_size, \
                     msg, ##__VA_ARGS__)
#endif

#define ANSI_COLOR_BLACK                     30
#define ANSI_COLOR_RED                       31
#define ANSI_COLOR_GREEN                     32
#define ANSI_COLOR_YELLOW                    33
#define ANSI_COLOR_BLUE                      34
#define ANSI_COLOR_MAGENTA                   35
#define ANSI_COLOR_CYAN                      36
#define ANSI_COLOR_WHITE                     37
#define ANSI_COLOR_BRIGHT_BLACK              90
#define ANSI_COLOR_BRIGHT_RED                91
#define ANSI_COLOR_BRIGHT_GREEN              92
#define ANSI_COLOR_BRIGHT_YELLOW             93
#define ANSI_COLOR_BRIGHT_BLUE               94
#define ANSI_COLOR_BRIGHT_MAGENTA            95
#define ANSI_COLOR_BRIGHT_CYAN               96
#define ANSI_COLOR_BRIGHT_WHITE              97


#define LOGX_PRIO_TRACE_STR             "Trace"
#define LOGX_PRIO_DEBUG_STR             "Debug"
#define LOGX_PRIO_INFORMAL_STR          "Informal"
#define LOGX_PRIO_NOTICE_STR            "Notice"
#define LOGX_PRIO_WARNING_STR           "Warning"
#define LOGX_PRIO_ERROR_STR             "Error"
#define LOGX_PRIO_CRITICAL_STR          "Critical"
#define LOGX_PRIO_ALERT_STR             "Alert"
#define LOGX_PRIO_EMERGENCY_STR         "Emergency"


#define LOGX_COLOR_EMERGENCY            ANSI_COLOR_BRIGHT_MAGENTA
#define LOGX_COLOR_ALERT                ANSI_COLOR_MAGENTA
#define LOGX_COLOR_CRITICAL             ANSI_COLOR_BRIGHT_RED
#define LOGX_COLOR_ERROR                ANSI_COLOR_RED
#define LOGX_COLOR_WARNING              ANSI_COLOR_BRIGHT_YELLOW
#define LOGX_COLOR_NOTICE               ANSI_COLOR_GREEN
#define LOGX_COLOR_INFORMAL             ANSI_COLOR_CYAN
#define LOGX_COLOR_DEBUG                ANSI_COLOR_WHITE
#define LOGX_COLOR_TRACE                ANSI_COLOR_BRIGHT_BLACK


// Test whether to log the origin of the log message
#if defined (LOGX_LOG_TAG) || defined(LOGX_LOG_APP_NAME) \
 || defined (LOGX_LOG_FUNC_NAME) || defined(LOGX_LOG_SOURCE_FILE)
#define LOGX_LOG_ORIGIN
#endif


// enable logging of the source file, if logging of source code line
// numbers is enabled
#if defined(LOGX_LOG_LINE_NUMBER) && ! defined(LOGX_LOG_SOURCE_FILE)
#define LOGX_LOG_SOURCE_FILE
#endif


// calculate the minimum space reserved for the origin part of the log message

#ifdef LOGX_LOG_TAG
#ifndef LOGX_RESERVED_SPACE_TAG
#define LOGX_RESERVED_SPACE_TAG 10
#endif
#else
#ifndef LOGX_RESERVED_SPACE_TAG
#define LOGX_RESERVED_SPACE_TAG 0
#endif
#endif


#ifdef LOGX_LOG_FUNC_NAME
#ifndef LOGX_RESERVED_SPACE_FUNC_NAME
#define LOGX_RESERVED_SPACE_FUNC_NAME 10
#endif
#else
#ifndef LOGX_RESERVED_SPACE_FUNC_NAME
#define LOGX_RESERVED_SPACE_FUNC_NAME 0
#endif
#endif


#ifdef LOGX_LOG_SOURCE_FILE
#ifndef LOGX_RESERVED_SPACE_SOURCE_FILE
#define LOGX_RESERVED_SPACE_SOURCE_FILE 10
#endif
#else
#ifndef LOGX_RESERVED_SPACE_SOURCE_FILE
#define LOGX_RESERVED_SPACE_SOURCE_FILE 0
#endif
#endif


#ifdef LOGX_LOG_LINE_NUMBER
#ifndef LOGX_RESERVED_SPACE_LINE_NUMBER
#define LOGX_RESERVED_SPACE_LINE_NUMBER 4
#endif
#else
#ifndef LOGX_RESERVED_SPACE_LINE_NUMBER
#define LOGX_RESERVED_SPACE_LINE_NUMBER 0
#endif
#endif


/**
 * @def LOGX_MIN_LEN_ORIGIN
 * @brief the minimum reserved space for the log messages origin
 */
#ifndef LOGX_MIN_LEN_ORIGIN
#define LOGX_MIN_LEN_ORIGIN (\
      LOGX_RESERVED_SPACE_TAG \
    + LOGX_RESERVED_SPACE_FUNC_NAME \
    + LOGX_RESERVED_SPACE_SOURCE_FILE \
    + LOGX_RESERVED_SPACE_LINE_NUMBER )
#endif


/**
 * @def LOGX_LOGFILE_DEFAULT
 * @brief Default file path for the log file.
 *
 * This macro defines the default file path for the log file. The default
 * location is used if no other log file path is specified at runtime.
 *
 * The default log file location can be altered based on the operating system:
 * - On POSIX systems: "/tmp/logx.log"
 * - On Windows systems: "%TMP%/logx.log"
 * - otherwise: "./logx.log"
 *
 */
#ifndef LOGX_LOGFILE_DEFAULT
#ifdef IS_POSIX
#define LOGX_LOGFILE_DEFAULT "/tmp/logx.log"
#elif defined(IS_WINDOWS)
#define LOGX_LOGFILE_DEFAULT "%TMP%/logx.log"
#else
#define LOGX_LOGFILE_DEFAULT "logx.log"
#endif
#endif


/**
 * @brief Macro that wraps a priority name in ANSI color control sequences.
 *
 * This macro takes a priority name and a color code, and returns the priority
 * name string wrapped in the appropriate ANSI escape sequences for colored
 * output in the terminal.
 *
 * @param priority_str The priority name to be colored.
 * @param color The ANSI color code to apply.
 */
#define COLORED_PRIORITY_STR(priority_str, color) \
    "\33[1;" TOSTRING(color) "m" priority_str "\33[0m"


#endif
