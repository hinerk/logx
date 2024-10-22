#include "logx.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>


#ifdef IS_WINDOWS
#include "processenv.h"


bool expand_path(const char *orig_path, char *expanded_path,
                 const int expanded_path_max_len) {
    const int size_expanded = ExpandEnvironmentStrings(
        orig_path, expanded_path, expanded_path_max_len);
    return size_expanded != 0 && size_expanded <= expanded_path_max_len;
}
#endif


#ifdef  IS_POSIX
#include <wordexp.h>


bool expand_path(const char *orig_path, char *expanded_path,
                 const int expanded_path_max_len) {
    wordexp_t p;

    wordexp(orig_path, &p, WRDE_NOCMD | WRDE_UNDEF | WRDE_SHOWERR);
    if (p.we_wordc != 1) {
        fprintf(
            stderr,
            p.we_wordc < 1 ? "expanding '%s' yields nothing!\n"
                           : "expanding '%s' yields too many (%d) results!\n",
            orig_path,
            p.we_wordc);
        wordfree(&p);
        return false;
    }

    strncpy(expanded_path, p.we_wordv[0], expanded_path_max_len);
    wordfree(&p);
    return true;
}
#endif


#define LOGX_MAX_PRIORITY_NAME_LEN 10
const char *logx_priority_names[] = {
    LOGX_PRIO_TRACE_STR,
    LOGX_PRIO_DEBUG_STR,
    LOGX_PRIO_INFORMAL_STR,
    LOGX_PRIO_NOTICE_STR,
    LOGX_PRIO_WARNING_STR,
    LOGX_PRIO_ERROR_STR,
    LOGX_PRIO_CRITICAL_STR,
    LOGX_PRIO_ALERT_STR,
    LOGX_PRIO_EMERGENCY_STR,
};


#ifdef LOGX_COLORED_OUTPUT
#define LOGX_MAX_PRIORITY_NAME_LEN_COLORED (LOGX_MAX_PRIORITY_NAME_LEN + 10)
const char *priority_names_colored[] = {
    COLORED_PRIORITY_STR(LOGX_PRIO_TRACE_STR ,LOGX_COLOR_TRACE),
    COLORED_PRIORITY_STR(LOGX_PRIO_DEBUG_STR ,LOGX_COLOR_DEBUG),
    COLORED_PRIORITY_STR(LOGX_PRIO_INFORMAL_STR ,LOGX_COLOR_INFORMAL),
    COLORED_PRIORITY_STR(LOGX_PRIO_NOTICE_STR ,LOGX_COLOR_NOTICE),
    COLORED_PRIORITY_STR(LOGX_PRIO_WARNING_STR ,LOGX_COLOR_WARNING),
    COLORED_PRIORITY_STR(LOGX_PRIO_ERROR_STR ,LOGX_COLOR_ERROR),
    COLORED_PRIORITY_STR(LOGX_PRIO_CRITICAL_STR ,LOGX_COLOR_CRITICAL),
    COLORED_PRIORITY_STR(LOGX_PRIO_ALERT_STR ,LOGX_COLOR_ALERT),
    COLORED_PRIORITY_STR(LOGX_PRIO_EMERGENCY_STR ,LOGX_COLOR_EMERGENCY),
};
#endif


bool logx_string_to_priority(Priority *priority, const char *priority_str) {
    for (int i = 0; i < LOGX_TOTAL_NUMBER_OF_PRIORITY_LEVELS; i++) {
        char priority_number[2];
        snprintf(priority_number, 2, "%d", i);

        if (0 == strncasecmp(priority_str,
                             logx_priority_names[i],
                             strlen(priority_str))
            || 0 == strcmp(priority_str, priority_number)) {
            *priority = i;
            return true;
        }
    }
    return false;
}


// logx_logfile_default stores the default logfile location ...
const char logx_logfile_default[] = LOGX_LOGFILE_DEFAULT;
// ... while logx_logfile points to the currently active logfile. The active
// logfile is selected within logx_init_logfile() based on environment
// variables or command line arguments.
const char *logx_logfile = logx_logfile_default;

#define LOGX_LOGFILE_EXPANDED_SIZE 512
char logx_logfile_expanded[LOGX_LOGFILE_EXPANDED_SIZE];


void logx_init_logfile() {
    const char *env_logfile = getenv(LOGX_LOGFILE_LOCATION_ENV_VAR);
    if (env_logfile != NULL) logx_logfile = env_logfile;
    if (expand_path(logx_logfile, logx_logfile_expanded,
                    LOGX_LOGFILE_EXPANDED_SIZE))
        return;
    fprintf(stderr, "failed to expand log file path: '%s'!\n", logx_logfile);
}


int logx_priority_threshold = LOGX_DEFAULT_THRESHOLD;
const char *logx_priority_threshold_name = NULL;

void logx_init_threshold() {
    const char *env_debug = getenv(LOGX_THRESHOLD_LEVEL_ENV_VAR);
    if (env_debug == NULL) return;
    const int increase_verbosity = atoi(env_debug);
    int threshold = logx_priority_threshold - increase_verbosity;
    threshold = threshold > Emergency ? Emergency: threshold;
    threshold = threshold < Trace ? Trace : threshold;
    logx_priority_threshold = threshold;
    logx_priority_threshold_name =
            logx_priority_names[LOGX_DEFAULT_THRESHOLD];
}


bool logx_is_initialized = false;


void logx_init() {
    if (logx_is_initialized) return;
    logx_is_initialized = true;
    logx_init_threshold();
    logx_init_logfile();
}


#ifdef LOGX_LOG_DATE
void logx_get_datetime(char buffer[22]) {
    const time_t t = time(NULL);
    const struct tm tm = *localtime(&t);
    sprintf(buffer, "[%04d-%02d-%02d %02d:%02d:%02d]",
            1900 + tm.tm_year, tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
}
#else
void logx_get_time(char buffer[11]) {
    const time_t t = time(NULL);
    const struct tm tm = *localtime(&t);
    sprintf(buffer, "[%02d:%02d:%02d]",
            tm.tm_hour, tm.tm_min, tm.tm_sec);
}
#endif


void logx_get_origin(char buffer[LOGX_ORIGIN_BUFFER_SIZE], const char *tag,
                     const char *file, const char *line, const char* func) {
#ifdef LOGX_LOG_TAG
    snprintf(buffer, LOGX_ORIGIN_BUFFER_SIZE, "%s", tag);
    return;
#else
    int printed = 0;

#ifdef LOGX_LOG_SOURCE_FILE
#ifdef LOGX_LOG_LINE_NUMBER
    char file_and_line_no[1024] = {0};
    snprintf(file_and_line_no, 1024, "%s:%s", file, line);
    printed += snprintf(&buffer[printed], LOGX_ORIGIN_BUFFER_SIZE - printed,
                        "%-*s", LOGX_RESERVED_SPACE_SOURCE_FILE
                              + LOGX_RESERVED_SPACE_LINE_NUMBER,
                        file_and_line_no);
#else
    printed += snprintf(&buffer[printed], LOGX_ORIGIN_BUFFER_SIZE - printed,
                        "%*s", LOGX_RESERVED_SPACE_SOURCE_FILE, file);
#endif
#endif

#ifdef LOGX_LOG_FUNC_NAME
    snprintf(&buffer[printed], LOGX_ORIGIN_BUFFER_SIZE - printed,
             " %-*s", LOGX_RESERVED_SPACE_FUNC_NAME, func);
#endif
#endif
}


/**
 * Checks if the given priority exceeds the current threshold.
 * @param[in] priority The priority to be tested.
 * @return True if the priority is greater than or equal to the threshold,
 *         false otherwise.
 */
bool logx_threshold_is_exceeded(const Priority priority) {
    return priority >= logx_priority_threshold;
}


/**
 * @brief Logs a formatted message with metadata to the specified file stream.
 *
 * This intermediate function is used internally by the logging system to
 * log messages with various metadata such as priority, tag, source file,
 * line number, and function name. It is not intended to be used directly
 * by users.
 *
 * @param[in] fp The file stream to which the log message will be written.
 * @param[in] colored A boolean indicating whether to use colored output
 *                    for the priority name.
 * @param[in] only_log_if_threshold_is_exceeded
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
 * @param[in] args Additional arguments for the format string.
 */
void logx_log_to_stream(FILE *fp, const bool colored, const Priority priority,
                        const bool only_log_if_threshold_is_exceeded,
                        const char *tag, const char *file, const char *line,
                        const char* func, const char *msg,
                        const va_list args) {
    if (only_log_if_threshold_is_exceeded
        && !logx_threshold_is_exceeded(priority)) return;

#ifdef LOGX_COLORED_OUTPUT
    const int priority_len = colored ? LOGX_MAX_PRIORITY_NAME_LEN_COLORED
                                     : LOGX_MAX_PRIORITY_NAME_LEN;
    const char *priority_name = colored ? priority_names_colored[priority]
                                        : logx_priority_names[priority];
#else
    const int priority_len = LOGX_MAX_PRIORITY_NAME_LEN;
    const char *priority_name = logx_priority_names[priority];
#endif

#ifdef LOGX_LOG_DATE
    char datetime[22];
    logx_get_datetime(datetime);
#else
    char datetime[11];
    logx_get_time(datetime);
#endif
#ifdef LOGX_LOG_ORIGIN
    char origin[LOGX_ORIGIN_BUFFER_SIZE] = {0};
    logx_get_origin(origin, tag, file, line, func);

    fprintf(fp,
            "%s  %*s  %-*s  ",
            datetime,
            priority_len,
            priority_name,
            LOGX_MIN_LEN_ORIGIN,
            origin);
#else
    fprintf(fp,
            "%s  %*s  ",
            datetime,
            priority_len,
            priority_name);
#endif
    vfprintf(fp, msg, args);
    fprintf(fp, "\n");
}


void logx(const Priority priority, const char *tag, const char *file,
          const char *line, const char* func, const char *msg, ...) {
    logx_init();

    va_list args;
    va_start(args, msg);
#ifdef LOGX_COLORED_OUTPUT
    bool colored = true;
#else
    bool colored = false;
#endif
    logx_log_to_stream(stderr, colored, priority,
                       true, tag, file, line, func,
                       msg, args);
    va_end(args);

#ifdef LOGX_LOG_TO_LOGFILE
    FILE *stream = fopen(logx_logfile_expanded, "a");
    if (stream == NULL) {
        fprintf(stderr,
                "logx error: cannot open '%s' for logging!\n",
                logx_logfile);
        return;
    }
    va_start(args, msg);
    logx_log_to_stream(stream, false, priority, false, tag, file,
                       line, func, msg, args);
    va_end(args);
    fflush(stream);
    fclose(stream);
#endif
}


#ifdef LOGX_HEXDUMP

/**
 * @brief writes whitespace separated bytes to buffer
 *
 * @note writes 3 * LOGX_HEXDUMP_BYTES_PER_ROW - 1 characters to buffer
 *
 * @note intended for internal usage only.
 *
 * @param[out] buffer the buffer to which the hexdump is written
 * @param[in] bytes the bytes to be dumped
 * @param[in] bytes_to_print the remaining number of bytes to dump
 */
void logx_hexdump_format_hex(char *buffer,
                             const uint8_t *bytes,
                             const unsigned int bytes_to_print) {
    unsigned int i_source = 0;
    unsigned int i_target = 0;
    const unsigned int abs_target_row_len = LOGX_HEXDUMP_BYTES_PER_ROW * 3;

    for (; i_source < bytes_to_print; i_source++, i_target = 3 * i_source) {
        sprintf(&buffer[i_target], "%02X", bytes[i_source]);
        buffer[i_target + 2] = ' ';
    }
    // if no more bytes to print, fill row with whitespaces
    for (; i_target < abs_target_row_len; i_target++) {
        buffer[i_target] = ' ';
    }
    buffer[abs_target_row_len - 1] = 0;
}


/**
 * @brief writes printable bytes as ascii to buffer, if not printable the
 *        byte is substituted with a '.'.
 *
 * @note writes LOGX_HEXDUMP_BYTES_PER_ROW characters to buffer
 *
 * @note intended for internal usage only.
 *
 * @param[out] buffer the buffer to which the hexdump is written
 * @param[in] bytes the bytes to be dumped
 * @param[in] bytes_to_print the remaining number of bytes to dump
 */
void logx_hexdump_format_ascii(char *buffer,
                               const uint8_t *bytes,
                               const unsigned int bytes_to_print) {
    unsigned int i = 0;
    for (; i < bytes_to_print; i++)
        buffer[i] = isprint(bytes[i]) ? bytes[i] : '.';
    // if no more bytes to print, fill row with whitespaces
    for (; i < LOGX_HEXDUMP_BYTES_PER_ROW; i++)
        buffer[i] = ' ';
}


/**
 * @brief writes a canonical hexdump row
 *
 * @note writes LOGX_HEXDUMP_BUFFER_SIZE_ROW bytes to buffer.
 *
 * @note intended for internal usage only.
 *
 * @param[out] buffer target buffer to which the hexdump row is written
 * @param[in] bytes the bytes to print
 * @param[in] bytes_to_print the number of remaining bytes to print
 * @param[in] address address of the hexdump row
 * @return number of written bytes, or negative number on failure
 */
int logx_hexdump_format_row(char *buffer,
                             const uint8_t *bytes,
                             const unsigned int bytes_to_print,
                             const unsigned int address) {
    char hex[3 * LOGX_HEXDUMP_BYTES_PER_ROW] = {0};
    char ascii[LOGX_HEXDUMP_BYTES_PER_ROW + 1] = {0};

    logx_hexdump_format_hex(hex, bytes, bytes_to_print);
    logx_hexdump_format_ascii(ascii, bytes, bytes_to_print);

    return sprintf(buffer, "%4x | %s | %s\n", address, hex, ascii);
}


void logx_format_hexdump(char *buffer, const uint8_t *bytes,
                         const unsigned int total_bytes) {
    unsigned int bytes_written = 0;
    for (unsigned int address = 0; address < total_bytes;
         address += LOGX_HEXDUMP_BYTES_PER_ROW) {
        const unsigned int remaining_bytes = total_bytes - address;
        const unsigned int bytes_to_print =
                remaining_bytes < LOGX_HEXDUMP_BYTES_PER_ROW
                ? remaining_bytes
                : LOGX_HEXDUMP_BYTES_PER_ROW;

        bytes_written += logx_hexdump_format_row(
                &buffer[bytes_written],
                &bytes[address],
                bytes_to_print,
                address);
    }
}


void logx_log_hexdump(const Priority priority, const char *tag,
                      const char *file, const char *line, const char* func,
                      const uint8_t *bytes, const int total_bytes,
                      const char *msg, ...) {
    va_list args;
    va_start(args, msg);
    const int msg_size = vsnprintf(NULL, 0, msg, args);
    va_end(args);

    char *formatted_msg = malloc(msg_size + 1);
    if (formatted_msg == NULL) {
        fprintf(stderr,
                "cannot allocate memory for formatted_msg buffer!\n");
        return;
    }

    va_start(args, msg);
    vsprintf(formatted_msg, msg, args);
    va_end(args);

    const int hexdump_buffer_size = logx_hexdump_calc_buffer_size(total_bytes);
    char *hexdump_buffer = malloc(hexdump_buffer_size);
    if (hexdump_buffer == NULL) {
        fprintf(stderr,
                "cannot allocate memory for hexdump_buffer!\n");
        free(formatted_msg);
        return;
    }
    logx_format_hexdump(hexdump_buffer, bytes, total_bytes);

    logx(priority, tag, file, line, func, "%s\n%s", formatted_msg, hexdump_buffer);
    free(hexdump_buffer);
    free(formatted_msg);
}

#endif // LOGX_HEXDUMP
