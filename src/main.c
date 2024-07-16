# include <string.h>
# include <stdlib.h>
# include "logx.h"
# include <stdio.h>


const char help_text[] =
"logx command line interface \n"
"\n"
"Usage: log [-h,--help] "
#ifdef LOGX_LOG_TO_LOGFILE
"[-l LOGFILE] "
#endif
"[-t TAG] [-p PRIORITY] MSG\n"
#ifdef LOGX_LOG_TO_LOGFILE
"    -l LOGFILE  alter logfile location\n"
#endif
"    -t TAG      additional info about the source\n"
"    -p PRIORITY the messages severity [0-8], defaults to 1 (Debug)\n"
"%s"   // format priority levels
"    MSG         message\n"
"\n"
"Messages with a severity of %s (%d) or larger are logged to stderr.\n"
"The threshold can be adjusted via '%s' environment variable.\n"
"Setting '%s=3' will increase verbosity by 3 severity levels. All\n"
"messages of a severity of %s (%d) or larger will be logged to stderr.\n"
"Similarly, verbosity can be decreased by setting '%s' to a negative\n"
"value.\n"
#ifdef LOGX_LOG_TO_LOGFILE
"Additionally and regardless their severity, all messages are logged to\n"
"%s.\n"
#endif
;


#define HELP_TEXT_PRIORITY_BUFFER_SIZE (8 * 79)

char help_text_priority_buffer[HELP_TEXT_PRIORITY_BUFFER_SIZE];


void format_help_text_priorities() {
    int offset = 0;
    for (int i = 0; i < LOGX_TOTAL_NUMBER_OF_PRIORITY_LEVELS; i++) {
        offset += snprintf(
                &help_text_priority_buffer[offset],
                HELP_TEXT_PRIORITY_BUFFER_SIZE - offset,
                "%*s  %d: %s\n",
                16, "", i, logx_priority_names[i]);
    }
}


void show_help() {
    format_help_text_priorities();
    fprintf(stderr, help_text, help_text_priority_buffer,
            logx_priority_names[LOGX_DEFAULT_THRESHOLD],
            LOGX_DEFAULT_THRESHOLD, LOGX_THRESHOLD_LEVEL_ENV_VAR,
            LOGX_THRESHOLD_LEVEL_ENV_VAR,
            logx_priority_names[LOGX_DEFAULT_THRESHOLD - 3],
            LOGX_DEFAULT_THRESHOLD - 3, LOGX_THRESHOLD_LEVEL_ENV_VAR
#ifdef LOGX_LOG_TO_LOGFILE
            , logx_logfile
#endif
            );
}


const char logx_default_tag[] = LOGX_DEFAULT_TAG;


int main(const int argc, const char * argv[]) {
    Priority priority = 1;
    const char *tag = logx_default_tag;
    char * message = NULL;

    // Argument Parsing
    //
    // Any parameter must precede the log message. If a command line argument
    // is not identified as parameter, it is considered part of the log
    // message. From then on, all arguments are considered the log message.
    for (int i = 1; i < argc; i++) {
        if (message == NULL) {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                show_help();
                exit(255);
            }
            if (strcmp(argv[i], "-l") == 0) {
                logx_logfile = argv[++i];
                continue;
            }
            if (strcmp(argv[i], "-p") == 0) {
                if (!logx_string_to_priority(&priority, argv[++i])) {
                    fprintf(stderr,
                            "unknown priority level \"%s\"!\n",
                            argv[i]);
                    return 1;
                }
                continue;
            }
            if (strcmp(argv[i], "-t") == 0) {
                tag = argv[++i];
                continue;
            }

            // argv[i] is no command line argument: therefore, begin
            // recording the log message.
            message = malloc(strlen(argv[i]) + 1);
            strcpy(message, argv[i]);
            continue;
        }

        char *r_message = realloc(message,
                                  strlen(message) + strlen(argv[i]) + 2);
        if (r_message == NULL) {
            free(message);
            return 1;
        }

        message = r_message;
        strcat(message, " ");
        strcat(message, argv[i]);
    }

    if (message == NULL) {
        message = malloc(1);
        strcpy(message, "");
    }

    logx_log_tag(tag, priority, message);
    free(message);
}
