# logx - a tiny logging facility

logx offers a "C" library for logging purposes, along with a command-line 
interface designed to meet the logging needs of shell scripts.
Its aim of use are embedded systems and situations in which there is no
abundance of compute, memory or storage. Therefore, one of its design goals is
the ability to strip features not required before the build.

Depending on whether one is using the app or API, log messages are formatted 
slightly different. Using the app, one can tag a message to provide a hint of
its origin, while logging from the library will show the source file with line 
number and function name from which a message originated.

Additional to the log facilities, the API provides a method for logging 
hexdumps which produces log messages like:

```
[13:54:13]  Error      src/tests.c:22 main       dumping 3 bytes
   0 | 48 65 6C 6C 6F 20 77 6F 72 6C 64 20 61 6E 64 20 | Hello world and 
  10 | 73 75 63 68 20 2E 2E 2E 20 49 20 6E 65 65 64 20 | such ... I need 
  20 | 6D 6F 72 65 20 74 68 61 6E 20 31 36 20 6C 65 74 | more than 16 let
  30 | 74 65 72 73 00                                  | ters. 
```

## Important Notes

The author has little experience with C and cmake. Code review is welcome!

## TODOs

* `CMakeLists.txt` currently hardcodes compile definitions.
* `LOGX_ORIGIN_BUFFER_SIZE` is hardcoded. Dynamic allocation appears to be 
  the more reliable approach.

# App Usage

```
logx command line interface

Usage: log [-h,--help] [-l LOGFILE] [-t TAG] [-p PRIORITY] MSG
    -l LOGFILE  alter logfile location
    -t TAG      additional info about the source
    -p PRIORITY the messages severity [0-8], defaults to 1 (Debug)
                  0: Trace
                  1: Debug
                  2: Informal
                  3: Notice
                  4: Warning
                  5: Error
                  6: Critical
                  7: Alert
                  8: Emergency
    MSG         message

Messages with a severity of Warning (4) or larger are logged to stderr.
The threshold can be adjusted via 'DEBUG' environment variable.
Setting 'DEBUG=3' will increase verbosity by 3 severity levels. All
messages of a severity of Debug (1) or larger will be logged to stderr.
Similarly, verbosity can be decreased by setting 'DEBUG' to a negative
value.
Additionally and regardless their severity, all messages are logged to
/tmp/logx.log.
```

# API Usage

`log.h` exports `logx_emergency`, `logx_alert`, `logx_critical`, `logx_error`,
`logx_warning`, `logx_notice`, `logx_info`, `logx_debug` and `logx_trace`
macros. All of which except a message which might be formatted with subsequent
data, like `printf`.

`logx_hexdump(priority, bytes, bytes_size, msg, ...)` macro will render a 
message followed by a hexdump of `bytes`.


# Building


## Build Options

* `LOGX_COLORED_OUTPUT` enables colored severity levels on stderr output.
* `LOGX_LOG_TO_LOGFILE` enables logging to a logfile additionally to stderr.
* `LOGX_HEXDUMP` enables hexdump macro.
* `LOGX_LOG_DATE` by default, only the time is logged. If `LOGX_LOG_DATE`
   is defined during build, date and time are logged along with the message
* `LOGX_DEFAULT_THRESHOLD` the default threshold which must be exceeded for 
  a log message to be printed on stderr (defaults to Warning(4)).
* `LOGX_THRESHOLD_LEVEL_ENV_VAR` the name of the environment variable, 
  which allows for runtime adjustment of `LOGX_DEFAULT_THRESHOLD` (defaults 
  to `DEBUG`).
* `LOGX_LOGFILE_LOCATION_ENV_VAR` the name of the environment variable, 
  which allows for runtime adjustment of the used logfile (defaults to
  `LOGX_LOGFILE`).


### Build Options only concerning the CLI

* `LOGX_DEFAULT_TAG` specifies the default tag with which a log message is
  tagged


### Build Options only concerning the API

* `LOGX_LOG_SOURCE_FILE` whether to log the source file where the log 
  message originated.
* `LOGX_LOG_LINE_NUMBER` whether to log line number from which the log 
  message originated (will enable `LOGX_LOG_SOURCE_FILE` as well).
* `LOGX_LOG_FUNC_NAME` whether to log the function name from which the log
  message originated.
