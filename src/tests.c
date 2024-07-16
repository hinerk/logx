# include "logx.h"


int main () {
    logx_log_location(Emergency, "format string at end of the message: %s","test");
    logx_emergency("format string at end of the message: %s", "test");

    logx_emergency("test log_emergency");
    logx_alert("test log_alert");
    logx_critical("test log_critical");
    logx_error("test log_error");
    logx_warning("test log_warning");
    logx_notice("test log_notice");
    logx_info("test log_info");
    logx_debug("test log_debug");
    logx_trace("test log_trace");

    char bytes2[] = "Hello world and such ... I need more than 16 letters";
#if LOGX_HEXDUMP
    logx_hexdump(Error, (uint8_t *) bytes2, sizeof bytes2, "dumping %d bytes", 3);
#endif
}
