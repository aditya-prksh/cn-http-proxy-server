#include "error_handler.h"
#include "logger.h"
#include <stdio.h>
void report_error(const char *c,const char *m){char b[512];snprintf(b,sizeof(b),"%s: %s",c?c:"UNKNOWN",m?m:"unspecified error");logger_log("ERROR",b);}
