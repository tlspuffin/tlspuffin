#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

// NOTE: expose `vasprintf` even when _GNU_SOURCE is not set
extern int vasprintf(char **restrict strp, const char *restrict fmt, va_list ap);

void _log(void (*logger)(const char *), const char *format, ...)
{
    char *message = NULL;
    va_list args;

    va_start(args, format);
    vasprintf(&message, format, args);
    va_end(args);
    logger(message);

    free(message);
}
