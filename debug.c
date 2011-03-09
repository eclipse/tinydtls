/* dsrv -- utility functions for servers that use datagram sockets
 *
 * Copyright (C) 2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "debug.h"

static int maxlog = LOG_WARN;	/* default maximum log level */

log_t 
get_log_level() {
  return maxlog;
}

void
set_log_level(log_t level) {
  maxlog = level;
}

/* this array has the same order as the type log_t */
static char *loglevels[] = {
  "EMRG", "ALRT", "CRIT", "WARN", "NOTE", "INFO", "DEBG" 
};

void 
dsrv_log(log_t level, char *format, ...) {
  static char timebuf[32];
  struct tm *tmp;
  time_t now;
  va_list ap;

  if (maxlog < level)
    return;

  time(&now);
  tmp = localtime(&now);

  if (strftime(timebuf,sizeof(timebuf), "%b %d %H:%M:%S", tmp))
    printf("%s ", timebuf);

  if (level >= 0 && level <= LOG_DEBUG) 
    printf("%s ", loglevels[level]);

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
  fflush(stdout);
}
