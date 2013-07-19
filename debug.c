/* debug.c -- debug utilities
 *
 * Copyright (C) 2011--2012 Olaf Bergmann <bergmann@tzi.org>
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

#include "config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
#include <assert.h>
#endif

#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "global.h"
#include "debug.h"

#ifdef WITH_CONTIKI
# ifndef DEBUG
#  define DEBUG DEBUG_PRINT
# endif /* DEBUG */
#include "net/uip-debug.h"
#else
#define PRINTF(...)
#endif

static int maxlog = LOG_WARN;	/* default maximum log level */

log_t 
dtls_get_log_level() {
  return maxlog;
}

void
dtls_set_log_level(log_t level) {
  maxlog = level;
}

/* this array has the same order as the type log_t */
static char *loglevels[] = {
  "EMRG", "ALRT", "CRIT", "WARN", "NOTE", "INFO", "DEBG" 
};

#ifdef HAVE_TIME_H

static inline size_t
print_timestamp(char *s, size_t len, time_t t) {
  struct tm *tmp;
  tmp = localtime(&t);
  return strftime(s, len, "%b %d %H:%M:%S", tmp);
}

#else /* alternative implementation: just print the timestamp */

static inline size_t
print_timestamp(char *s, size_t len, clock_time_t t) {
#ifdef HAVE_SNPRINTF
  return snprintf(s, len, "%u.%03u", 
		  (unsigned int)(t / CLOCK_SECOND), 
		  (unsigned int)(t % CLOCK_SECOND));
#else /* HAVE_SNPRINTF */
  /* @todo do manual conversion of timestamp */
  return 0;
#endif /* HAVE_SNPRINTF */
}

#endif /* HAVE_TIME_H */

#ifndef HAVE_STRNLEN
/** 
 * A length-safe strlen() fake. 
 * 
 * @param s      The string to count characters != 0.
 * @param maxlen The maximum length of @p s.
 * 
 * @return The length of @p s.
 */
static inline size_t
strnlen(const char *s, size_t maxlen) {
  size_t n = 0;
  while(*s++ && n < maxlen)
    ++n;
  return n;
}
#endif /* HAVE_STRNLEN */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

size_t
dsrv_print_addr(const session_t *addr, unsigned char *buf, size_t len) {
#ifdef HAVE_ARPA_INET_H
  const void *addrptr = NULL;
  in_port_t port;
  unsigned char *p = buf;

  switch (addr->addr.sa.sa_family) {
  case AF_INET: 
    addrptr = &addr->addr.sin.sin_addr;
    port = ntohs(addr->addr.sin.sin_port);
    break;
  case AF_INET6:
    if (len < 7) /* do not proceed if buffer is even too short for [::]:0 */
      return 0;

    *p++ = '[';

    addrptr = &addr->addr.sin6.sin6_addr;
    port = ntohs(addr->addr.sin6.sin6_port);

    break;
  default:
    memcpy(buf, "(unknown address type)", min(22, len));
    return min(22, len);
  }

  if (inet_ntop(addr->addr.sa.sa_family, addrptr, (char *)p, len) == 0) {
    perror("dsrv_print_addr");
    return 0;
  }

  p += strnlen((char *)p, len);

  if (addr->addr.sa.sa_family == AF_INET6) {
    if (p < buf + len) {
      *p++ = ']';
    } else 
      return 0;
  }

  p += snprintf((char *)p, buf + len - p + 1, ":%d", port);

  return buf + len - p;
#else /* HAVE_ARPA_INET_H */
# if WITH_CONTIKI
  unsigned char *p = buf;
  uint8_t i;
#  if WITH_UIP6
  const unsigned char hex[] = "0123456789ABCDEF";

  if (len < 41)
    return 0;

  *p++ = '[';

  for (i=0; i < 8; i += 4) {
    *p++ = hex[(addr->addr.u16[i] & 0xf000) >> 24];
    *p++ = hex[(addr->addr.u16[i] & 0x0f00) >> 16];
    *p++ = hex[(addr->addr.u16[i] & 0x00f0) >> 8];
    *p++ = hex[(addr->addr.u16[i] & 0x000f)];
    *p++ = ':';
  }
  *(p-1) = ']';
#  else /* WITH_UIP6 */
#   warning "IPv4 network addresses will not be included in debug output"

  if (len < 21)
    return 0;
#  endif /* WITH_UIP6 */
  if (buf + len - p < 6)
    return 0;

#ifdef HAVE_SNPRINTF
  p += snprintf((char *)p, buf + len - p + 1, ":%d", uip_htons(addr->port));
#else /* HAVE_SNPRINTF */
  /* @todo manual conversion of port number */
#endif /* HAVE_SNPRINTF */

  return buf + len - p;
# else /* WITH_CONTIKI */
  /* TODO: output addresses manually */
#   warning "inet_ntop() not available, network addresses will not be included in debug output"
# endif /* WITH_CONTIKI */
  return 0;
#endif
}

#ifndef WITH_CONTIKI
void 
dsrv_log(log_t level, char *format, ...) {
  static char timebuf[32];
  va_list ap;
  FILE *log_fd;

  if (maxlog < level)
    return;

  log_fd = level <= LOG_CRIT ? stderr : stdout;

  if (print_timestamp(timebuf,sizeof(timebuf), time(NULL)))
    fprintf(log_fd, "%s ", timebuf);

  if (level >= 0 && level <= LOG_DEBUG) 
    printf("%s ", loglevels[level]);

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
  fflush(stdout);
}
#else /* WITH_CONTIKI */
void 
dsrv_log(log_t level, char *format, ...) {
  static char timebuf[32];
  va_list ap;

  if (maxlog < level)
    return;

  if (print_timestamp(timebuf,sizeof(timebuf), clock_time()))
    PRINTF("%s ", timebuf);

  if (level >= 0 && level <= LOG_DEBUG) 
    PRINTF("%s ", loglevels[level]);

  va_start(ap, format);
#ifdef HAVE_VPRINTF
  vprintf(format, ap);
#else
  PRINTF(format, ap);
#endif
  va_end(ap);
}
#endif /* WITH_CONTIKI */
