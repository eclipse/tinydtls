/*******************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Olaf Bergmann  - initial API and implementation
 *    Hauke Mehrtens - memory optimization, ECC integration
 *
 *******************************************************************************/

#include "tinydtls.h"

#ifdef IS_WINDOWS
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */
#endif /* IS_WINDOWS */

#if defined(HAVE_ASSERT_H) && !defined(assert)
#include <assert.h>
#endif

#include <stdarg.h>
#include <stdio.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <string.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef WITH_ZEPHYR
#ifdef HAVE_NET_SOCKET_H
#include <zephyr/net/socket.h>
#endif /* HAVE_NET_SOCKET_H */
typedef int in_port_t;
#endif /* WITH_ZEPHYR */

#include "global.h"
#include "dtls_debug.h"
#include "dtls_mutex.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifdef WITH_ZEPHYR
LOG_MODULE_REGISTER(TINYDTLS, CONFIG_TINYDTLS_LOG_LEVEL);
#endif /* WITH_ZEPHYR */

const char *dtls_package_name(void) {
  return PACKAGE_NAME;
}

const char *dtls_package_version(void) {
  return PACKAGE_VERSION;
}

#ifndef NDEBUG
static int maxlog = DTLS_LOG_WARN;      /* default maximum log level */

log_t
dtls_get_log_level(void) {
  return maxlog;
}

void
dtls_set_log_level(log_t level) {
  maxlog = level;
}

/* this array has the same order as the type log_t */
static const char *loglevels[] = {
  "EMRG", "ALRT", "CRIT", "WARN", "NOTE", "INFO", "DEBG"
};

#ifdef HAVE_TIME_H

#ifndef IS_WINDOWS

static inline size_t
print_timestamp(char *s, size_t len, time_t t) {
  struct tm *tmp;
  tmp = localtime(&t);
  return strftime(s, len, "%b %d %H:%M:%S", tmp);
}

#else

static inline size_t
print_timestamp(char *s, size_t len, time_t t) {
  struct tm tmp;
  errno_t err = localtime_s(&tmp, &t);
  if (err) {
      printf("Invalid argument to localtime_s.");
      exit(1);
  }
  return strftime(s, len, "%b %d %H:%M:%S", &tmp);
}

#endif

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

/**
 * A length-safe strlen() fake.
 *
 * @param s      The string to count characters != 0.
 * @param maxlen The maximum length of @p s.
 *
 * @return The length of @p s.
 */
static inline size_t
dtls_strnlen(const char *s, size_t maxlen) {
  size_t n = 0;
  while(*s++ && n < maxlen)
    ++n;
  return n;
}

/**
 * Write service-address as text to buffer.
 *
 * The text is \000 terminated.
 *
 * \param addr   The session including the sockaddr.
 * \param buf    The buffer to write the service address into.
 * \param len    The actual length of \p buf.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static size_t
dsrv_print_addr(const session_t *addr, char *buf, size_t len) {
#ifdef HAVE_INET_NTOP
  const void *addrptr = NULL;
  in_port_t port;
  char *p = buf;
  size_t append;
  int err;

  /* max. '[' ipv6 ']:' port '\0' */
  assert(len >= 1 + INET6_ADDRSTRLEN + 2 + 5 + 1);

  switch (addr->addr.sa.sa_family) {
  case AF_INET:
    addrptr = &addr->addr.sin.sin_addr;
    port = ntohs(addr->addr.sin.sin_port);
    break;
  case AF_INET6:
    *p++ = '[';
    --len;
    addrptr = &addr->addr.sin6.sin6_addr;
    port = ntohs(addr->addr.sin6.sin6_port);
    break;
  default:
    /* include terminating \000 */
    append = strlen("(unknown address type)");
    memcpy(p, "(unknown address type)", append + 1);
    return append;
  }

  if (inet_ntop(addr->addr.sa.sa_family, addrptr, p, len) == 0) {
    perror("dsrv_print_addr");
    return 0;
  }

  /* append inet_ntop to p */
  append = dtls_strnlen(p, len);
  p += append;
  len -= append;

  if (addr->addr.sa.sa_family == AF_INET6) {
    *p++ = ']';
    --len;
  }

  /* append port and \000 termination */
  err = snprintf(p, len, ":%d", port);
  if (err < 0) {
    return 0;
  }
  p += err;
  len -= err;

  return p - buf;
#else /* ! HAVE_INET_NTOP */

#ifdef WITH_CONTIKI
  char *p = buf;
#if NETSTACK_CONF_WITH_IPV6
  uint8_t i;
  const char hex[] = "0123456789ABCDEF";

  if (len < 41)
    return 0;

  *p++ = '[';

  for (i=0; i < 16; i += 2) {
    if (i) {
      *p++ = ':';
    }
    *p++ = hex[(addr->addr.u8[i] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i] & 0x0f)];
    *p++ = hex[(addr->addr.u8[i+1] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i+1] & 0x0f)];
  }
  *p++ = ']';
#else /* NETSTACK_CONF_IPV6 */
  if (len < 21)
    return 0;

  p += sprintf(p, "%u.%u.%u.%u",
               addr->addr.u8[0], addr->addr.u8[1],
               addr->addr.u8[2], addr->addr.u8[3]);
#endif /* NETSTACK_CONF_IPV6 */
  if (buf + len - p < 6)
    return 0;

  p += sprintf(p, ":%d", uip_htons(addr->port));

  return p - buf;

#endif /* WITH_CONTIKI */

#if defined(RIOT_VERSION) || defined(IS_WINDOWS) || defined(WITH_LWIP)
  /* FIXME: Switch to RIOT own DEBUG lines */
  /* TODO: Check if inet_ntop can be used on Windows */
  (void) addr;
  (void) buf;
  (void) len;
#endif /* RIOT_VERSION || IS_WINDOWS */

#ifdef WITH_POSIX
  /* TODO: output addresses manually */
#warning "inet_ntop() not available, network addresses will not be included in debug output"
#endif /* WITH_POSIX */

  return 0;
#endif /* ! HAVE_INET_NTOP */
}

#if !defined(WITH_CONTIKI) && !defined(_MSC_VER)

static void
dtls_logging_handler(log_t level, const char *message) {
  static char timebuf[32];
  FILE* log_fd = level <= DTLS_LOG_CRIT ? stderr : stdout;

  if (print_timestamp(timebuf,sizeof(timebuf), time(NULL)))
    fprintf(log_fd, "%s ", timebuf);

  if (level <= DTLS_LOG_DEBUG)
    fprintf(log_fd, "%s ", loglevels[level]);

  fwrite(message, strlen(message), 1, log_fd);
  fflush(log_fd);
}

static dtls_log_handler_t log_handler = dtls_logging_handler;

void
dtls_set_log_handler(dtls_log_handler_t app_handler) {
  if (app_handler == NULL)
    log_handler = dtls_logging_handler;
  else
    log_handler = app_handler;
}

#ifndef DTLS_DEBUG_BUF_SIZE
#define DTLS_DEBUG_BUF_SIZE 128
#endif

#ifdef DTLS_CONSTRAINED_STACK
static dtls_mutex_t static_mutex = DTLS_MUTEX_INITIALIZER;
static char message[DTLS_DEBUG_BUF_SIZE];
#endif /* DTLS_CONSTRAINED_STACK */

/*
 * Caution. If DTLS_CONSTRAINED_STACK is set, then the same mutex will get
 * locked in dtls_log() and/or dtls_dsrv_hexdump_log() so these functions
 * cannot call each other.  Furthermore, if log_handler() calls dsrv_log() /
 * dtls_dsrv_hexdump_log() there will be a recursive lookup.
 */
void
dsrv_log(log_t level, const char *format, ...) {
  va_list ap;
  size_t len;
#ifndef DTLS_CONSTRAINED_STACK
  char message[DTLS_DEBUG_BUF_SIZE];
#endif /* ! DTLS_CONSTRAINED_STACK */

  if (maxlog < (int) level)
    return;

#ifdef DTLS_CONSTRAINED_STACK
  dtls_mutex_lock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */
  va_start(ap, format);
  len = vsnprintf( message, sizeof(message), format, ap);
  va_end(ap);
  if (len + 1 > sizeof(message)) {
    /* 6 is needed as trailing 0 byte space needed */
    snprintf(&message[sizeof(message)-6], 6, " ...\n");
  }
  log_handler(level, message);
#ifdef DTLS_CONSTRAINED_STACK
  dtls_mutex_unlock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */
}

#elif defined (HAVE_VPRINTF) /* WITH_CONTIKI */
void
dsrv_log(log_t level, char *format, ...) {
  static char timebuf[32];
  va_list ap;

  if (maxlog < level)
    return;

  if (print_timestamp(timebuf,sizeof(timebuf), clock_time()))
    PRINTF("%s ", timebuf);

  if (level <= DTLS_LOG_DEBUG)
    PRINTF("%s ", loglevels[level]);

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
}
#endif /* WITH_CONTIKI */

/** dumps packets in usual hexdump format */
void hexdump(const unsigned char *packet, int length) {
  int n = 0;

  while (length--) {
    if (n % 16 == 0)
      printf("%08X ",n);

    printf("%02X ", *packet++);

    n++;
    if (n % 8 == 0) {
      if (n % 16 == 0)
        printf("\n");
      else
        printf(" ");
    }
  }
}

/** dump as narrow string of hex digits */
void dump(unsigned char *buf, size_t len) {
  while (len--)
    printf("%02x", *buf++);
}

void dtls_dsrv_log_addr(log_t level, const char *name, const session_t *addr)
{
  char addrbuf[73];
  int len;

  len = dsrv_print_addr(addr, addrbuf, sizeof(addrbuf));
  if (!len)
    return;
#ifdef WITH_ZEPHYR
  switch(level) {
    case DTLS_LOG_EMERG:
    case DTLS_LOG_ALERT:
    case DTLS_LOG_CRIT:
      Z_LOG(LOG_LEVEL_ERR, "%s: %s\n", name, addrbuf);
      break;
    case DTLS_LOG_WARN:
      Z_LOG(LOG_LEVEL_WRN, "%s: %s\n", name, addrbuf);
      break;
    case DTLS_LOG_NOTICE:
    case DTLS_LOG_INFO:
      Z_LOG(LOG_LEVEL_INF, "%s: %s\n", name, addrbuf);
      break;
    case DTLS_LOG_DEBUG:
      Z_LOG(LOG_LEVEL_DBG, "%s: %s\n", name, addrbuf);
      break;
  }
#else /* WITH_ZEPHYR */
  dsrv_log(level, "%s: %s\n", name, addrbuf);
#endif /* WITH_ZEPHYR */
}

#ifndef WITH_CONTIKI
void
dtls_dsrv_hexdump_log(log_t level, const char *name, const unsigned char *buf, size_t length, int extend) {
  int n = 0;
#ifndef DTLS_CONSTRAINED_STACK
  char message[DTLS_DEBUG_BUF_SIZE];
#endif /* ! DTLS_CONSTRAINED_STACK */
  size_t len;

  if (maxlog < (int) level)
    return;

#ifdef DTLS_CONSTRAINED_STACK
  dtls_mutex_lock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */
  if (extend) {
    snprintf(message, sizeof(message), "%s: (%zu bytes):\n", name, length);
    log_handler(level, message);
    len = 0;
    while (length-- && len + 1 < sizeof(message)) {
      if (n % 16 == 0) {
        len += snprintf(&message[len], sizeof(message)-len, "%08X ", n);
        if (len + 1 >= sizeof(message))
          break;
      }
      len += snprintf(&message[len], sizeof(message)-len, "%02X ", *buf++);
      if (len + 1 >= sizeof(message))
        break;
      n++;
      if (n % 8 == 0) {
        if (n % 16 == 0) {
          if (len + 2 < sizeof(message))
            snprintf(&message[len], sizeof(message)-len, "\n");
          else {
            /* 6 is needed as trailing 0 byte space needed */
            snprintf(&message[sizeof(message)-6], 6, " ...\n");
          }
          log_handler(level, message);
          len = 0;
        } else {
          len += snprintf(&message[len], sizeof(message)-len, " ");
        }
      }
    }
  } else {
    len = snprintf(message, sizeof(message), "%s: (%zu bytes): ", name, length);
    while (length-- && len + 1 < sizeof(message)) {
      len += snprintf(&message[len], sizeof(message)-len, "%02X", *buf++);
    }
  }
  if (len) {
    /* Process any new output */
    if (len + 2 < sizeof(message)) {
      snprintf(&message[len], sizeof(message)-len, "\n");
    } else {
      /* 6 is needed as trailing 0 byte space needed */
      snprintf(&message[sizeof(message)-6], 6, " ...\n");
    }
    log_handler(level, message);
  }
#ifdef DTLS_CONSTRAINED_STACK
  dtls_mutex_unlock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */
}
#else /* WITH_CONTIKI */
void
dtls_dsrv_hexdump_log(log_t level, const char *name, const unsigned char *buf, size_t length, int extend) {
  static char timebuf[32];
  int n = 0;

  if (maxlog < level)
    return;

  if (print_timestamp(timebuf,sizeof(timebuf), clock_time()))
    PRINTF("%s ", timebuf);

  if (level >= 0 && level <= DTLS_LOG_DEBUG)
    PRINTF("%s ", loglevels[level]);

  if (extend) {
    PRINTF("%s: (%zu bytes):\n", name, length);

    while (length--) {
      if (n % 16 == 0)
        PRINTF("%08X ", n);

      PRINTF("%02X ", *buf++);

      n++;
      if (n % 8 == 0) {
        if (n % 16 == 0)
          PRINTF("\n");
        else
          PRINTF(" ");
      }
    }
  } else {
    PRINTF("%s: (%zu bytes): ", name, length);
    while (length--)
      PRINTF("%02X", *buf++);
  }
  PRINTF("\n");
}
#endif /* WITH_CONTIKI */

#else /* NDEBUG */

log_t
dtls_get_log_level(void) {
  return 0;
}

void
dtls_set_log_level(log_t level) {
  (void)level;
}

void
hexdump(const unsigned char *packet, int length) {
  (void)packet;
  (void)length;
}

void
dump(unsigned char *buf, size_t len) {
  (void)buf;
  (void)len;
}

void
dtls_dsrv_hexdump_log(log_t level, const char *name, const unsigned char *buf, size_t length, int extend) {
  (void)level;
  (void)name;
  (void)buf;
  (void)length;
  (void)extend;
}

void
dsrv_log(log_t level, const char *format, ...) {
  (void)level;
  (void)format;
}

void
dtls_dsrv_log_addr(log_t level, const char *name, const session_t *addr) {
  (void)level;
  (void)name;
  (void)addr;
}

#endif /* NDEBUG */
