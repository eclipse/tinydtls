/* dtls -- a very basic DTLS implementation
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

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include "config.h"

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#ifndef assert
#warning "assertions are disabled"
#  define assert(x)
#endif
#endif

#include <string.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef DTLSv12
/* The current version of tinyDTLS supports DTLSv1.2 only. */
#define DTLSv12 1
#endif

#ifndef WITH_SHA256
/* The current version of tinyDTLS supports DTLSv1.2 with SHA256 PRF
   only. */
#define WITH_SHA256 1
#endif

#ifndef WITH_CONTIKI
typedef unsigned int clock_time_t;
#else /* WITH_CONTIKI */
#include "uip.h"
typedef struct {
  unsigned char size;
  uip_ipaddr_t addr;
  unsigned short port;
  int ifindex;
} __uip_session_t;
#define session_t __uip_session_t

#define _dtls_address_equals_impl(A,B)				\
  ((A)->size == (B)->size					\
   && (A)->port == (B)->port					\
   && uip_ipaddr_cmp(&((A)->addr),&((B)->addr))			\
   && (A)->ifindex == (B)->ifindex)

#endif /* WITH_CONTIKI */

/** multi-purpose address abstraction */
#ifndef session_t
typedef struct __session_t {
  socklen_t size;		/**< size of addr */
  union {
    struct sockaddr     sa;
    struct sockaddr_storage st;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
  } addr;
  int ifindex;
} __session_t;

#define session_t __session_t

static inline int 
_dtls_address_equals_impl(const session_t *a,
			  const session_t *b) {
  if (a->ifindex != b->ifindex ||
      a->size != b->size || a->addr.sa.sa_family != b->addr.sa.sa_family)
    return 0;
  
  /* need to compare only relevant parts of sockaddr_in6 */
 switch (a->addr.sa.sa_family) {
 case AF_INET:
   return 
     a->addr.sin.sin_port == b->addr.sin.sin_port && 
     memcmp(&a->addr.sin.sin_addr, &b->addr.sin.sin_addr, 
	    sizeof(struct in_addr)) == 0;
 case AF_INET6:
   return a->addr.sin6.sin6_port == b->addr.sin6.sin6_port && 
     memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr, 
	    sizeof(struct in6_addr)) == 0;
 default: /* fall through and signal error */
   ;
 }
 return 0;
}
#endif /* session_t */

/* Define our own types as at least uint32_t does not work on my amd64. */

typedef unsigned char uint8;
typedef unsigned char uint16[2];
typedef unsigned char uint24[3];
typedef unsigned char uint32[4];
typedef unsigned char uint48[6];

#ifndef HAVE_STR
typedef struct {
  size_t length;		/* length of string */
  unsigned char *s;		/* string data */
} str;
#endif

#ifndef DTLS_MAX_BUF
/** Maximum size of DTLS message. */
#define DTLS_MAX_BUF 256
#endif

#ifndef DTLS_DEFAULT_MAX_RETRANSMIT
/** Number of message retransmissions. */
#define DTLS_DEFAULT_MAX_RETRANSMIT 5
#endif

/** Known cipher suites.*/
typedef enum { 
  TLS_NULL_WITH_NULL_NULL = 0x0000,   /**< NULL cipher  */
  TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8 /**< see RFC 6655 */
} dtls_cipher_t;

/** 
 * XORs \p n bytes byte-by-byte starting at \p y to the memory area
 * starting at \p x. */
static inline void
memxor(unsigned char *x, const unsigned char *y, size_t n) {
  while(n--) {
    *x ^= *y;
    x++; y++;
  }
}

#ifdef HAVE_FLS
#define dtls_fls(i) fls(i)
#else
static inline int 
dtls_fls(unsigned int i) {
  int n;
  for (n = 0; i; n++)
    i >>= 1;
  return n;
}
#endif /* HAVE_FLS */

/** 
 * Resets the given session_t object @p sess to its default
 * values.  In particular, the member rlen must be initialized to the
 * available size for storing addresses.
 * 
 * @param sess The session_t object to initialize.
 */
static inline void
dtls_session_init(session_t *sess) {
  assert(sess);
  memset(sess, 0, sizeof(session_t));
  sess->size = sizeof(sess->addr);
}

static inline int
dtls_session_equals(const session_t *a, const session_t *b) {
  assert(a); assert(b);
  return _dtls_address_equals_impl(a, b);
}
#endif /* _GLOBAL_H_ */
