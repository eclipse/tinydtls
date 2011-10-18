/* dtls -- a very basic DTLS implementation
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

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include "uip.h"
typedef struct {
  int rlen;
  uip_ipaddr_t raddr;
  unsigned short rport;
  int ifindex;
} __uip_session_t;
#define session_t __uip_session_t

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

/** Maximum size of DTLS message */
#define DTLS_MAX_BUF 256

/** 
 * Known cipher suites. Note that the NULL suite is always available.
 * Other cipher suites are included only if defined here.
 *
 * \hideinitializer
 */
#define TLS_PSK_WITH_AES_128_CBC_SHA { 0x00, 0x8c }
#define TLS_NULL_WITH_NULL_NULL      { 0x00, 0x00 }
/* #define TLS_PSK_WITH_AES_128_CCM_8 */

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

#endif /* _GLOBAL_H_ */
