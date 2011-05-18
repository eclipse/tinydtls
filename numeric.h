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

#ifndef _NUMERIC_H_
#define _NUMERIC_H_

#include <stdint.h>

#ifndef min
#define min(A,B) ((A) <= (B) ? (A) : (B))
#endif

#ifndef max
#define max(A,B) ((A) < (B) ? (B) : (A))
#endif

/**
 * Increments given \p Var of type \p Type by \c 1.
 *
 * \hideinitializer
 */
#define inc_uint(Type,Var) {			\
    int i = sizeof(Type);			\
    while (i && !++((Var)[--i]));		\
  }

/* this one is for consistency... */
#define dtls_int_to_uint8(Field,Value) do {			\
    *(unsigned char*)(Field) = (Value) & 0xff;			\
  } while(0)

#define dtls_int_to_uint16(Field,Value) do {			\
    *(unsigned char*)(Field) = ((Value) >> 8) & 0xff;		\
    *(((unsigned char*)(Field))+1) = ((Value) & 0xff);		\
  } while(0)

#define dtls_int_to_uint24(Field,Value) do {			\
    *(unsigned char*)(Field) = ((Value) >> 16) & 0xff;		\
    dtls_int_to_uint16((((unsigned char*)(Field))+1),Value);	\
  } while(0)

#define dtls_int_to_uint32(Field,Value) do {				\
    *(unsigned char*)(Field) = ((Value) >> 24) & 0xff;			\
    *(((unsigned char*)(Field))+1) = ((Value) >> 16) & 0xff;		\
    *(((unsigned char*)(Field))+2) = ((Value) >> 8) & 0xff;		\
    *(((unsigned char*)(Field))+3) = (Value) & 0xff;			\
  } while(0)

#define dtls_ulong_to_uint48(Field,Value) do {				\
    *(unsigned char*)(Field) = ((Value) >> 40) & 0xff;			\
    *(((unsigned char*)(Field))+1) = ((Value) >> 32) & 0xff;		\
    *(((unsigned char*)(Field))+2) = ((Value) >> 24) & 0xff;		\
    *(((unsigned char*)(Field))+3) = ((Value) >> 16) & 0xff;		\
    *(((unsigned char*)(Field))+4) = ((Value) >> 8) & 0xff;		\
    *(((unsigned char*)(Field))+5) = (Value) & 0xff;			\
  } while(0)

#define dtls_ulong_to_uint64(Field,Value) do {				\
    *(unsigned char*)(Field) = ((Value) >> 56) & 0xff;			\
    *(((unsigned char*)(Field))+1) = ((Value) >> 48) & 0xff;		\
    *(((unsigned char*)(Field))+2) = ((Value) >> 40) & 0xff;		\
    *(((unsigned char*)(Field))+3) = ((Value) >> 32) & 0xff;		\
    *(((unsigned char*)(Field))+4) = ((Value) >> 24) & 0xff;		\
    *(((unsigned char*)(Field))+5) = ((Value) >> 16) & 0xff;		\
    *(((unsigned char*)(Field))+6) = ((Value) >> 8) & 0xff;		\
    *(((unsigned char*)(Field))+7) = (Value) & 0xff;			\
  } while(0)

#define dtls_uint8_to_int(Field) \
  (*(unsigned char*)(Field) & 0xFF)

#define dtls_uint16_to_int(Field) \
  (((*(unsigned char*)(Field)) << 8) | (*(((unsigned char*)(Field))+1)))

#define dtls_uint24_to_int(Field)		\
  (((*(((unsigned char*)(Field)))) << 16)	\
   | ((*(((unsigned char*)(Field))+1)) << 8)	\
   | ((*(((unsigned char*)(Field))+2))))
  
#define dtls_uint48_to_ulong(Field)			\
  (((uint64_t) *(unsigned char*)(Field)) << 40)		\
  | (((uint64_t) *(((unsigned char*)(Field))+1)) << 32)	\
  | (((uint64_t) *(((unsigned char*)(Field))+2)) << 24)	\
  | (((uint64_t) *(((unsigned char*)(Field))+3)) << 16)	\
  | (((uint64_t) *(((unsigned char*)(Field))+4)) << 8)	\
  | (((uint64_t) *(((unsigned char*)(n))+5)))

#endif /* _NUMERIC_H_ */
