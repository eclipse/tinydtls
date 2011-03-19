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

#include <string.h>

#include "numeric.h"
#include "ccm.h"

#define CCM_FLAGS(A,M,L) (((A > 0) << 6) | (((M - 2)/2) << 3) | (L - 1))

#define MASK_L(_L) ((1 << 8 * _L) - 1)

#define SET_COUNTER(A,L,cnt,C) {					\
    int i;								\
    memset((A) + DTLS_CCM_BLOCKSIZE - (L), 0, (L));			\
    (C) = (cnt) & MASK_L(L);						\
    for (i = DTLS_CCM_BLOCKSIZE - 1; (C) && (i > (L)); --i, (C) >>= 8)	\
      (A)[i] |= (C) & 0xFF;						\
  }

void 
block0(size_t M,       /* number of auth bytes */
       size_t L,       /* number of bytes to encode message length */
       size_t la,      /* l(a) octets additional authenticated data */
       size_t lm,      /* l(m) message length */
       unsigned char N[DTLS_CCM_BLOCKSIZE],
       unsigned char *result) {
  int i;

  result[0] = CCM_FLAGS(la, M, L);

  /* copy the nonce */
  memcpy(result + 1, N, DTLS_CCM_BLOCKSIZE - L);
  
  for (i=0; i < L; i++) {
    result[15-i] = lm & 0xff;
    lm >>= 8;
  }
}

void
memxor(unsigned char *x, unsigned char *y, size_t n) {
  while(n--) {
    *x ^= *y;
    x++; y++;
  }
}

size_t
dtls_ccm_encrypt_message(rijndael_ctx *ctx, size_t M, size_t L, 
			 unsigned char N[DTLS_CCM_BLOCKSIZE], 
			 unsigned char *msg, size_t lm, size_t la) {
  size_t i, j, len;
  unsigned long C;
  unsigned long counter = 1; /* \bug does not work correctly on ia32 when
			             lm >= 2^16 */
  unsigned char A[DTLS_CCM_BLOCKSIZE]; /* A_i blocks for encryption input */
  unsigned char B[DTLS_CCM_BLOCKSIZE]; /* B_i blocks for CBC-MAC input */
  unsigned char S[DTLS_CCM_BLOCKSIZE]; /* S_i = encrypted A_i blocks */
  unsigned char X[DTLS_CCM_BLOCKSIZE]; /* X_i = encrypted B_i blocks */

  len = lm;			/* save original length */
  lm -= la;			/* detract additional auth data count */
  /* create the initial authentication block B0 */
  block0(M, L, la, lm, N, B);
  rijndael_encrypt(ctx, B, X);

  memset(B, 0, DTLS_CCM_BLOCKSIZE);

  if (la) {
    if (la < 0xFF00) {		/* 2^16 - 2^8 */
      j = 2;
      dtls_int_to_uint16(B, la);
    } else if (la < 0x100000000L) {
      j = 6;
      dtls_int_to_uint16(B, 0xFFFE);
      dtls_int_to_uint32(B+2, la);
    } else {
      j = 10;
      dtls_int_to_uint16(B, 0xFFFF);
      dtls_ulong_to_uint64(B+2, la);
    }

    i = min(DTLS_CCM_BLOCKSIZE - j, la);
    memcpy(B + j, msg, i);
    la -= i;
    msg += i;
    
    memxor(B, X, DTLS_CCM_BLOCKSIZE);
  } 
  
  rijndael_encrypt(ctx, B, X);
  
  while (la > DTLS_CCM_BLOCKSIZE) {
    for (i = 0; i < DTLS_CCM_BLOCKSIZE; ++i)
      B[i] = X[i] ^ *msg++;
    la -= DTLS_CCM_BLOCKSIZE;

    rijndael_encrypt(ctx, B, X);
  }
  
  if (la) {
    memset(B, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(B, msg, la);
    memxor(B, X, DTLS_CCM_BLOCKSIZE);

    rijndael_encrypt(ctx, B, X);  
    msg += la;
  }  

  /* initialize block template */
  A[0] = L-1;

  /* copy the nonce */
  memcpy(A + 1, N, DTLS_CCM_BLOCKSIZE - L);
  
  while (lm > DTLS_CCM_BLOCKSIZE) {
    /* calculate MAC */
    for (i = 0; i < DTLS_CCM_BLOCKSIZE; ++i)
      B[i] = X[i] ^ msg[i];

    rijndael_encrypt(ctx, B, X);
    
    /* encrypt */
    SET_COUNTER(A, L, counter, C);
    
    rijndael_encrypt(ctx, A, S);
    
    memxor(msg, S, DTLS_CCM_BLOCKSIZE);
    
    /* update local pointers */
    lm -= DTLS_CCM_BLOCKSIZE;
    msg += DTLS_CCM_BLOCKSIZE;
    counter++;
  }

  if (lm) {
    /* calculate MAC */
    memset(B, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(B, msg, lm);
    memxor(B, X, DTLS_CCM_BLOCKSIZE);

    rijndael_encrypt(ctx, B, X);

    /* encrypt */
    SET_COUNTER(A, L, counter, C);
    rijndael_encrypt(ctx, A, S);

    memxor(msg, S, lm);

    /* update local pointers */
    msg += lm;
  }
  
  /* calculate S_0 */  
  SET_COUNTER(A, L, 0, C);
  rijndael_encrypt(ctx, A, S);

  for (i = 0; i < M; ++i) 
    *msg++ = X[i] ^ S[i];

  return len + M;
}

