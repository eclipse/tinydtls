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

#include <stdio.h>
#include <assert.h>

#include "aes/rijndael.h"

#include "global.h"
#include "debug.h"
#include "numeric.h"
#include "dtls.h"
#include "crypto.h"

#ifndef NDEBUG
extern void dump(unsigned char *, size_t);
#endif

/** 
 * The list of acceptable cipher suites. Do not include the NULL
 * cipher here as it would enable a bid-down attack.
 */
const dtls_cipher_t ciphers[] = {
#ifdef TLS_PSK_WITH_AES_128_CBC_SHA
  { TLS_PSK_WITH_AES_128_CBC_SHA, AES_BLKLEN, 16, HASH_SHA1, 20, 20, 16 },
#else
#error "TLS_PSK_WITH_AES_128_CBC_SHA not defined!"
#endif

  /* \todo: add TLS_PSK_WITH_AES_128_CCM_8 */

  { { 0, 0 }, 0, 0, HASH_NONE, 0, 0, 0 } /* end marker */
};

#define HMAC_UPDATE_SEED(Context,Seed,Length)		\
  if (Seed) dtls_hmac_update(Context, (Seed), (Length))

/** 
 * \bug dtls_hmac_finalize() releases the hash function's 
 *      memory. Maybe we are better off with another 
 *      hmac function API.
 */
size_t
dtls_p_hash(dtls_hashfunc_t h,
	    unsigned char *key, size_t keylen,
	    unsigned char *label, size_t labellen,
	    unsigned char *random1, size_t random1len,
	    unsigned char *random2, size_t random2len,
	    unsigned char *buf, size_t buflen) {
  dtls_hmac_context_t hmac_a, hmac_p;

  static unsigned char A[DTLS_HMAC_MAX];
  static unsigned char tmp[DTLS_HMAC_MAX];
  size_t dlen;			/* digest length */
  size_t len = 0;			/* result length */

  dtls_hmac_init(&hmac_a, key, keylen, h);

  /* calculate A(1) from A(0) == seed */
  HMAC_UPDATE_SEED(&hmac_a, label, labellen);
  HMAC_UPDATE_SEED(&hmac_a, random1, random1len);
  HMAC_UPDATE_SEED(&hmac_a, random2, random2len);

  dlen = dtls_hmac_finalize(&hmac_a, A);

  while (len + dlen < buflen) {
    dtls_hmac_init(&hmac_p, key, keylen, h);
    dtls_hmac_update(&hmac_p, A, dlen);

    HMAC_UPDATE_SEED(&hmac_p, label, labellen);
    HMAC_UPDATE_SEED(&hmac_p, random1, random1len);
    HMAC_UPDATE_SEED(&hmac_p, random2, random2len);

    len += dtls_hmac_finalize(&hmac_p, tmp);
    memxor(buf, tmp, dlen);
    buf += dlen;

    /* calculate A(i+1) */
    dtls_hmac_init(&hmac_a, key, keylen, h);
    dtls_hmac_update(&hmac_a, A, dlen);
    dtls_hmac_finalize(&hmac_a, A);
  }

  dtls_hmac_init(&hmac_p, key, keylen, h);
  dtls_hmac_update(&hmac_p, A, dlen);
  
  HMAC_UPDATE_SEED(&hmac_p, label, labellen);
  HMAC_UPDATE_SEED(&hmac_p, random1, random1len);
  HMAC_UPDATE_SEED(&hmac_p, random2, random2len);
  
  dtls_hmac_finalize(&hmac_p, tmp);
  memxor(buf, tmp, buflen - len);

  return buflen;
}

size_t 
dtls_prf(unsigned char *key, size_t keylen,
	 unsigned char *label, size_t labellen,
	 unsigned char *random1, size_t random1len,
	 unsigned char *random2, size_t random2len,
	 unsigned char *buf, size_t buflen) {
#if DTLS_VERSION == 0xfeff
  size_t len_2 = keylen >> 1;

  /* Clear the result buffer */
  memset(buf, 0, buflen);

  dtls_p_hash(HASH_MD5,
	      key, len_2 + (keylen & 0x01),
	      label, labellen, 
	      random1, random1len,
	      random2, random2len,
	      buf, buflen);

  return dtls_p_hash(HASH_SHA1,
		     key + len_2, len_2 + (keylen & 0x01),
		     label, labellen, 
		     random1, random1len,
		     random2, random2len,
		     buf, buflen);
#elif DTLS_VERSION == 0xfefd
  /* Clear the result buffer */
  memset(buf, 0, buflen);
  return dtls_p_hash(HASH_SHA256, 
		     key, keylen, 
		     label, labellen, 
		     random1, random1len,
		     random2, random2len,
		     buf, buflen);
#endif
}

void
dtls_mac(dtls_hmac_context_t *hmac_ctx, 
	 const unsigned char *record,
	 const unsigned char *packet, size_t length,
	 unsigned char *buf) {
  uint16 L;
  dtls_int_to_uint16(L, length);

  assert(hmac_ctx);
  dtls_hmac_update(hmac_ctx, record +3, sizeof(uint16) + sizeof(uint48));
  dtls_hmac_update(hmac_ctx, record, sizeof(uint8) + sizeof(uint16));
  dtls_hmac_update(hmac_ctx, L, sizeof(uint16));
  dtls_hmac_update(hmac_ctx, packet, length);
  
  dtls_hmac_finalize(hmac_ctx, buf);
}

#ifdef TLS_PSK_WITH_AES_128_CBC_SHA
typedef struct {
  rijndael_ctx ctx;
  unsigned char pad[AES_BLKLEN];
} aes128_cbc_t;

void 
dtls_aes128_cbc_init(void *ctx, unsigned char *iv, size_t length) {
  aes128_cbc_t *c = (aes128_cbc_t *)ctx;

  if (length < AES_BLKLEN)
    memset(c->pad + length, 0, AES_BLKLEN - length);

  memcpy(c->pad, iv, AES_BLKLEN);
}

size_t
dtls_aes128_cbc_encrypt(void *ctx, 
			const unsigned char *src, size_t srclen,
			unsigned char *buf) {

  aes128_cbc_t *c = (aes128_cbc_t *)ctx;
  unsigned char *p;
  size_t i, j;

  assert(c);
  p = c->pad;

  /* write IV to result buffer */
  prng(buf, AES_BLKLEN);
  memxor(c->pad, buf, AES_BLKLEN);
  
  rijndael_encrypt(&c->ctx, c->pad, buf);

  for (i = AES_BLKLEN; i <= srclen; i += AES_BLKLEN) {
    for (j = 0; j < AES_BLKLEN; ++j)
      c->pad[j] = *src++ ^ *buf++;
    
    rijndael_encrypt(&c->ctx, c->pad, buf);
  }

  memcpy(c->pad, buf, AES_BLKLEN);
  memxor(c->pad, src, srclen & (AES_BLKLEN - 1));

  /* fill last block with padding bytes before encryption */
  for (j = srclen & (AES_BLKLEN - 1); j < AES_BLKLEN; ++j)
    c->pad[j] ^= ~srclen & (AES_BLKLEN - 1);

  rijndael_encrypt(&c->ctx, c->pad, buf + AES_BLKLEN);
  memcpy(c->pad, buf + AES_BLKLEN, AES_BLKLEN);

  return i + AES_BLKLEN;
}

static inline int
check_pattern(unsigned char *buf,
	      unsigned char pattern,
	      size_t count) {
  int ok = 1;
  while (count--)    /* check all bytes to minimize timing differences */
    ok = (*buf++ == pattern) & ok;

  return ok;
}


size_t
dtls_aes128_cbc_decrypt(void *ctx,
			const unsigned char *src, size_t srclen,
			unsigned char *buf) {

  aes128_cbc_t *c = (aes128_cbc_t *)ctx;
  size_t i, j;

  assert(c);

  /* The upper layer does not need the first block of the ciphertext
   * as it contains only the random IV. Therefore, we skip it during
   * decryption and save some buffer space. As a result, there must be
   * at least two entire ciphertext blocks.
   */

  if (srclen < 2 * AES_BLKLEN)
    return 0;		 /* ought to be safe as MAC check will fail */
 
  for (i = 0; i <= srclen - 2 * AES_BLKLEN; i += AES_BLKLEN) {
    rijndael_decrypt(&c->ctx, src + AES_BLKLEN, c->pad);
    for (j = 0; j < AES_BLKLEN; ++j)
      *buf++ = c->pad[j] ^ *src++;
  }
  memset(c->pad, 0, AES_BLKLEN); /* avoid data leakage */
  
  /* check padding */
  --buf;
  
  if (*buf < i && check_pattern(buf - *buf, *buf, *buf))
    return i - (*buf + 1);
  else
    return i;			/* MAC check should fail */
}
#endif /* TLS_PSK_WITH_AES_128_CBC_SHA */

void 
dtls_init_cipher(dtls_cipher_context_t *ctx,
		 unsigned char *iv, size_t length) {
  assert(ctx);
  ctx->init(ctx->data, iv, length);
}

dtls_cipher_context_t *
dtls_new_cipher(const dtls_cipher_t *cipher,
		unsigned char *key, size_t keylen) {
  dtls_cipher_context_t *cipher_context = NULL;

  switch (dtls_uint16_to_int(cipher->code)) {

#ifdef TLS_PSK_WITH_AES_128_CBC_SHA
  case 0x008c: /* AES128_CBC */ 

    /* Allocate memory for the dtls_cipher_context_t, the rijndael_ctx
     * and a pad to carry the previous ciphertext block as IV for the
     * next operation. */ 
    cipher_context = (dtls_cipher_context_t *)
      malloc(sizeof(dtls_cipher_context_t) + sizeof(aes128_cbc_t));

    if (cipher_context) {
      cipher_context->data = 
	(unsigned char *)cipher_context + sizeof(dtls_cipher_context_t);

      cipher_context->init = dtls_aes128_cbc_init;
      cipher_context->encrypt = dtls_aes128_cbc_encrypt;
      cipher_context->decrypt = dtls_aes128_cbc_decrypt;

      if (rijndael_set_key(&((aes128_cbc_t *)cipher_context->data)->ctx,
			   key, 8 * keylen) < 0) {
	/* cleanup everything in case the key has the wrong size */
	
	warn("cannot set rijndael key\n");
	free(cipher_context);
	cipher_context = NULL;
      }
    } 
    break;
#endif /* TLS_PSK_WITH_AES_128_CBC_SHA */

  default:
    warn("unknown cipher %04x\n", cipher->code);
  }

  return cipher_context;
}

