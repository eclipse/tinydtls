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

#include "numeric.h"
#include "dtls.h"
#include "crypto.h"

/** 
 * The list of acceptable cipher suites. Do not include the NULL
 * cipher here as it would enable a bid-down attack.
 */
dtls_cipher_t ciphers[] = {
  { TLS_PSK_WITH_AES_128_CBC_SHA, 16, 16, HASH_SHA1, 20, 20, 16 },
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
	 unsigned char *record,
	 unsigned char *packet, size_t length,
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

int
dtls_cbc_decrypt(dtls_security_parameters_t *sec,
		 unsigned char *record, size_t record_length,
		 unsigned char *result, size_t *result_length) {

  rijndael_ctx ctx;
  unsigned char *cipher;
  int i;

  if (rijndael_set_key(&ctx, dtls_kb_client_write_key(sec),
		       8 * dtls_kb_key_size(sec)) < 0) {
#ifndef NDEBUG
    fprintf(stderr, "cannot set key\n");
#endif
    return 0;
  }

  *result_length = dtls_uint16_to_int(((dtls_record_header_t *)record)->length);
  if (record_length < *result_length + sizeof(dtls_record_header_t)
      || *result_length < ciphers[sec->cipher].blk_length) {
#ifndef NDEBUG
    fprintf(stderr, "invalid length\n");    
#endif
    return 0;
  }

  *result_length -= ciphers[sec->cipher].blk_length;
  cipher = record + sizeof(dtls_record_header_t);

  /* is it ok to skip the IV block completely? do we need it for anything? */
  for (i = 0; i < *result_length; i += ciphers[sec->cipher].blk_length) {
    rijndael_decrypt(&ctx, cipher + ciphers[sec->cipher].blk_length, result);
    memxor(result, cipher, ciphers[sec->cipher].blk_length);

    cipher += ciphers[sec->cipher].blk_length;
    result += ciphers[sec->cipher].blk_length;
  }

  return 1;
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

int
dtls_verify(dtls_security_parameters_t *sec,
	    unsigned char *record, size_t record_length,
	    unsigned char *cleartext, size_t cleartext_length) {

  unsigned char *p, mac[DTLS_HMAC_MAX];
  dtls_hmac_context_t hmac_ctx;
  int ok = 0;

  dtls_hmac_init(&hmac_ctx, 
		 dtls_kb_client_mac_secret(sec),
		 dtls_kb_mac_secret_size(sec),
		 dtls_kb_mac_algorithm(sec));

  /* check padding */
  p = cleartext + cleartext_length - 1; /* point to last byte */
  
  if (*p + ciphers[sec->cipher].mac_length + 1 <= cleartext_length) {
    cleartext_length -= (*p + ciphers[sec->cipher].mac_length + 1);
    ok = 1;
  }
  ok = ok & check_pattern(p - *p, *p, *p);

  /* calculate MAC even if padding is wrong */
  dtls_mac(&hmac_ctx, 
	   record, 		/* the pre-filled record header */
	   cleartext, cleartext_length,
	   mac);

  ok = ok && (memcmp(mac, cleartext + cleartext_length, 
		     dtls_kb_digest_size(sec)) == 0);
#ifndef NDEBUG
  printf("MAC (%s):\n", ok ? "valid" : "invalid");
  dump(mac, dtls_kb_digest_size(sec));
  printf("\n");
#endif
  return ok;
}
		    
