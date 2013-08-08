/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011--2012 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2013 Hauke Mehrtens <hauke@hauke-m.de>
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
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

#include "global.h"
#include "debug.h"
#include "numeric.h"
#include "dtls.h"
#include "crypto.h"
#include "ccm.h"
#include "ecc/ecc.h"

#ifndef WITH_CONTIKI
#include <stdlib.h>

static inline dtls_cipher_context_t *
dtls_cipher_context_new() {
  return (dtls_cipher_context_t *)malloc(sizeof(dtls_cipher_context_t));
}

static inline void
dtls_cipher_context_free(dtls_cipher_context_t *ctx) {
  free(ctx);
}
#else /* WITH_CONTIKI */
MEMB(cipher_storage, dtls_cipher_context_t, DTLS_CIPHER_CONTEXT_MAX);

static inline dtls_cipher_context_t *
dtls_cipher_context_new() {
  return (dtls_cipher_context_t *)memb_alloc(&cipher_storage);
}

static inline void
dtls_cipher_context_free(dtls_cipher_context_t *ctx) {
  if (ctx)
    memb_free(&cipher_storage, ctx);
}
#endif /* WITH_CONTIKI */

void crypto_init() {
  dtls_hmac_storage_init();

#ifdef WITH_CONTIKI
  memb_init(&cipher_storage);
#endif /* WITH_CONTIKI */
}

#define HMAC_UPDATE_SEED(Context,Seed,Length)		\
  if (Seed) dtls_hmac_update(Context, (Seed), (Length))

size_t
dtls_p_hash(dtls_hashfunc_t h,
	    const unsigned char *key, size_t keylen,
	    const unsigned char *label, size_t labellen,
	    const unsigned char *random1, size_t random1len,
	    const unsigned char *random2, size_t random2len,
	    unsigned char *buf, size_t buflen) {
  dtls_hmac_context_t *hmac_a, *hmac_p;

  unsigned char A[DTLS_HMAC_DIGEST_SIZE];
  unsigned char tmp[DTLS_HMAC_DIGEST_SIZE];
  size_t dlen;			/* digest length */
  size_t len = 0;			/* result length */

  hmac_a = dtls_hmac_new(key, keylen);
  if (!hmac_a)
    return 0;

  /* calculate A(1) from A(0) == seed */
  HMAC_UPDATE_SEED(hmac_a, label, labellen);
  HMAC_UPDATE_SEED(hmac_a, random1, random1len);
  HMAC_UPDATE_SEED(hmac_a, random2, random2len);

  dlen = dtls_hmac_finalize(hmac_a, A);

  hmac_p = dtls_hmac_new(key, keylen);
  if (!hmac_p)
    goto error;

  while (len + dlen < buflen) {

    /* FIXME: rewrite loop to avoid superflous call to dtls_hmac_init() */
    dtls_hmac_init(hmac_p, key, keylen);
    dtls_hmac_update(hmac_p, A, dlen);

    HMAC_UPDATE_SEED(hmac_p, label, labellen);
    HMAC_UPDATE_SEED(hmac_p, random1, random1len);
    HMAC_UPDATE_SEED(hmac_p, random2, random2len);

    len += dtls_hmac_finalize(hmac_p, tmp);
    memcpy(buf, tmp, dlen);
    buf += dlen;

    /* calculate A(i+1) */
    dtls_hmac_init(hmac_a, key, keylen);
    dtls_hmac_update(hmac_a, A, dlen);
    dtls_hmac_finalize(hmac_a, A);
  }

  dtls_hmac_init(hmac_p, key, keylen);
  dtls_hmac_update(hmac_p, A, dlen);
  
  HMAC_UPDATE_SEED(hmac_p, label, labellen);
  HMAC_UPDATE_SEED(hmac_p, random1, random1len);
  HMAC_UPDATE_SEED(hmac_p, random2, random2len);
  
  dtls_hmac_finalize(hmac_p, tmp);
  memcpy(buf, tmp, buflen - len);

 error:
  dtls_hmac_free(hmac_a);
  dtls_hmac_free(hmac_p);

  return buflen;
}

size_t 
dtls_prf(const unsigned char *key, size_t keylen,
	 const unsigned char *label, size_t labellen,
	 const unsigned char *random1, size_t random1len,
	 const unsigned char *random2, size_t random2len,
	 unsigned char *buf, size_t buflen) {

  /* Clear the result buffer */
  memset(buf, 0, buflen);
  return dtls_p_hash(HASH_SHA256, 
		     key, keylen, 
		     label, labellen, 
		     random1, random1len,
		     random2, random2len,
		     buf, buflen);
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

static size_t
dtls_ccm_encrypt(aes128_ccm_t *ccm_ctx, const unsigned char *src, size_t srclen,
		 unsigned char *buf, 
		 unsigned char *nounce,
		 const unsigned char *aad, size_t la) {
  long int len;

  assert(ccm_ctx);

  len = dtls_ccm_encrypt_message(&ccm_ctx->ctx, 8 /* M */, 
				 max(2, 15 - DTLS_CCM_NONCE_SIZE),
				 nounce,
				 buf, srclen, 
				 aad, la);
  return len;
}

static size_t
dtls_ccm_decrypt(aes128_ccm_t *ccm_ctx, const unsigned char *src,
		 size_t srclen, unsigned char *buf,
		 unsigned char *nounce,
		 const unsigned char *aad, size_t la) {
  long int len;

  assert(ccm_ctx);

  len = dtls_ccm_decrypt_message(&ccm_ctx->ctx, 8 /* M */, 
				 max(2, 15 - DTLS_CCM_NONCE_SIZE),
				 nounce,
				 buf, srclen, 
				 aad, la);
  return len;
}

size_t
dtls_psk_pre_master_secret(unsigned char *key, size_t keylen,
			   unsigned char *result) {
  unsigned char *p = result;

  dtls_int_to_uint16(p, keylen);
  p += sizeof(uint16);

  memset(p, 0, keylen);
  p += keylen;

  memcpy(p, result, sizeof(uint16));
  p += sizeof(uint16);
  
  memcpy(p, key, keylen);

  return (sizeof(uint16) + keylen) << 1;
}

static void dtls_ec_key_to_uint32(const unsigned char *key, size_t key_size,
				  uint32_t *result) {
  int i;

  for (i = (key_size / sizeof(uint32_t)) - 1; i >= 0 ; i--) {
    *result = dtls_uint32_to_int(&key[i * sizeof(uint32_t)]);
    result++;
  }
}

static void dtls_ec_key_from_uint32(const uint32_t *key, size_t key_size,
				    unsigned char *result) {
  int i;

  for (i = (key_size / sizeof(uint32_t)) - 1; i >= 0 ; i--) {
    dtls_int_to_uint32(result, key[i]);
    result += 4;
  }
}

int dtls_ec_key_from_uint32_asn1(const uint32_t *key, size_t key_size,
				 unsigned char *buf) {
  int i;
  unsigned char *buf_orig = buf;
  int first = 1; 

  for (i = (key_size / sizeof(uint32_t)) - 1; i >= 0 ; i--) {
    if (key[i] == 0)
      continue;
    /* the first bit has to be set to zero, to indicate a poritive integer */
    if (first && key[i] & 0x80000000) {
      *buf = 0;
      buf++;
      dtls_int_to_uint32(buf, key[i]);
      buf += 4;      
    } else if (first && !(key[i] & 0xFF800000)) {
      buf[0] = (key[i] >> 16) & 0xff;
      buf[1] = (key[i] >> 8) & 0xff;
      buf[2] = key[i] & 0xff;
      buf += 3;
    } else if (first && !(key[i] & 0xFFFF8000)) {
      buf[0] = (key[i] >> 8) & 0xff;
      buf[1] = key[i] & 0xff;
      buf += 2;
    } else if (first && !(key[i] & 0xFFFFFF80)) {
      buf[0] = key[i] & 0xff;
      buf += 1;
    } else {
      dtls_int_to_uint32(buf, key[i]);
      buf += 4;
    }
    first = 0;
  }
  return buf - buf_orig;
}

size_t dtls_ecdh_pre_master_secret(unsigned char *priv_key,
				   unsigned char *pub_key_x,
                                   unsigned char *pub_key_y,
                                   size_t key_size,
                                   unsigned char *result) {
  uint32_t priv[8];
  uint32_t pub_x[8];
  uint32_t pub_y[8];
  uint32_t result_x[8];
  uint32_t result_y[8];

  dtls_ec_key_to_uint32(priv_key, key_size, priv);
  dtls_ec_key_to_uint32(pub_key_x, key_size, pub_x);
  dtls_ec_key_to_uint32(pub_key_y, key_size, pub_y);

  ecc_ecdh(pub_x, pub_y, priv, result_x, result_y);

  dtls_ec_key_from_uint32(result_x, key_size, result);
  return key_size;
}

void
dtls_ecdsa_generate_key(unsigned char *priv_key,
			unsigned char *pub_key_x,
			unsigned char *pub_key_y,
			size_t key_size) {
  uint32_t priv[8];
  uint32_t pub_x[8];
  uint32_t pub_y[8];

  do {
    prng((unsigned char *)priv, key_size);
  } while (!ecc_is_valid_key(priv));

  ecc_gen_pub_key(priv, pub_x, pub_y);

  dtls_ec_key_from_uint32(priv, key_size, priv_key);
  dtls_ec_key_from_uint32(pub_x, key_size, pub_key_x);
  dtls_ec_key_from_uint32(pub_y, key_size, pub_key_y);
}

/* rfc4492#section-5.4 */
void
dtls_ecdsa_create_sig_hash(const unsigned char *priv_key, size_t key_size,
			   const unsigned char *sign_hash, size_t sign_hash_size,
			   uint32_t point_r[9], uint32_t point_s[9]) {
  int ret;
  uint32_t priv[8];
  uint32_t hash[8];
  uint32_t rand[8];
  
  dtls_ec_key_to_uint32(priv_key, key_size, priv);
  dtls_ec_key_to_uint32(sign_hash, sign_hash_size, hash);
  do {
    prng((unsigned char *)rand, key_size);
    ret = ecc_ecdsa_sign(priv, hash, rand, point_r, point_s);
  } while (ret);
}

void
dtls_ecdsa_create_sig(const unsigned char *priv_key, size_t key_size,
		      const unsigned char *client_random, size_t client_random_size,
		      const unsigned char *server_random, size_t server_random_size,
		      const unsigned char *keyx_params, size_t keyx_params_size,
		      uint32_t point_r[9], uint32_t point_s[9]) {
  dtls_hash_ctx data;
  unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];

  dtls_hash_init(&data);
  dtls_hash_update(&data, client_random, client_random_size);
  dtls_hash_update(&data, server_random, server_random_size);
  dtls_hash_update(&data, keyx_params, keyx_params_size);
  dtls_hash_finalize(sha256hash, &data);
  
  dtls_ecdsa_create_sig_hash(priv_key, key_size, sha256hash,
			     sizeof(sha256hash), point_r, point_s);
}

/* rfc4492#section-5.4 */
int
dtls_ecdsa_verify_sig_hash(const unsigned char *pub_key_x,
			   const unsigned char *pub_key_y, size_t key_size,
			   const unsigned char *sign_hash, size_t sign_hash_size,
			   unsigned char *result_r, unsigned char *result_s) {
  uint32_t pub_x[8];
  uint32_t pub_y[8];
  uint32_t hash[8];
  uint32_t point_r[8];
  uint32_t point_s[8];

  dtls_ec_key_to_uint32(pub_key_x, key_size, pub_x);
  dtls_ec_key_to_uint32(pub_key_y, key_size, pub_y);
  dtls_ec_key_to_uint32(result_r, key_size, point_r);
  dtls_ec_key_to_uint32(result_s, key_size, point_s);
  dtls_ec_key_to_uint32(sign_hash, sign_hash_size, hash);

  return ecc_ecdsa_validate(pub_x, pub_y, hash, point_r, point_s);
}

int
dtls_ecdsa_verify_sig(const unsigned char *pub_key_x,
		      const unsigned char *pub_key_y, size_t key_size,
		      const unsigned char *client_random, size_t client_random_size,
		      const unsigned char *server_random, size_t server_random_size,
		      const unsigned char *keyx_params, size_t keyx_params_size,
		      unsigned char *result_r, unsigned char *result_s) {
  dtls_hash_ctx data;
  unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];
  
  dtls_hash_init(&data);
  dtls_hash_update(&data, client_random, client_random_size);
  dtls_hash_update(&data, server_random, server_random_size);
  dtls_hash_update(&data, keyx_params, keyx_params_size);
  dtls_hash_finalize(sha256hash, &data);

  return dtls_ecdsa_verify_sig_hash(pub_key_x, pub_key_y, key_size, sha256hash,
				    sizeof(sha256hash), result_r, result_s);
}

dtls_cipher_context_t *
dtls_cipher_new(dtls_cipher_t cipher,
		unsigned char *key, size_t keylen) {
  dtls_cipher_context_t *cipher_context = NULL;

  cipher_context = dtls_cipher_context_new();
  if (!cipher_context) {
    warn("cannot allocate cipher_context\r\n");
    return NULL;
  }

  switch (cipher) {
  case TLS_PSK_WITH_AES_128_CCM_8:
  case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: {
    aes128_ccm_t *ccm_ctx = &cipher_context->data;
    
    if (rijndael_set_key_enc_only(&ccm_ctx->ctx, key, 8 * keylen) < 0) {
      /* cleanup everything in case the key has the wrong size */
      warn("cannot set rijndael key\n");
      goto error;
    }
    break;
  }
  default:
    warn("unknown cipher %04x\n", cipher);
    goto error;
  }
  
  return cipher_context;
 error:
  dtls_cipher_context_free(cipher_context);
  return NULL;
}

void 
dtls_cipher_free(dtls_cipher_context_t *cipher_context) {
  dtls_cipher_context_free(cipher_context);
}

int 
dtls_encrypt(dtls_cipher_context_t *ctx, 
	     const unsigned char *src, size_t length,
	     unsigned char *buf,
	     unsigned char *nounce,
	     const unsigned char *aad, size_t la) {
  if (ctx) {
    if (src != buf)
      memmove(buf, src, length);
    return dtls_ccm_encrypt(&ctx->data, src, length, buf, nounce,
			    aad, la);
  }

  return -1;
}

int 
dtls_decrypt(dtls_cipher_context_t *ctx, 
	     const unsigned char *src, size_t length,
	     unsigned char *buf,
	     unsigned char *nounce,
	     const unsigned char *aad, size_t la) {
  if (ctx) {
    if (src != buf)
      memmove(buf, src, length);
    return dtls_ccm_decrypt(&ctx->data, src, length, buf, nounce,
			    aad, la);
  }

  return -1;
}

