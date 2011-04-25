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
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define DTLS_HMAC_BLOCKSIZE 64
#define DTLS_HMAC_MAX       64

/** L. Peter Deutsch's MD5 implementation, 
 *  see http://libmd5-rfc.sourceforge.net/ */
#ifdef WITH_MD5
#  include "md5/md5.h"
#endif

/** Aaron D. Gifford's implementation of SHA1 and SHA256
 *  see http://www.aarongifford.com/ */
#ifdef WITH_SHA1
#  include "sha1/sha.h"
#endif

#if defined(WITH_SHA256) || defined(WITH_SHA384) || defined(WITH_SHA512)
#  include "sha2/sha2.h"
#endif

#include "debug.h"

#include "hmac.h"

#ifdef WITH_MD5
void 
h_md5_init(void *ctx) {
  md5_init((md5_state_t *)ctx);
}

void 
h_md5_update(void *ctx, const unsigned char *input, size_t len) {
  md5_append((md5_state_t *)ctx, input, len);
}

size_t
h_md5_finalize(unsigned char *buf, void *ctx) {
  md5_finish((md5_state_t *)ctx, buf);
  return 16;			/* length of MD5 digest */
}
#endif

#ifdef WITH_SHA1
void 
h_sha_init(void *ctx) {
  SHA1_Init((SHA_CTX *)ctx);
}

void 
h_sha_update(void *ctx, const unsigned char *input, size_t len) {
  SHA1_Update((SHA_CTX *)ctx, (sha1_byte *)input, len);
}

size_t
h_sha_finalize(unsigned char *buf, void *ctx) {
  SHA1_Final(buf, (SHA_CTX *)ctx);
  return SHA1_DIGEST_LENGTH;
}
#endif

#ifdef WITH_SHA256
void 
h_sha256_init(void *ctx) {
  SHA256_Init((SHA256_CTX *)ctx);
}

void 
h_sha256_update(void *ctx, const unsigned char *input, size_t len) {
  SHA256_Update((SHA256_CTX *)ctx, input, len);
}

size_t
h_sha256_finalize(unsigned char *buf, void *ctx) {
  SHA256_Final(buf, (SHA256_CTX *)ctx);
  return SHA256_DIGEST_LENGTH;
}
#endif /* WITH_SHA1 */

void
dtls_hmac_update(dtls_hmac_context_t *ctx,
		 const unsigned char *input, size_t ilen) {
  assert(ctx);
  assert(ctx->H);

  ctx->H->update(ctx->H->data, input, ilen);
}

dtls_hash_t *
dtls_new_hash(dtls_hashfunc_t h) {
  dtls_hash_t *H = NULL;
  
  switch(h) {
#ifdef WITH_MD5
  case HASH_MD5:
    H = (dtls_hash_t *)malloc(sizeof(dtls_hash_t) + sizeof(md5_state_t));
    if (H) {
      H->data = ((char *)H) + sizeof(dtls_hash_t);
      H->init = h_md5_init;
      H->update = h_md5_update;
      H->finalize = h_md5_finalize;
    } 
    break;
#endif
#ifdef WITH_SHA1
  case HASH_SHA1:
    H = (dtls_hash_t *)malloc(sizeof(dtls_hash_t) + sizeof(SHA_CTX));
    if (H) {
      H->data = ((char *)H) + sizeof(dtls_hash_t);
      H->init = h_sha_init;
      H->update = h_sha_update;
      H->finalize = h_sha_finalize;
    } 
    break;
#endif
#ifdef WITH_SHA256
  case HASH_SHA256:
    H = (dtls_hash_t *)malloc(sizeof(dtls_hash_t) + sizeof(SHA256_CTX));
    if (H) {
      H->data = ((char *)H) + sizeof(dtls_hash_t);
      H->init = h_sha256_init;
      H->update = h_sha256_update;
      H->finalize = h_sha256_finalize;
    } 
    break;
#endif
  default:
    dsrv_log(LOG_CRIT, "unknown hash function %d\n", h);
  }
  
  if (!H)
    dsrv_log(LOG_CRIT, "cannot create hash function %d\n", h);

  return H;
}

int
dtls_hmac_init(dtls_hmac_context_t *ctx,
	       unsigned char *key, size_t klen,
	       dtls_hashfunc_t h) {
  int i;
  assert(ctx);

  ctx->H = dtls_new_hash(h);
  if (!ctx->H)
    return -1;

  memset(ctx->ipad, 0, DTLS_HMAC_BLOCKSIZE);

  if (klen > DTLS_HMAC_BLOCKSIZE) {
    ctx->H->init(ctx->H->data);
    ctx->H->update(ctx->H->data, key, klen);
    ctx->H->finalize(ctx->ipad, ctx->H->data);
  } else
    memcpy(ctx->ipad, key, klen);

  memcpy(ctx->opad, ctx->ipad, DTLS_HMAC_BLOCKSIZE);

  for (i=0; i < DTLS_HMAC_BLOCKSIZE; ++i) {
    ctx->ipad[i] ^= 0x36;
    ctx->opad[i] ^= 0x5C;
  }

  ctx->H->init(ctx->H->data);
  dtls_hmac_update(ctx, ctx->ipad, DTLS_HMAC_BLOCKSIZE);
  return 1;
}

int
dtls_hmac_finalize(dtls_hmac_context_t *ctx, unsigned char *result) {
  unsigned char buf[DTLS_HMAC_MAX];
  size_t len; 

  assert(ctx);
  assert(result);
  
  memset(result, 0, DTLS_HMAC_MAX);

  len = ctx->H->finalize(buf, ctx->H->data);

  ctx->H->init(ctx->H->data);
  ctx->H->update(ctx->H->data, ctx->opad, DTLS_HMAC_BLOCKSIZE);
  ctx->H->update(ctx->H->data, buf, len);

  len = ctx->H->finalize(result, ctx->H->data);

  free(ctx->H);
  return len;
}

#ifdef WITH_OPENSSL
#define DIGEST EVP_md5()

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

void
reference(unsigned char *secret, int keylen, 
	  unsigned char *text, int textlen) {
#ifdef WITH_OPENSSL
  HMAC_CTX hmac_context;

  static unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned int len, i;

  OpenSSL_add_all_digests();

  HMAC_Init(&hmac_context, secret, keylen, DIGEST);
  HMAC_Update(&hmac_context, text, textlen);

  HMAC_Final(&hmac_context, buf, &len);

  for(i = 0; i < len; i++) 
    printf("%02x", buf[i]);
  printf("\n");
#else
  fprintf(stderr,"Error: no OpenSSL\n");
#endif
}

#ifdef HMAC_TEST
int main(int argc, char **argv) {
  static unsigned char key[] = { 0x0b, 0x0b, 0x0b, 0x0b, 
				 0x0b, 0x0b, 0x0b, 0x0b, 
				 0x0b, 0x0b, 0x0b, 0x0b, 
				 0x0b, 0x0b, 0x0b, 0x0b };
  static unsigned char text[] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };
  static unsigned char buf[DTLS_HMAC_MAX];
  size_t len, i;
  dtls_hmac_context_t hmac_ctx;

  dtls_hmac_init(&hmac_ctx, key, sizeof(key), HASH_MD5);
  dtls_hmac_update(&hmac_ctx, text, sizeof(text));
  
  len = dtls_hmac_finalize(&hmac_ctx, buf);

  for(i = 0; i < len; i++) 
    printf("%02x", buf[i]);
  printf("\n");

  reference(key, sizeof(key), text, sizeof(text));

  return 0;
}
#endif
