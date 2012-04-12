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

#ifndef _HMAC_H_
#define _HMAC_H_

#include <sys/types.h>

#include "global.h"

/**
 * \defgroup HMAC Keyed-Hash Message Authentication Code (HMAC)
 * NIST Standard FIPS 198 describes the Keyed-Hash Message Authentication 
 * Code (HMAC) which is used as hash function for the DTLS PRF.
 * @{
 */

#define DTLS_HMAC_BLOCKSIZE   64	/**< size of hmac blocks */
#define DTLS_HMAC_DIGEST_SIZE 32	/**< digest size (for SHA-256) */
#define DTLS_HMAC_MAX         64	/**< max number of bytes in digest */

/**
 * List of known hash functions for use in dtls_hmac_init(). The
 * identifiers are the same as the HashAlgorithm defined in 
 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1"
 * >Section 7.4.1.4.1 of RFC 5246</a>.
 */
typedef enum { 
  HASH_NONE=0, HASH_MD5=1, HASH_SHA1=2, HASH_SHA224=3,
  HASH_SHA256=4, HASH_SHA384=5, HASH_SHA512=6
} dtls_hashfunc_t;

/**
 * Context for HMAC generation. This object is initialized with
 * dtls_hmac_init() and must be passed to dtls_hmac_update() and
 * dtls_hmac_finalize(). Once, finalized, the component \c H is
 * invalid and must be initialized again with dtls_hmac_init() before
 * the structure can be used again. 
 */
typedef struct {
  unsigned char pad[DTLS_HMAC_BLOCKSIZE]; /**< ipad and opad storage */
  unsigned char data[];	                  /**< context for hash function */
} dtls_hmac_context_t;

/**
 * Allocates a new HMAC context \p ctx with the given secret key.
 * This function returns \c 1 if \c ctx has been set correctly, or \c
 * 0 or \c -1 otherwise. Note that this function allocates new storage
 * that must be released by dtls_hmac_free().
 *
 * \param key    The secret key.
 * \param klen   The length of \p key.
 * \return A new dtls_hmac_context_t object or @c NULL on error
 */
dtls_hmac_context_t *dtls_hmac_new(unsigned char *key, size_t klen);

/**
 * Releases the storage for @p ctx that has been allocated by
 * dtls_hmac_new().
 *
 * @param ctx The dtls_hmac_context_t to free. 
 */
void dtls_hmac_free(dtls_hmac_context_t *ctx);

/**
 * Updates the HMAC context with data from \p input. 
 * 
 * \param ctx    The HMAC context.
 * \param input  The input data.
 * \param ilen   Size of \p input.
 */
void dtls_hmac_update(dtls_hmac_context_t *ctx,
		      const unsigned char *input, size_t ilen);

/** 
 * Completes the HMAC generation and writes the result to the given
 * output parameter \c result. The buffer must be large enough to hold
 * the message digest created by the actual hash function. If in
 * doubt, use \c DTLS_HMAC_MAX. The function returns the number of
 * bytes written to \c result. 
 *
 * \param ctx    The HMAC context.
 * \param result Output parameter where the MAC is written to.
 * \return Length of the MAC written to \p result.
 */
int dtls_hmac_finalize(dtls_hmac_context_t *ctx, unsigned char *result);

/**@}*/

#endif /* _HMAC_H_ */
