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

#ifndef _DTLS_HMAC_H_
#define _DTLS_HMAC_H_

#include <sys/types.h>

#include "tinydtls.h"
#include "global.h"
#include "dtls_hash.h"


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
  dtls_hash_ctx data;		          /**< context for hash function */
} dtls_hmac_context_t;

/**
 * Initializes an existing HMAC context. 
 *
 * @param ctx The HMAC context to initialize.
 * @param key    The secret key.
 * @param klen   The length of @p key.
 */
void dtls_hmac_init(dtls_hmac_context_t *ctx, const unsigned char *key, size_t klen);

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

#endif /* _DTLS_HMAC_H_ */
