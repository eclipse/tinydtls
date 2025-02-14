/*******************************************************************************
 *
 * Copyright (c) 2011-2025 Lukas Luger (TUD) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Lukas Luger    - adding psa crypto support
 *
 *******************************************************************************/

#ifdef WITH_SHA256
#ifndef _DTLS_HASH_H_
#define _DTLS_HASH_H_

#include "tinydtls.h"
#include <stdio.h>

#define DTLS_SHA256_DIGEST_LENGTH 32
#define DTLS_SHA256_BLOCK_LENGTH  64
// using psa
#ifdef USE_PSA

#include "psa/crypto.h"
#define DTLS_HASH_CTX_SIZE sizeof(psa_hash_operation_t)
typedef psa_hash_operation_t dtls_hash_ctx;


// using esp and libsodium
#elif defined ESP_PLATFORM && defined CONFIG_LIBSODIUM_USE_MBEDTLS_SHA

#include "sodium/crypto_hash_sha256.h"
#define DTLS_HASH_CTX_SIZE sizeof(crypto_hash_sha256_state)
typedef crypto_hash_sha256_state dtls_hash_ctx;

// using provided software hashing
#else /* ! RIOT_VERSION && ! ESP_PLATFORM */

/** Aaron D. Gifford's implementation of SHA256
 *  see http://www.aarongifford.com/ */
#include "sha2/sha2.h"

typedef dtls_sha256_ctx dtls_hash_ctx;

#define DTLS_HASH_CTX_SIZE sizeof(dtls_sha256_ctx)

typedef dtls_hash_ctx *dtls_hash_t;

static inline void
dtls_hash_init(dtls_hash_t ctx) {
  dtls_sha256_init((dtls_sha256_ctx *)ctx);
}

static inline void 
dtls_hash_update(dtls_hash_t ctx, const unsigned char *input, size_t len) {
  dtls_sha256_update((dtls_sha256_ctx *)ctx, input, len);
}

static inline size_t
dtls_hash_finalize(uint8_t digest[DTLS_SHA256_DIGEST_LENGTH], dtls_hash_t ctx) {
  dtls_sha256_final(digest, (dtls_sha256_ctx *)ctx);
  return DTLS_SHA256_DIGEST_LENGTH;
}

#endif /* ! RIOT_VERSION && ! ESP_PLATFORM */

void dtls_hash_init(dtls_hash_ctx* ctx);
void dtls_hash_update(dtls_hash_ctx* ctx, const unsigned char *input, size_t len);
size_t dtls_hash_finalize(uint8_t digest[DTLS_SHA256_DIGEST_LENGTH], dtls_hash_ctx* ctx);

#endif
#endif
