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

#include "tinydtls.h"

#include "dtls_hash.h"
#include "sodium/crypto_hash_sha256.h"


void
dtls_hash_init(dtls_hash_ctx* context) {
  crypto_hash_sha256_init(ctx);
}

void
dtls_hash_update(dtls_hash_ctx* context, const uint8_t *data, size_t len) {
  crypto_hash_sha256_update(context, data, len);
}

size_t
dtls_hash_finalize(uint8_t digest[DTLS_SHA256_DIGEST_LENGTH], dtls_hash_ctx* context) {
  crypto_hash_sha256_final(context, digest);
  return DTLS_SHA256_DIGEST_LENGTH;
}
