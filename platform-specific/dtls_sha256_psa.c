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
#include "psa/crypto.h"
#include <stdio.h>


void
dtls_hash_init(dtls_hash_ctx* context) {
  *context = psa_hash_operation_init();
  psa_hash_setup(context, PSA_ALG_SHA_256);
}

void
dtls_hash_update(dtls_hash_ctx* context, const uint8_t *data, size_t len) {
  psa_hash_update(context, data, len);
}

size_t
dtls_hash_finalize(uint8_t digest[DTLS_SHA256_DIGEST_LENGTH], dtls_hash_ctx* context) {
  size_t actual_size;
  psa_hash_finish(context, digest, PSA_HASH_LENGTH(PSA_ALG_SHA_256), &actual_size);
  return actual_size;
}
