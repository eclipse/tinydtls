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

#include <sys/types.h>
#include "tinydtls.h"
#include "global.h"
#include "psa/crypto.h"
#include "hmac.h"
#include <stdio.h>

void
dtls_hmac_init(dtls_hmac_context_t *ctx, const unsigned char *key, size_t klen) {
  *ctx = psa_mac_operation_init();

  psa_key_attributes_t attr = psa_key_attributes_init();
  psa_key_id_t key_id = 0;

  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);

  psa_set_key_lifetime(&attr, PSA_KEY_PERSISTENCE_VOLATILE);

  psa_algorithm_t algo = PSA_ALG_HMAC(PSA_ALG_SHA_256);
  psa_set_key_algorithm(&attr, algo);

  psa_key_type_t type = PSA_KEY_TYPE_HMAC;
  psa_set_key_type(&attr, type);

  uint8_t size = klen > PSA_HASH_LENGTH(algo) ? PSA_HASH_LENGTH(algo)  : klen;
  psa_set_key_bits(&attr, size * 8);

  psa_import_key(&attr, key, klen, &key_id);

  if(key_id == PSA_KEY_ID_NULL){
      return;
  }
  
  psa_mac_sign_setup(ctx, key_id, algo);

  psa_destroy_key(key_id);
}

void
dtls_hmac_update(dtls_hmac_context_t *ctx, 
    const unsigned char *input, size_t ilen) {
  assert(ctx);
  
  psa_mac_update(ctx, input, ilen);
}

int
dtls_hmac_finalize(dtls_hmac_context_t *ctx, unsigned char *result) {
  size_t actual_size;

  psa_mac_sign_finish(ctx, result, PSA_MAC_MAX_SIZE, &actual_size);

  return actual_size;
}
