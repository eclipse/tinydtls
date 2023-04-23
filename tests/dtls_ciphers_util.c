/*******************************************************************************
 *
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 *******************************************************************************/

#include <string.h>
#include <math.h>

#include "dtls_ciphers_util.h"


struct cipher_entry {
	const char* name;
	const dtls_cipher_t cipher;
};

#define CIPHER_ENTRY(X) { .name = #X, .cipher = X }
#define ARRAY_LENGTH (sizeof(map)/sizeof(struct cipher_entry))
#define SEP ':'

static const struct cipher_entry map[] = {
#ifdef DTLS_PSK
  CIPHER_ENTRY(TLS_PSK_WITH_AES_128_CCM),
  CIPHER_ENTRY(TLS_PSK_WITH_AES_128_CCM_8),
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  CIPHER_ENTRY(TLS_ECDHE_ECDSA_WITH_AES_128_CCM),
  CIPHER_ENTRY(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
#endif /* DTLS_ECC */
  { .name = NULL, .cipher = TLS_NULL_WITH_NULL_NULL}
};

static dtls_cipher_t ciphers_table[ARRAY_LENGTH] = { TLS_NULL_WITH_NULL_NULL };

static dtls_cipher_t find_cipher_suite(const char *arg) {
  if (arg) {
    size_t arg_len = strlen(arg);
    for (size_t i=0; i < ARRAY_LENGTH - 1; ++i) {
      size_t len = strlen(map[i].name);
      if (len <= arg_len) {
        if (strncmp(arg, map[i].name, len) == 0 && (arg[len] == 0 || arg[len] == SEP)) {
          return map[i].cipher;
        }
      }
    }
  }
  return TLS_NULL_WITH_NULL_NULL;
}

static void add_cipher_suite(dtls_cipher_t cipher) {
  for (size_t i=0; i < ARRAY_LENGTH - 1; ++i) {
    if (ciphers_table[i] == cipher) {
      return;
    }
    if (ciphers_table[i] == TLS_NULL_WITH_NULL_NULL) {
      ciphers_table[i] = cipher;
      ciphers_table[i + 1] = TLS_NULL_WITH_NULL_NULL;
      return;
    }
  }
}

const dtls_cipher_t*
init_cipher_suites(const char* arg) {
  while (arg) {
    dtls_cipher_t cipher = find_cipher_suite(arg);
    if (cipher != TLS_NULL_WITH_NULL_NULL) {
      add_cipher_suite(cipher);
    }
    arg = strchr(arg, SEP);
    if (arg) {
      ++arg;
    }
  }
  return ciphers_table;
}

void
cipher_suites_usage(FILE* file, const char* head) {
  fprintf(file, "%s-c ciphers\tlist of cipher suites separated by ':'\n", head);
  fprintf(file, "%s\t\t(default is %s", head, map[0].name);
  for (int i = 1; map[i].name; ++i) {
     fprintf(file, "\n%s\t\t :%s", head, map[i].name);
  }
  fprintf(file, ")\n");
}

