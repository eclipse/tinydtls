/*******************************************************************************
 *
 * Copyright (c) 2022 Jan Romann and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 *******************************************************************************/

#include "tinydtls.h"
#include "dtls_prng.h"
#include "dtls_debug.h"

#include <stdlib.h>

#if defined(__MINGW32__)
/** Missing function declaration for rand_s under MingW. */
__declspec(dllimport) int __cdecl rand_s(unsigned int*);
#endif

/**
 * Fills @p buf with @p len random bytes. Returns a non-zero
 * value on error.
 */
int
dtls_prng(unsigned char *buf, size_t len) {
  errno_t err;
  unsigned int number;
  size_t klen = len;
  while (len--) {
    err = rand_s(&number);
    if (err != 0) {
      dtls_emerg("PRNG failed\n");
      return err;
    }
    *buf++ = number & 0xFF;
  }
  return klen;
}

void
dtls_prng_init(unsigned seed) {
  srand(seed);
}
