/*******************************************************************************
 *
 * Copyright (c) 2011-2020 Olaf Bergmann (TZI) and others.
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
 *    Achim Kraus    - session recovery
 *    Sachin Agrawal - rehandshake support
 *    Jon Shallow    - platform dependent prng support
 *
 *******************************************************************************/

#ifdef HAVE_RANDOM
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */
#endif /* HAVE_RANDOM */

#include "tinydtls.h"
#include "dtls_prng.h"
#include "dtls_debug.h"

#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif /* HAVE_GETRANDOM */
#include <stdlib.h>
#include <stdio.h>

/**
 * Fills @p buf with @p len random bytes. This is the default
 * implementation for prng().  You might want to change prng() to use
 * a better PRNG on your specific platform.
 */
int
dtls_prng(unsigned char *buf, size_t len) {
#ifdef HAVE_GETRANDOM
  return getrandom(buf, len, 0);
#elif defined(HAVE_RANDOM)

#define RAND_BYTES (RAND_MAX >= 0xffffff ? 3 : (RAND_MAX >= 0xffff ? 2 : 1))

  if (len) {
    size_t klen = len;
    uint8_t byte_counter = RAND_BYTES;
    uint32_t rand_val = random();
    while (1) {
      *buf++ = rand_val & 0xFF;
      if (!--klen) {
        break;
      }
      if (--byte_counter) {
        rand_val >>= 8;
      } else {
        rand_val = random();
        byte_counter = RAND_BYTES;
      }
    }
  }
  return len;
#else /*!HAVE_GETRANDOM && !HAVE_RANDOM */
  #error "CVE-2021-34430: using rand() for crypto randoms is not secure!"
  #error "Please update you C-library and rerun the auto-configuration."
  size_t klen = len;
  while (len--)
    *buf++ = rand() & 0xFF;
  return klen;
#endif /* !HAVE_GETRANDOM */
}

void
dtls_prng_init(unsigned seed) {
#ifdef HAVE_GETRANDOM
  /* No seed to seed the random source if getrandom() is used,
   * see dtls_prng(). */
  (void)seed;
#else /* !HAVE_GETRANDOM */
  FILE *urandom = fopen("/dev/urandom", "r");
  unsigned char buf[sizeof(unsigned long)];
  (void)seed;

  if (!urandom) {
    dtls_emerg("cannot initialize PRNG\n");
    return;
  }

  if (fread(buf, 1, sizeof(buf), urandom) != sizeof(buf)) {
    dtls_emerg("cannot initialize PRNG\n");
    return;
  }

  fclose(urandom);
#ifdef HAVE_RANDOM
  srandom((unsigned long)*buf);
#else
  srand((unsigned long)*buf);
#endif
#endif /* !HAVE_GETRANDOM */
}

