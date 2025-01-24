/*******************************************************************************
 *
 * Copyright (c) 2011-2019 Olaf Bergmann (TZI) and others.
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
 *    Lukas Luger    - adding psa crypto support
 *
 *******************************************************************************/

#include "tinydtls.h"
#include "dtls_prng.h"
#include "psa/crypto.h"

int
dtls_prng(unsigned char *buf, size_t len) {
  psa_generate_random(buf, len);
  return len;
}

void
dtls_prng_init(unsigned seed) {
  (void) seed;
}

