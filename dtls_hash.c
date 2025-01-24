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

#include "dtls_hash.h"

#include "tinydtls.h"

// using psa
#ifdef USE_PSA

#include "platform-specific/dtls_sha256_psa.c"

// using esp and libsodium
#elif defined ESP_PLATFORM && defined CONFIG_LIBSODIUM_USE_MBEDTLS_SHA

#include "platform-specific/dtls_sha256_sodium.c"


#endif /* ! RIOT_VERSION && ! ESP_PLATFORM */

#endif
