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

#ifndef _DTLS_CIPHERS_UTIL_H_
#define _DTLS_CIPHERS_UTIL_H_

#include <stdio.h>

#include "global.h"

const dtls_cipher_t* init_cipher_suites(const char* arg);

void cipher_suites_usage(FILE* file, const char* head);

#endif /* _DTLS_CIPHERS_UTIL_H_ */
