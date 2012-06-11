/* alert.h -- DTLS alert protocol
 *
 * Copyright (C) 2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file alert.h
 * @brief DTLS alert protocol
 */

#ifndef _ALERT_H_
#define _ALERT_H_

#include "config.h"

typedef enum {
  DTLS_ALERT_LEVEL_WARNING=1,
  DTLS_ALERT_LEVEL_FATAL=2
} dtls_alert_level_t;

typedef enum {
  DTLS_ALERT_CLOSE=0,
  DTLS_ALERT_UNEXPECTED_MESSAGE=10,
  DTLS_ALERT_BAD_RECORD_MAC=20,
  DTLS_ALERT_RECORD_OVERFLOW=22,
  DTLS_ALERT_DECOMPRESSION_FAILURE=30,
  DTLS_ALERT_HANDSHAKE_FAILURE=40,
  DTLS_ALERT_ILLEGAL_PARAMETER=47,
  DTLS_ALERT_ACCESS_DENIED=49,
  DTLS_ALERT_DECODE_ERROR=50,
  DTLS_ALERT_DECRYPT_ERROR=51,
  DTLS_ALERT_PROTOCOL_VERSION=70,
  DTLS_ALERT_INSUFFICIENT_SECURITY=70,
  DTLS_ALERT_INTERNAL_ERROR=80,
  DTLS_ALERT_USER_CANCELED=90,
  DTLS_ALERT_NO_RENEGOTIATION=100,
  DTLS_ALERT_UNSUPPORTED_EXTENSION=110
} dtls_alert_t;

#define DTLS_EVENT_CONNECTED      0x01DE

#endif /* _ALERT_H_ */
