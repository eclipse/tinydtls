/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011--2013 Olaf Bergmann <bergmann@tzi.org>
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
 * @file state.h
 * @brief state information for DTLS FSM
 */

#ifndef _STATE_H_
#define _STATE_H_

#include "config.h"
#include "global.h"
#include "hmac.h"

typedef enum { 
  DTLS_STATE_INIT = 0, DTLS_STATE_SERVERHELLO, DTLS_STATE_KEYEXCHANGE, 
  DTLS_STATE_WAIT_FINISHED, DTLS_STATE_FINISHED, 
  /* client states */
  DTLS_STATE_CLIENTHELLO, DTLS_STATE_WAIT_SERVERHELLODONE,
  DTLS_STATE_WAIT_SERVERFINISHED, 

  DTLS_STATE_CONNECTED,
  DTLS_STATE_CLOSING,
  DTLS_STATE_CLOSED,
} dtls_state_t;

typedef struct {
  uint24 mseq;		     /**< handshake message sequence number counter */

  /** pending config that is updated during handshake */
  /* FIXME: dtls_security_parameters_t pending_config; */

  /* temporary storage for the final handshake hash */
  dtls_hash_ctx hs_hash;
} dtls_hs_state_t;

#endif /* _STATE_H_ */
