/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011 Olaf Bergmann <bergmann@tzi.org>
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

#ifndef _DTLS_H_
#define _DTLS_H_

#include <stdint.h>

#include "uthash.h"
#include "peer.h"
#include "crypto.h"

#define DTLS_VERSION 0xfeff	/* 0xfefd for DTLS 1.2 */

/** Known compression methods
 *
 * \hideinitializer
 */
#define TLS_COMP_NULL      0x00	/* NULL compression */
 
typedef enum { 
  DTLS_STATE_INIT = 0, DTLS_STATE_SERVERHELLO, DTLS_STATE_KEYEXCHANGE, 
  DTLS_STATE_WAIT_FINISHED, DTLS_STATE_FINISHED, DTLS_STATE_IDLE
} dtls_state_t;

/** 
 * Holds security parameters, local state and the transport address
 * for each peer. */
typedef struct {
  session_t session;	     /**< peer address and local interface */
  UT_hash_handle hh;	     /**< the hash handle (used internally) */

  dtls_state_t state;        /**< DTLS engine state */
  uint16 epoch;		     /**< counter for cipher state changes*/
  uint48 rseq;		     /**< sequence number of last record sent */

  uint24 mseq;		     /**< handshake message sequence number counter */

  /** actual and potential security parameters */
  dtls_security_parameters_t security_params[2]; 
  int config;	             /**< denotes which security params are in effect */

  /* temporary storage for the final handshake hash */
#if DTLS_VERSION == 0xfeff
  dtls_hash_t *hs_hash[2];
#elif DTLS_VERSION == 0xfefd
  dtls_hash_t *hs_hash[1];
#endif
} dtls_peer_t;

/** Length of the secret that is used for generating Hello Verify cookies. */
#define DTLS_COOKIE_SECRET_LENGTH 12

/** Holds global information of the DTLS engine. */
typedef struct dtls_context_t {
  unsigned char cookie_secret[DTLS_COOKIE_SECRET_LENGTH];
  time_t cookie_secret_age;	/**< the time the secret has been generated */

  dtls_peer_t *peers;		/**< hash table to manage peer status */

  void *app;			/**< application-specific data */
  int (*cb_write)(struct dtls_context_t *ctx, 
		  struct sockaddr *dst, socklen_t dstlen, int ifindex, 
		  uint8 *buf, int len);

  unsigned char *psk; /**< pre-shared key (set with dtls_set_psk()) */
  size_t psk_length;  /**< length of psk  */

  unsigned char readbuf[DTLS_MAX_BUF];
  unsigned char sendbuf[DTLS_MAX_BUF];
} dtls_context_t;

/** 
 * Creates a new context object. The storage allocated for the new
 * object must be released with dtls_free_context(). */
dtls_context_t *dtls_new_context(void *app_data);

/** Releases any storage that has been allocated for \p ctx. */
void dtls_free_context(dtls_context_t *ctx);

#define dtls_set_app_data(CTX,DATA) ((CTX)->app = (DATA))
#define dtls_get_app_data(CTX) ((CTX)->app)

/** Sets one of the available callbacks write, read. */
#define dtls_set_cb(ctx,cb,CB) do { (ctx)->cb_##CB = cb; } while(0)

#define DTLS_COOKIE_LENGTH 32

#define DTLS_CT_CHANGE_CIPHER_SPEC 20
#define DTLS_CT_ALERT              21
#define DTLS_CT_HANDSHAKE          22
#define DTLS_CT_APPLICATION_DATA   23

/** Generic header structure of the DTLS record layer. */
typedef struct {
  uint8 content_type;		/**< content type of the included message */
  uint16 version;		/**< Protocol version */
  uint16 epoch;		        /**< counter for cipher state changes */
  uint48 sequence_number;       /**< sequence number */
  uint16 length;		/**< length of the following fragment */
  /* fragment */
} dtls_record_header_t;

/* Handshake types */

#define DTLS_HT_HELLO_REQUEST        0
#define DTLS_HT_CLIENT_HELLO         1
#define DTLS_HT_SERVER_HELLO         2
#define DTLS_HT_HELLO_VERIFY_REQUEST 3
#define DTLS_HT_CERTIFICATE         11
#define DTLS_HT_SERVER_KEY_EXCHANGE 12
#define DTLS_HT_CERTIFICATE_REQUEST 13
#define DTLS_HT_SERVER_HELLO_DONE   14
#define DTLS_HT_CERTIFICATE_VERIFY  15
#define DTLS_HT_CLIENT_KEY_EXCHANGE 16
#define DTLS_HT_FINISHED            20

/** Header structure for the DTLS handshake protocol. */
typedef struct {
  uint8 msg_type; /**< Type of handshake message  (one of DTLS_HT_) */
  uint24 length;  /**< length of this message */
  uint16 message_seq; 	/**< Message sequence number */
  uint24 fragment_offset;	/**< Fragment offset. */
  uint24 fragment_length;	/**< Fragment length. */
  /* body */
} dtls_handshake_header_t;

/** Structure of the Client Hello message. */
typedef struct {
  uint16 version;	  /**< Client version */
  uint32 gmt_random;	  /**< GMT time of the random byte creation */
  unsigned char random[28];	/**< Client random bytes */
  /* session id (up to 32 bytes) */
  /* cookie (up to 32 bytes) */
  /* cipher suite (2 to 2^16 -1 bytes) */
  /* compression method */
} dtls_client_hello_t;

/** Structure of the Hello Verify Request. */
typedef struct {
  uint16 version;		/**< Server version */
  uint8 cookie_length;	/**< Length of the included cookie */
  uint8 cookie[];		/**< up to 32 bytes making up the cookie */
} dtls_hello_verify_t;  

#if 0
/** 
 * Checks a received DTLS record for consistency and eventually decrypt,
 * verify, decompress and reassemble the contained fragment for 
 * delivery to high-lever clients. 
 * 
 * \param state The DTLS record state for the current session. 
 * \param 
 */
int dtls_record_read(dtls_state_t *state, uint8 *msg, int msglen);
#endif

/**
 * Sets the pre-shared key for context \p ctx. 
 */
int dtls_set_psk(dtls_context_t *ctx, unsigned char *psk, size_t length);

/**
 * Retrieves a pointer to the cookie contained in a Client Hello message.
 *
 * \param hello_msg   Points to the received Client Hello message
 * \param msglen      Length of \p hello_msg
 * \param cookie      Is set to the beginning of the cookie in the message if
 *                    found. Undefined if this function returns \c 0.
 * \return \c 0 if no cookie was found, < 0 on error. On success, the return
 *         value reflects the cookie's length.
 */
int dtls_get_cookie(uint8 *hello_msg, int msglen, uint8 **cookie);

/**
 * Checks a received Client Hello message for a valid cookie. When the
 * Client Hello contains no cookie, the function fails and a Hello
 * Verify Request is sent to the peer (using the write callback function
 * registered with \p ctx). The return value is \c -1 on error, \c 0 when
 * undecided, and \c 1 if the Client Hello was good. 
 * 
 * \param ctx     The DTLS context.
 * \param session Transport address of the remote peer.
 * \param msg     The received datagram.
 * \param msglen  Length of \p msg.
 * \return \c 1 if msg is a Client Hello with a valid cookie, \c 0 or
 * \c -1 otherwise.
 */
int dtls_verify_peer(dtls_context_t *ctx, 
		     session_t *session,
		     uint8 *msg, int msglen);

/** 
 * Handles incoming data as DTLS message from given peer.
 */
int dtls_handle_message(dtls_context_t *ctx, session_t *session,
			uint8 *msg, int msglen);

#endif /* _DTLS_H_ */
