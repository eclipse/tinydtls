/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011--2012 Olaf Bergmann <bergmann@tzi.org>
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
 * @file dtls.h
 * @brief High level DTLS API and visible structures. 
 */

#ifndef _DTLS_H_
#define _DTLS_H_

#include <stdint.h>

#include "t_list.h"

#ifndef WITH_CONTIKI
#include "uthash.h"
#endif /* WITH_CONTIKI */

#include "crypto.h"
#include "hmac.h"

#include "config.h"
#include "global.h"
#ifndef DTLSv12
#define DTLS_VERSION 0xfeff	/* DTLS v1.1 */
#else
#define DTLS_VERSION 0xfefd	/* DTLS v1.2 */
#endif

/** Known compression methods
 *
 * \hideinitializer
 */
#define TLS_COMP_NULL      0x00	/* NULL compression */
 
typedef enum { 
  DTLS_STATE_INIT = 0, DTLS_STATE_SERVERHELLO, DTLS_STATE_KEYEXCHANGE, 
  DTLS_STATE_WAIT_FINISHED, DTLS_STATE_FINISHED, 
  /* client states */
  DTLS_STATE_CLIENTHELLO, DTLS_STATE_WAIT_SERVERHELLODONE,
  DTLS_STATE_WAIT_SERVERFINISHED, 

  DTLS_STATE_CONNECTED
} dtls_state_t;

typedef struct {
  uint24 mseq;		     /**< handshake message sequence number counter */

  /** pending config that is updated during handshake */
  /* FIXME: dtls_security_parameters_t pending_config; */

  /* temporary storage for the final handshake hash */
  dtls_hash_ctx hs_hash;
} dtls_hs_state_t;

/** 
 * Holds security parameters, local state and the transport address
 * for each peer. */
typedef struct dtls_peer_t {
#ifndef WITH_CONTIKI
  UT_hash_handle hh;
#else /* WITH_CONTIKI */
  struct dtls_peer_t *next;
#endif /* WITH_CONTIKI */

  session_t session;	     /**< peer address and local interface */

  dtls_state_t state;        /**< DTLS engine state */
  uint16 epoch;		     /**< counter for cipher state changes*/
  uint48 rseq;		     /**< sequence number of last record sent */

  dtls_hs_state_t hs_state;  /**< handshake protocol status */

  dtls_security_parameters_t security_params[2]; 
  int config;	             /**< denotes which security params are in effect 
			      FIXME: check if we can use epoch for this */
} dtls_peer_t;

typedef enum {
  DTLS_KEY_INVALID=0, DTLS_KEY_PSK=1, DTLS_KEY_RPK=2
} dtls_key_type_t;

typedef struct dtls_key_t {
  struct dtls_key_t *next;

  dtls_key_type_t type;
  union {
    struct dtls_psk_t {
      unsigned char *id;     /**< psk identity (set with dtls_set_psk()) */
      size_t id_length;      /**< length of psk identity  */
      unsigned char *data;   /**< key data */
      unsigned char *length; /**< length of data */
    } psk;
  } key;
} dtls_key_t;

/** Length of the secret that is used for generating Hello Verify cookies. */
#define DTLS_COOKIE_SECRET_LENGTH 12

/** Holds global information of the DTLS engine. */
typedef struct dtls_context_t {
  unsigned char cookie_secret[DTLS_COOKIE_SECRET_LENGTH];
  clock_time_t cookie_secret_age; /**< the time the secret has been generated */

#ifndef WITH_CONTIKI
  dtls_peer_t *peers;		/**< peer hash map */
#else /* WITH_CONTIKI */
  LIST_STRUCT(peers);
#endif /* WITH_CONTIKI */

  LIST_STRUCT(sendqueue);	/**< the packets to send */
  LIST_STRUCT(recvqueue);	/**< received packets */

  void *app;			/**< application-specific data */

  int (*cb_write)(struct dtls_context_t *ctx, 
		  session_t *session, uint8 *buf, size_t len);
  void (*cb_read)(struct dtls_context_t *ctx, 
		  session_t *session, uint8 *buf, size_t len);

  /* FIXME: use LIST_STRUCT(key_store) with dtls_key_t */
  unsigned char *psk; /**< pre-shared key (set with dtls_set_psk()) */
  size_t psk_length;  /**< length of psk  */

  unsigned char *psk_id; /**< psk identity (set with dtls_set_psk()) */
  size_t psk_id_length;  /**< length of psk identity  */

  unsigned char readbuf[DTLS_MAX_BUF];
  unsigned char sendbuf[DTLS_MAX_BUF];
} dtls_context_t;

/** 
 * This function initializes the tinyDTLS memory management and must
 * be called first.
 */
void dtls_init();

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

/** 
 * Writes the application data given in @p buf to the peer specified
 * by @p session. 
 * 
 * @param ctx      The DTLS context to use.
 * @param session  The remote transport address and local interface.
 * @param buf      The data to write.
 * @param len      The actual length of @p data.
 * 
 * @return The number of bytes written of @c -1 on error.
 */
int dtls_write(struct dtls_context_t *ctx, session_t *session, 
	       uint8 *buf, size_t len);

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
 * Sets the pre-shared key for context @p ctx. This function returns @c 1
 * when the @p psk and @p psk_id have been stored in @p ctx. In case of
 * error (most likely due to insufficient memory), @c 0 as returned. The
 * storage used by @p psk and @psk_id must remain valid until the PSK is
 * invalidated explicitly by dtls_remove_psk() or until @p ctx becomes
 * invalid.
 * 
 * @param psk     The pre-shared key to be used.
 * @param length  Length of @p psk.
 * @param psk_id  The identity to use with @p psk.
 * @param id_length Length of @p psk_id.
 * @return @c 1 if psk and psk_id have been set, @c 0 otherwise.
 */
int dtls_set_psk(dtls_context_t *ctx, unsigned char *psk, size_t length,
		 unsigned char *psk_id, size_t id_length);

/** 
 * Removes the PSK associated with @p psk_id from internal storage.
 */
void dtls_remove_psk(dtls_context_t *ctx, unsigned char *psk_id, size_t id_length);

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
 * Handles incoming data as DTLS message from given peer.
 */
int dtls_handle_message(dtls_context_t *ctx, session_t *session,
			uint8 *msg, int msglen);

/**
 * This function is called to add the received @p msg of size @p len to
 * the internal receive queue.
 *
 * @param ctx     The dtls context to use.
 * @param remote  Sender of the data.
 * @param msg     The received data
 * @param len     The actual length of @p msg.
 * @return A value less than zero on error, greater zero on success.
 */
int dtls_read(dtls_context_t *ctx, session_t *remote, uint8 *msg, size_t len);

/**
 * Dispatches messages from the receive queue.
 */
void dtls_dispatch(dtls_context_t *ctx);

#endif /* _DTLS_H_ */

/**
 * @addtogroup dtls_usage DTLS Usage
 *
 * @section dtls_server_example DTLS Server Example
 *
 * This section shows how to use the DTLS library functions to setup a 
 * simple secure UDP echo server. The application is responsible for the
 * entire network communication and thus will look like a usual UDP
 * server with socket creation and binding and a typical select-loop as
 * shown below. The minimum configuration required for DTLS is the 
 * creation of the dtls_context_t using dtls_new_context(), and a callback
 * for sending data. Received packets are read by the application and
 * passed to dtls_handle_message() as shown in @ref dtls_read_cb. 
 * For any useful communication to happen, a read call back should be 
 * registered as well. A shared secret is set by dtls_set_psk().
 * 
 * @code 
 dtls_context_t *the_context = NULL;
 int fd, result;

 fd = socket(...);
 if (fd < 0 || bind(fd, ...) < 0)
   exit(-1);

 the_context = dtls_new_context(&fd);
 dtls_set_psk(the_context, (unsigned char *)"secretPSK", 9);

 dtls_set_cb(the_context, read_from_peer, read);
 dtls_set_cb(the_context, send_to_peer, write);

 while (1) {
   ...initialize fd_set rfds and timeout ...
   result = select(fd+1, &rfds, NULL, 0, NULL);
    
   if (FD_ISSET(fd, &rfds))
     dtls_handle_read(the_context);
 }

 dtls_free_context(the_context);
 * @endcode
 * 
 * @subsection dtls_read_cb The Read Callback
 *
 * The DTLS library expects received raw data to be passed to
 * dtls_handle_message(). The application is responsible for
 * filling a session_t structure with the address data of the
 * remote peer as illustrated by the following example:
 * 
 * @code
int dtls_handle_read(struct dtls_context_t *ctx) {
  int *fd;
  session_t session;
  static uint8 buf[DTLS_MAX_BUF];
  int len;

  fd = dtls_get_app_data(ctx);

  assert(fd);

  session.rlen = sizeof(session.raddr);
  len = recvfrom(*fd, buf, sizeof(buf), 0, &session.raddr.sa, &session.rlen);
  
  return len < 0 ? len : dtls_handle_message(ctx, &session, buf, len);
}    
 * @endcode 
 * 
 * Once a new DTLS session was established and DTLS ApplicationData has been
 * received, the DTLS server invokes the read callback with the MAC-verified 
 * cleartext data as its argument. A read callback for a simple echo server
 * could look like this:
 * @code
void read_from_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len) {
  dtls_write(ctx, session, data, len);
}
 * @endcode 
 * 
 * @subsection dtls_send_cb The Send Callback
 * 
 * The callback function send_to_peer() is called whenever data must be
 * send over the network. Here, the sendto() system call is used to
 * transmit data within the given session. The socket descriptor required
 * by sendto() has been registered as application data when the DTLS context
 * was created with dtls_new_context().
 * Note that it is on the application to buffer the data when it cannot be
 * sent at the time this callback is invoked. The following example thus
 * is incomplete as it would have to deal with EAGAIN somehow.
 * @code
int send_to_peer(struct dtls_context_t *ctx, session_t *dst, uint8 *data, size_t len) {

  int fd = *(int *)dtls_get_app_data(ctx);
  return sendto(fd, data, len, MSG_DONTWAIT, &dst->raddr.sa, dst->rlen);
}
 * @endcode
 */

