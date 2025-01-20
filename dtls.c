/*******************************************************************************
 *
 * Copyright (c) 2011-2022 Olaf Bergmann (TZI) and others.
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
 *
 *******************************************************************************/

#include "tinydtls.h"
#include "dtls_time.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#ifndef WITH_CONTIKI
#include <stdlib.h>
#include "global.h"
#endif /* WITH_CONTIKI */
#ifdef HAVE_INTTYPES_H
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#else
#  ifndef PRIu64
#    define PRIu64 "llu"
#  endif
#  ifndef PRIx64
#    define PRIx64 "llx"
#  endif
#endif /* HAVE_INTTYPES_H */

#include "utlist.h"
#ifndef DTLS_PEERS_NOHASH
#include "uthash.h"
#endif /* DTLS_PEERS_NOHASH */

#include "dtls_debug.h"
#include "numeric.h"
#include "netq.h"
#include "dtls.h"

#include "alert.h"
#include "session.h"
#include "dtls_prng.h"
#include "dtls_mutex.h"

#ifdef WITH_SHA256
#  include "hmac.h"
#endif /* WITH_SHA256 */

#ifdef WITH_ZEPHYR
LOG_MODULE_DECLARE(TINYDTLS, CONFIG_TINYDTLS_LOG_LEVEL);
#endif /* WITH_ZEPHYR */

#define DTLS10_VERSION 0xfeff

/* Flags for dtls_destroy_peer()
 *
 *  DTLS_DESTROY_CLOSE indicates that the connection should be closed
 *                     when applicable
 */
#define DTLS_DESTROY_CLOSE 0x02

#ifdef RIOT_VERSION
# include <memarray.h>

dtls_context_t dtlscontext_storage_data[DTLS_CONTEXT_MAX];
memarray_t dtlscontext_storage;
#endif /* RIOT_VERSION */

#define dtls_set_version(H,V) dtls_int_to_uint16((H)->version, (V))
#define dtls_set_content_type(H,V) ((H)->content_type = (V) & 0xff)
#define dtls_set_length(H,V)  dtls_int_to_uint16(&((H)->length), (V))

#define dtls_get_content_type(H) ((H)->content_type & 0xff)
#define dtls_get_version(H) dtls_uint16_to_int((H)->version)
#define dtls_get_epoch(H) dtls_uint16_to_int((H)->epoch)
#define dtls_get_length(H) dtls_uint16_to_int((H)->length)
#define dtls_get_sequence_number(H) dtls_uint48_to_ulong((H)->sequence_number)
#define dtls_get_fragment_length(H) dtls_uint24_to_int((H)->fragment_length)

#ifdef DTLS_PEERS_NOHASH
#define FIND_PEER(head,sess,out)                                \
  do {                                                          \
    dtls_peer_t * tmp;                                          \
    (out) = NULL;                                               \
    LL_FOREACH((head), tmp) {                                   \
      if (dtls_session_equals(&tmp->session, (sess))) {         \
        (out) = tmp;                                            \
        break;                                                  \
      }                                                         \
    }                                                           \
  } while (0)
#define DEL_PEER(head,delptr)                   \
  if ((head) != NULL && (delptr) != NULL) {	\
    LL_DELETE(head,delptr);                     \
  }
#define ADD_PEER(head,sess,add)                 \
  LL_PREPEND(ctx->peers, peer);
#else /* DTLS_PEERS_NOHASH */
#define FIND_PEER(head,sess,out)		\
  HASH_FIND(hh,head,sess,sizeof(session_t),out)
#define ADD_PEER(head,sess,add)                 \
  HASH_ADD(hh,head,sess,sizeof(session_t),add)
#define DEL_PEER(head,delptr)                   \
  if ((head) != NULL && (delptr) != NULL) {	\
    HASH_DELETE(hh,head,delptr);		\
  }
#endif /* DTLS_PEERS_NOHASH */

#define DTLS_RH_LENGTH sizeof(dtls_record_header_t)
#define DTLS_HS_LENGTH sizeof(dtls_handshake_header_t)
/*
 * ClientHello:
 *
 * session_length         := 1 byte
 * session                := 0 bytes
 * cookie_length          := 1 byte
 * cookie                 := n bytes
 * cipher_length          := 2 bytes
 * cipher suites (max)    := 2 bytes + max * 2 bytes
 *    empty_renegotiation    := 2 bytes
 *    cipher suites          := max * 2 bytes
 * compression_length     := 1 byte
 * compression            := 1 byte
 * extensions_length      := 2 bytes   => 10 bytes + max * 2 bytes
 *
 * client_cert_type       := 6 bytes
 * server_cert_type       := 6 bytes
 * ec curves              := 8 bytes
 * ec point format        := 6 bytes   => 26
 * sign. and hash algos   := 8 bytes
 * extended master secret := 4 bytes   => 12
 *
 * (The ClientHello uses TLS_EMPTY_RENEGOTIATION_INFO_SCSV
 *  instead of renegotiation info)
 */
#define DTLS_CH_LENGTH sizeof(dtls_client_hello_t) /* no variable length fields! */
#define DTLS_COOKIE_LENGTH_MAX 32
#define DTLS_CH_LENGTH_MAX DTLS_CH_LENGTH + DTLS_COOKIE_LENGTH_MAX + 10 + (2 * DTLS_MAX_CIPHER_SUITES) + 26 + 12
#define DTLS_HV_LENGTH sizeof(dtls_hello_verify_t)
/*
 * ServerHello:
 *
 * version                := 2 bytes
 * random                 := 32 bytes
 * session_length         := 1 byte
 * session                := 0 bytes
 * cipher suite           := 2 bytes
 * compression            := 1 byte
 */
#define DTLS_SH_LENGTH (2 + DTLS_RANDOM_LENGTH + 1 + 2 + 1)
#define DTLS_SKEXEC_LENGTH (1 + 2 + 1 + 1 + DTLS_EC_KEY_SIZE + DTLS_EC_KEY_SIZE + 1 + 1 + 2 + 70)
#define DTLS_SKEXECPSK_LENGTH_MIN 2
#define DTLS_SKEXECPSK_LENGTH_MAX 2 + DTLS_PSK_MAX_CLIENT_IDENTITY_LEN
#define DTLS_CKXPSK_LENGTH_MIN 2
#define DTLS_CKXEC_LENGTH (1 + 1 + max(DTLS_EC_KEY_SIZE + DTLS_EC_KEY_SIZE, DTLS_PSK_MAX_CLIENT_IDENTITY_LEN))
#define DTLS_CV_LENGTH (1 + 1 + 2 + 1 + 1 + 1 + 1 + DTLS_EC_KEY_SIZE + 1 + 1 + DTLS_EC_KEY_SIZE)
#define DTLS_FIN_LENGTH 12

#define DTLS_ALERT_LENGTH 2 /* length of the Alert message */

#define HS_HDR_LENGTH  DTLS_RH_LENGTH + DTLS_HS_LENGTH
#define HV_HDR_LENGTH  HS_HDR_LENGTH + DTLS_HV_LENGTH

#define HIGH(V) (((V) >> 8) & 0xff)
#define LOW(V)  ((V) & 0xff)

#define DTLS_RECORD_HEADER(M) ((dtls_record_header_t *)(M))
#define DTLS_HANDSHAKE_HEADER(M) ((dtls_handshake_header_t *)(M))

#define HANDSHAKE(M) ((dtls_handshake_header_t *)((M) + DTLS_RH_LENGTH))
#define CLIENTHELLO(M) ((dtls_client_hello_t *)((M) + HS_HDR_LENGTH))

/*
 * Skip variable length field.
 *
 * A variable length field is encoded with a preceding length followed by
 * the value. That length itself is encoded in one to three bytes using uint8,
 * uint16, or uint24. Decoding a variable length field requires to check first,
 * if the length itself is within the bounds, and if so, if the value is also
 * within the bounds.
 *
 * The macro "returns" the calling context with an error when the bounds are
 * violated.
 *
 * \param P  pointer to length of the var field. Will be forwarded the end of
 *           the var field.
 * \param L  left overall data of P. Will be reduced by the size of the var
 *           field.
 * \param T  length type. e.g. uint8 or uint16
 * \param A  alert description in case of a length violation
 * \param M  logging message in case of a length violation
 */
#define SKIP_VAR_FIELD(P, L, T, A, M) {                \
    size_t skip_length = sizeof(T);                    \
    if (L < skip_length) {                             \
      dtls_info("%s: field length exceeds buffer", M); \
      return dtls_alert_fatal_create(A);               \
    }                                                  \
    skip_length += dtls_ ## T ## _to_int(P);           \
    if (L < skip_length) {                             \
      dtls_info("%s: field value exceeds buffer", M);  \
      return dtls_alert_fatal_create(A);               \
    }                                                  \
    L -= skip_length;                                  \
    P += skip_length;                                  \
  }

/*
 * Get variable length field.
 *
 * A variable length field is encoded with a preceding length followed by
 * the value. That length itself is encoded in one to three bytes using uint8,
 * uint16, or uint24. Decoding a variable length field requires to check first,
 * if the length itself is within the bounds, and if so, if the value is also
 * within the bounds.
 *
 * The macro "returns" the calling context with an error when the bounds are
 * violated.
 *
 * \param VL value length, variable to assign the length of the field value.
 * \param P  pointer to length of the var field. Will be forwarded to the
 *           value of the field.
 * \param L  left overall data of P. Will be reduced by the size of the field
 *           length type
 * \param T  field length type. e.g. uint8 or uint16
 * \param A  alert description in case of a length violation
 * \param M  logging message in case of a length violation
 */
#define GET_VAR_FIELD(VL, P, L, T, A, M) {             \
    if (L < sizeof(T)) {                               \
      dtls_info("%s: field length exceeds buffer", M); \
      return dtls_alert_fatal_create(A);               \
    }                                                  \
    VL = dtls_ ## T ## _to_int(P);                     \
    L -= sizeof(T);                                    \
    P += sizeof(T);                                    \
    if (L < VL) {                                      \
      dtls_info("%s: field value exceeds buffer", M);  \
      return dtls_alert_fatal_create(A);               \
    }                                                  \
  }

/* some constants for the PRF */
#define PRF_LABEL(Label) prf_label_##Label
#define PRF_LABEL_SIZE(Label) (sizeof(PRF_LABEL(Label)) - 1)

static const unsigned char prf_label_master[] = "master secret";
static const unsigned char prf_label_extended_master[] = "extended master secret";
static const unsigned char prf_label_key[] = "key expansion";
static const unsigned char prf_label_client[] = "client";
static const unsigned char prf_label_server[] = "server";
static const unsigned char prf_label_finished[] = " finished";

#ifdef DTLS_ECC
/* first part of Raw public key, the is the start of the Subject Public Key */
static const unsigned char cert_asn1_header[] = {
  0x30, 0x59, /* SEQUENCE, length 89 bytes */
    0x30, 0x13, /* SEQUENCE, length 19 bytes */
      0x06, 0x07, /* OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1) */
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
      0x06, 0x08, /* OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7) */
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
      0x03, 0x42, 0x00, /* BIT STRING, length 66 bytes, 0 bits unused */
         0x04 /* uncompressed, followed by the r und s values of the public key */
};
#endif /* DTLS_ECC */

#ifdef WITH_CONTIKI

PROCESS(dtls_retransmit_process, "DTLS retransmit process");

#endif /* WITH_CONTIKI */

#if defined(WITH_CONTIKI) ||  defined(WITH_LWIP)
static dtls_context_t the_dtls_context;

static inline dtls_context_t *
malloc_context(void) {
  return &the_dtls_context;
}

static inline void
free_context(dtls_context_t *context) {
  (void)context;
}

#endif /* WITH_CONTIKI || WITH_LWIP */

#ifdef RIOT_VERSION
static inline dtls_context_t *
malloc_context(void) {
     return (dtls_context_t *) memarray_alloc(&dtlscontext_storage);
}

static inline void free_context(dtls_context_t *context) {
  memarray_free(&dtlscontext_storage, context);
}
#endif /* RIOT_VERSION */

#if defined(WITH_POSIX) || defined(IS_WINDOWS)

static inline dtls_context_t *
malloc_context(void) {
  return (dtls_context_t *)malloc(sizeof(dtls_context_t));
}

static inline void
free_context(dtls_context_t *context) {
  free(context);
}

#endif /* WITH_POSIX */

void
dtls_init(void) {
  dtls_clock_init();
  crypto_init();
  netq_init();
  peer_init();

#ifdef RIOT_VERSION
memarray_init(&dtlscontext_storage, dtlscontext_storage_data,
              sizeof(dtls_context_t), DTLS_CONTEXT_MAX);
#endif /* RIOT_VERSION */
}

/* Calls cb_alert() with given arguments if defined, otherwise an
 * error message is logged and the result is -1. This is just an
 * internal helper.
 */
#define CALL(Context, which, ...)					\
  ((Context)->h && (Context)->h->which					\
   ? (Context)->h->which((Context), __VA_ARGS__)			\
   : -1)

static int
dtls_send_multi(dtls_context_t *ctx, dtls_peer_t *peer,
		dtls_security_parameters_t *security , session_t *session,
		unsigned char type, uint8 *buf_array[],
		size_t buf_len_array[], size_t buf_array_len);

static int
handle_alert(dtls_context_t *ctx, dtls_peer_t *peer,
		uint8 *record_header, uint8 *data, size_t data_length);

/**
 * Sends the fragment of length \p buflen given in \p buf to the
 * specified \p peer. The data will be MAC-protected and encrypted
 * according to the selected cipher and split into one or more DTLS
 * records of the specified \p type. This function returns the number
 * of bytes that were sent, or \c -1 if an error occurred.
 *
 * \param ctx    The DTLS context to use.
 * \param peer   The remote peer.
 * \param type   The content type of the record.
 * \param buf    The data to send.
 * \param buflen The actual length of \p buf.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static int
dtls_send(dtls_context_t *ctx, dtls_peer_t *peer, unsigned char type,
	  uint8 *buf, size_t buflen) {
  return dtls_send_multi(ctx, peer, dtls_security_params(peer), &peer->session,
			 type, &buf, &buflen, 1);
}

/**
 * Stops ongoing retransmissions of handshake messages for @p peer.
 */
static void dtls_stop_retransmission(dtls_context_t *context, dtls_peer_t *peer);

dtls_peer_t *
dtls_get_peer(const dtls_context_t *ctx, const session_t *session) {
  dtls_peer_t *p;
  FIND_PEER(ctx->peers, session, p);
  return p;
}

/**
 * Adds @p peer to list of peers in @p ctx. This function returns @c 0
 * on success, or a negative value on error (e.g. due to insufficient
 * storage).
 */
static int
dtls_add_peer(dtls_context_t *ctx, dtls_peer_t *peer) {
  ADD_PEER(ctx->peers, session, peer);
  return 0;
}

int
dtls_writev(struct dtls_context_t *ctx,
	    session_t *dst, uint8 *buf_array[],
	    size_t buf_len_array[], size_t buf_array_len) {

  dtls_peer_t *peer = dtls_get_peer(ctx, dst);

  /* Check if peer connection already exists */
  if (!peer) { /* no ==> create one */
    int res;

    /* dtls_connect() returns a value greater than zero if a new
     * connection attempt is made, 0 for session reuse. */
    res = dtls_connect(ctx, dst);

    return (res >= 0) ? 0 : res;
  } else { /* a session exists, check if it is in state connected */

    if (peer->state != DTLS_STATE_CONNECTED) {
      return 0;
    } else {
      return dtls_send_multi(ctx, peer, dtls_security_params(peer),
                             &peer->session, DTLS_CT_APPLICATION_DATA,
                             buf_array, buf_len_array, buf_array_len);
    }
  }
}

int
dtls_write(struct dtls_context_t *ctx, session_t *session,
	       uint8 *buf, size_t len) {
  return dtls_writev(ctx, session, &buf, &len, 1);
}

static int
dtls_get_cookie(uint8 *msg, size_t msglen, uint8 **cookie) {
  size_t cookie_len;
  /* To access the cookie, we have to determine the session id's
   * length and skip the whole thing. */
  if (msglen < DTLS_HS_LENGTH + DTLS_CH_LENGTH + sizeof(uint8))
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

  if (dtls_uint16_to_int(msg + DTLS_HS_LENGTH) != DTLS_VERSION)
    return dtls_alert_fatal_create(DTLS_ALERT_PROTOCOL_VERSION);

  msglen -= DTLS_HS_LENGTH + DTLS_CH_LENGTH;
  msg += DTLS_HS_LENGTH + DTLS_CH_LENGTH;

  /* skip session id */
  SKIP_VAR_FIELD(msg, msglen, uint8, DTLS_ALERT_HANDSHAKE_FAILURE,
                 "get_cookie, session_id");

  GET_VAR_FIELD(cookie_len, msg, msglen, uint8, DTLS_ALERT_HANDSHAKE_FAILURE,
                "get_cookie, cookie");

  *cookie = msg;
  return cookie_len;
}

static int
dtls_create_cookie(dtls_context_t *ctx,
		   session_t *session,
		   uint8 *msg, size_t msglen,
		   uint8 *cookie, int *clen) {
  unsigned char buf[DTLS_HMAC_MAX];
  uint8 *start;
  int len;

  /* create cookie with HMAC-SHA256 over:
   * - SECRET
   * - session parameters (only IP address?)
   * - client version
   * - random gmt and bytes
   * - session id
   * - cipher_suites
   * - compression method
   *
   * See RFC6347, 4.2.1.  Denial-of-Service Countermeasures, page 17
   *
   * "When responding to a HelloVerifyRequest, the client MUST use the same
   *  parameter values (version, random, session_id, cipher_suites,
   *  compression_method) as it did in the original ClientHello.  The
   *  server SHOULD use those values to generate its cookie and verify that
   *  they are correct upon cookie receipt."
   */

  /* Note that the buffer size must fit with the default hash algorithm. */

  dtls_hmac_context_t hmac_context;
  dtls_hmac_init(&hmac_context, ctx->cookie_secret, DTLS_COOKIE_SECRET_LENGTH);

  dtls_hmac_update(&hmac_context, (uint8 *)&session->addr, session->size);

  if (DTLS_HS_LENGTH + DTLS_CH_LENGTH > msglen)
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

  /* skip DTLS_HS_LENGTH */
  msg += DTLS_HS_LENGTH;
  msglen -= DTLS_HS_LENGTH;
  start = msg;

  /* add DTLS_CH_LENGTH by forward msg pointer */
  msg += DTLS_CH_LENGTH;
  msglen -= DTLS_CH_LENGTH;

  /* add session_id by forward msg pointer */
  SKIP_VAR_FIELD(msg, msglen, uint8, DTLS_ALERT_HANDSHAKE_FAILURE,
                 "create_cookie, session_id");

  dtls_hmac_update(&hmac_context, start, msg - start);

  /* skip cookie. */
  SKIP_VAR_FIELD(msg, msglen, uint8, DTLS_ALERT_HANDSHAKE_FAILURE,
                 "create_cookie, cookie");

  /* add cipher suites and compression by forward msg pointer. */
  start = msg;
  SKIP_VAR_FIELD(msg, msglen, uint16, DTLS_ALERT_HANDSHAKE_FAILURE,
                 "create_cookie, cipher-suites");
  SKIP_VAR_FIELD(msg, msglen, uint8, DTLS_ALERT_HANDSHAKE_FAILURE,
                 "create_cookie, compression");
  dtls_hmac_update(&hmac_context, start, msg - start);

  len = dtls_hmac_finalize(&hmac_context, buf);

  if (len < *clen) {
    memset(cookie + len, 0, *clen - len);
    *clen = len;
  }

  memcpy(cookie, buf, *clen);
  return 0;
}

#ifdef DTLS_CHECK_CONTENTTYPE
/* used to check if a received datagram contains a DTLS message */
static char const content_types[] = {
  DTLS_CT_CHANGE_CIPHER_SPEC,
  DTLS_CT_ALERT,
  DTLS_CT_HANDSHAKE,
  DTLS_CT_APPLICATION_DATA,
  0 				/* end marker */
};

/**
 * Checks if the content type of \p msg is known. This function returns
 * the found content type, or 0 otherwise.
 */
static int
known_content_type(const uint8_t *msg) {
  unsigned int n;
  assert(msg);

  for (n = 0; (content_types[n] != 0) && (content_types[n]) != msg[0]; n++)
    ;
  return content_types[n];
}
#else  /* DTLS_CHECK_CONTENTTYPE */
static int
known_content_type(const uint8_t *msg) {
  return msg[0];
}
#endif /* DTLS_CHECK_CONTENTTYPE */

/**
 * Checks if \p msg points to a valid DTLS record. If
 *
 */
static unsigned int
is_record(uint8 *msg, size_t msglen) {
  unsigned int rlen = 0;

  if (msglen >= DTLS_RH_LENGTH) { /* FIXME allow empty records? */
    uint16_t version = dtls_get_version(DTLS_RECORD_HEADER(msg));

    if (DTLS_VERSION == version) {
      if (!known_content_type(msg)) {
        return 0;
      }
    } else if (DTLS10_VERSION == version) {
        if (DTLS_CT_HANDSHAKE != msg[0] || DTLS_RH_LENGTH == msglen) {
          return 0;
        } else {
          uint8_t handshake_type = msg[DTLS_RH_LENGTH];
          if (DTLS_HT_CLIENT_HELLO != handshake_type  &&
              DTLS_HT_HELLO_VERIFY_REQUEST != handshake_type) {
            return 0;
          }
        }
    } else {
      return 0;
    }
    rlen = DTLS_RH_LENGTH + dtls_uint16_to_int(DTLS_RECORD_HEADER(msg)->length);

    /* we do not accept wrong length field in record header */
    if (rlen > msglen) {
      rlen = 0;
    }
  }

  return rlen;
}

/**
 * Initializes \p buf as record header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_record_header_t)
 * bytes. Increments records sequence number counter.
 * \return pointer to the next byte after the written header.
 * The length will be set to 0 and has to be changed before sending.
 */
static inline uint8 *
dtls_set_record_header(uint8 type,
		       uint16_t epoch,
		       uint64_t *rseqn,
		       uint8 *buf) {
  dtls_int_to_uint8(buf, type);
  buf += sizeof(uint8);

  dtls_int_to_uint16(buf, DTLS_VERSION);
  buf += sizeof(uint16);

  dtls_int_to_uint16(buf, epoch);
  buf += sizeof(uint16);

  dtls_int_to_uint48(buf, *rseqn);
  buf += sizeof(uint48);

  /* increment record sequence counter by 1 */
  (*rseqn)++;

  /* space for record size */
  memset(buf, 0, sizeof(uint16));
  return buf + sizeof(uint16);
}

/**
 * Initializes \p buf as handshake header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_handshake_header_t)
 * bytes. Increments message sequence number counter.
 * \return pointer to the next byte after \p buf
 */
static inline uint8 *
dtls_set_handshake_header(uint8 type,
			  uint16_t *mseqn,
			  int length,
			  int frag_offset, int frag_length,
			  uint8 *buf) {

  dtls_int_to_uint8(buf, type);
  buf += sizeof(uint8);

  dtls_int_to_uint24(buf, length);
  buf += sizeof(uint24);

  /* and copy the result to buf */
  dtls_int_to_uint16(buf, *mseqn);
  buf += sizeof(uint16);

  /* increment handshake message sequence counter by 1 */
  (*mseqn)++;

  dtls_int_to_uint24(buf, frag_offset);
  buf += sizeof(uint24);

  dtls_int_to_uint24(buf, frag_length);
  buf += sizeof(uint24);

  return buf;
}

/**
 * A copy of default_user_parameters are passed to the get_user_parameters
 * callback provided in dtls_handler_t and may be adapted according the user's
 * requirements.
 */
static const dtls_user_parameters_t default_user_parameters = {
  .cipher_suites =
#ifdef DTLS_DEFAULT_CIPHER_SUITES
    DTLS_DEFAULT_CIPHER_SUITES,
#else /* DTLS_DEFAULT_CIPHER_SUITES */
    {
#ifdef DTLS_ECC
      TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
      TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
#endif /* DTLS_ECC */
#ifdef DTLS_PSK
      TLS_PSK_WITH_AES_128_CCM_8,
      TLS_PSK_WITH_AES_128_CCM,
#endif /* DTLS_PSK */
    /* TLS_NULL_WITH_NULL_NULL must always be the last entry as it
     * indicates the stop marker for the traversal of this table. */
       TLS_NULL_WITH_NULL_NULL
    },
#endif /* DTLS_DEFAULT_CIPHER_SUITES */
  .force_extended_master_secret = 1,
  .force_renegotiation_info = 1,
};

/** only one compression method is currently defined */
static uint8 compression_methods[] = {
  TLS_COMPRESSION_NULL
};

typedef enum {
  DTLS_KEY_EXCHANGE_NONE,
  DTLS_KEY_EXCHANGE_PSK,
  DTLS_KEY_EXCHANGE_ECDHE_ECDSA
} cipher_suite_key_exchange_algorithm_t;

typedef struct cipher_suite_param_t {
  dtls_cipher_t cipher_suite;
  uint8_t mac_length;
  cipher_suite_key_exchange_algorithm_t key_exchange_algorithm;
} cipher_suite_param_t;

static const struct cipher_suite_param_t cipher_suite_params[] = {
  /* The TLS_NULL_WITH_NULL_NULL cipher suite must be the first
   * in this table (index DTLS_CIPHER_INDEX_NULL) */
  { TLS_NULL_WITH_NULL_NULL,             0, DTLS_KEY_EXCHANGE_NONE },
#ifdef DTLS_PSK
  { TLS_PSK_WITH_AES_128_CCM_8,          8, DTLS_KEY_EXCHANGE_PSK },
  { TLS_PSK_WITH_AES_128_CCM,           16, DTLS_KEY_EXCHANGE_PSK },
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  { TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,  8, DTLS_KEY_EXCHANGE_ECDHE_ECDSA },
  { TLS_ECDHE_ECDSA_WITH_AES_128_CCM,   16, DTLS_KEY_EXCHANGE_ECDHE_ECDSA },
#endif /* DTLS_ECC */
 };

static const dtls_cipher_index_t last_cipher_suite_param =
    sizeof(cipher_suite_params) / sizeof(cipher_suite_param_t);

/**
 * Check if cipher suite is contained in table.
 *
 * \param cipher_suites table with cipher suites. Terminated with
 *                      TLS_NULL_WITH_NULL_NULL.
 * \param cipher_suite cipher suite
 * \return 0 if not contained, != 0 if contained
 */
static inline uint8_t
contains_cipher_suite(const dtls_cipher_t* cipher_suites, const dtls_cipher_t cipher_suite) {
  if (cipher_suite == TLS_NULL_WITH_NULL_NULL) {
    return 0;
  }
  while ((*cipher_suites != cipher_suite) &&
         (*cipher_suites != TLS_NULL_WITH_NULL_NULL)) {
    cipher_suites++;
  }
  return *cipher_suites == cipher_suite;
}

/**
 * Get index to cipher suite params.
 *
 * \param cipher_suites table with user-selected cipher suites. Terminated with
 *                      TLS_NULL_WITH_NULL_NULL.
 * \param cipher cipher suite
 * \return index to cipher suite params, DTLS_CIPHER_INDEX_NULL if not found.
 */
static inline dtls_cipher_index_t
get_cipher_index(const dtls_cipher_t* cipher_suites, dtls_cipher_t cipher) {
  if (contains_cipher_suite(cipher_suites, cipher)) {
    for (int index = 0; index < last_cipher_suite_param ; ++index) {
      if (cipher_suite_params[index].cipher_suite == cipher) {
        return index;
      }
    }
  }
  return DTLS_CIPHER_INDEX_NULL;
}

/**
 * Get cipher suite.
 * \param cipher_index index to cipher suite params
 * \return cipher suite.
 */
static inline dtls_cipher_t
get_cipher_suite(dtls_cipher_index_t cipher_index) {
  assert(cipher_index < last_cipher_suite_param);
  return cipher_suite_params[cipher_index].cipher_suite;
}

/**
 * Get key exchange algorithm of cipher suite.
 * \param cipher_index index to cipher suite params
 * \return key exchange algorithm.
 *         \c DTLS_KEY_EXCHANGE_NONE, if cipher is not supported.
 */
static inline cipher_suite_key_exchange_algorithm_t
get_key_exchange_algorithm(dtls_cipher_index_t cipher_index) {
  assert(cipher_index < last_cipher_suite_param);
  return cipher_suite_params[cipher_index].key_exchange_algorithm;
}

/**
 * Get MAC length of cipher suite.
 * \param cipher_index index to cipher suite params
 * \return MAC length of cipher. \c 0, if cipher is not supported.
 */
static inline uint8_t
get_cipher_suite_mac_len(dtls_cipher_index_t cipher_index) {
  assert(cipher_index < last_cipher_suite_param);
  return cipher_suite_params[cipher_index].mac_length;
}

/** returns true if the cipher suite uses an ECDHE_ECDSA key exchange */
static inline int
is_key_exchange_ecdhe_ecdsa(dtls_cipher_index_t cipher_index) {
#ifdef DTLS_ECC
  return DTLS_KEY_EXCHANGE_ECDHE_ECDSA == get_key_exchange_algorithm(cipher_index);
#else
  (void) cipher_index;
  return 0;
#endif /* DTLS_ECC */
}

/** returns true if the cipher suite uses an PSK key exchange */
static inline int
is_key_exchange_psk(dtls_cipher_index_t cipher_index) {
#ifdef DTLS_PSK
  return DTLS_KEY_EXCHANGE_PSK == get_key_exchange_algorithm(cipher_index);
#else
  (void) cipher_index;
  return 0;
#endif /* DTLS_PSK */
}

/** returns true if the application is configured for psk */
static inline int
is_psk_supported(dtls_context_t *ctx) {
#ifdef DTLS_PSK
  return ctx && ctx->h && ctx->h->get_psk_info;
#else
  (void) ctx;
  return 0;
#endif /* DTLS_PSK */
}

/** returns true if the application is configured for ecdhe_ecdsa */
static inline int
is_ecdsa_supported(dtls_context_t *ctx, int is_client) {
#ifdef DTLS_ECC
  return ctx && ctx->h && ((!is_client && ctx->h->get_ecdsa_key) ||
                           (is_client && ctx->h->verify_ecdsa_key));
#else
  (void) ctx;
  (void) is_client;
  return 0;
#endif /* DTLS_ECC */
}

/** Returns true if the application is configured for ecdhe_ecdsa with
  * client authentication */
static inline int
is_ecdsa_client_auth_supported(dtls_context_t *ctx) {
#ifdef DTLS_ECC
  return ctx && ctx->h && ctx->h->get_ecdsa_key && ctx->h->verify_ecdsa_key;
#else
  (void) ctx;
  return 0;
#endif /* DTLS_ECC */
}

/**
 * Returns @c 1 if @p code is a cipher suite other than @c
 * TLS_NULL_WITH_NULL_NULL that we recognize.
 *
 * @param ctx   The current DTLS context
 * @param cipher_index The index to cipher suite params to check
 * @param is_client 1 for a dtls client, 0 for server
 * @return @c 1 iff @p code is recognized,
 */
static int
known_cipher(dtls_context_t *ctx, dtls_cipher_index_t cipher_index, int is_client) {
  const int psk = is_psk_supported(ctx);
  const int ecdsa = is_ecdsa_supported(ctx, is_client);
  const cipher_suite_key_exchange_algorithm_t key_exchange_algorithm =
                                      get_key_exchange_algorithm(cipher_index);

  return (psk && key_exchange_algorithm == DTLS_KEY_EXCHANGE_PSK) ||
	 (ecdsa && key_exchange_algorithm == DTLS_KEY_EXCHANGE_ECDHE_ECDSA);
}

/** Dump out the cipher keys and IVs used for the symmetric cipher. */
static void
dtls_debug_keyblock(dtls_security_parameters_t *config) {
  dtls_debug("key_block (%d bytes):\n", dtls_kb_size(config, peer->role));
  dtls_debug_dump("  client_MAC_secret",
		  dtls_kb_client_mac_secret(config, peer->role),
		  dtls_kb_mac_secret_size(config, peer->role));

  dtls_debug_dump("  server_MAC_secret",
		  dtls_kb_server_mac_secret(config, peer->role),
		  dtls_kb_mac_secret_size(config, peer->role));

  dtls_debug_dump("  client_write_key",
		  dtls_kb_client_write_key(config, peer->role),
		  dtls_kb_key_size(config, peer->role));

  dtls_debug_dump("  server_write_key",
		  dtls_kb_server_write_key(config, peer->role),
		  dtls_kb_key_size(config, peer->role));

  dtls_debug_dump("  client_IV",
		  dtls_kb_client_iv(config, peer->role),
		  dtls_kb_iv_size(config, peer->role));

  dtls_debug_dump("  server_IV",
		  dtls_kb_server_iv(config, peer->role),
		  dtls_kb_iv_size(config, peer->role));
}

/** returns the name of the given handshake type number.
  * see IANA for a full list of types:
  * https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-7
  */
static const char *
dtls_handshake_type_to_name(int type) {
  switch (type) {
  case DTLS_HT_HELLO_REQUEST:
    return "hello_request";
  case DTLS_HT_CLIENT_HELLO:
    return "client_hello";
  case DTLS_HT_SERVER_HELLO:
    return "server_hello";
  case DTLS_HT_HELLO_VERIFY_REQUEST:
    return "hello_verify_request";
  case DTLS_HT_CERTIFICATE:
    return "certificate";
  case DTLS_HT_SERVER_KEY_EXCHANGE:
    return "server_key_exchange";
  case DTLS_HT_CERTIFICATE_REQUEST:
    return "certificate_request";
  case DTLS_HT_SERVER_HELLO_DONE:
    return "server_hello_done";
  case DTLS_HT_CERTIFICATE_VERIFY:
    return "certificate_verify";
  case DTLS_HT_CLIENT_KEY_EXCHANGE:
    return "client_key_exchange";
  case DTLS_HT_FINISHED:
    return "finished";
  default:
    return "unknown";
  }
}

static const char *
dtls_message_type_to_name(int type) {
  switch (type) {
  case DTLS_CT_CHANGE_CIPHER_SPEC:
    return "change_cipher_spec";
  case DTLS_CT_ALERT:
    return "alert";
  case DTLS_CT_HANDSHAKE:
    return "handshake";
  case DTLS_CT_APPLICATION_DATA:
    return "application_data";
  default:
    return NULL;
  }
}


/**
 * Calculate the pre master secret and after that calculate the master-secret.
 */
static int
calculate_key_block(dtls_context_t *ctx,
		    dtls_handshake_parameters_t *handshake,
		    dtls_peer_t *peer,
		    session_t *session,
		    dtls_peer_type role) {
  (void) ctx;
  (void) session;
  unsigned char *pre_master_secret;
  int pre_master_len = 0;
  dtls_security_parameters_t *security = dtls_security_params_next(peer);
  uint8 master_secret[DTLS_MASTER_SECRET_LENGTH];
  (void)role; /* The macro dtls_kb_size() does not use role. */

  if (!security) {
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  pre_master_secret = security->key_block;
  switch (get_key_exchange_algorithm(handshake->cipher_index)) {
  case DTLS_KEY_EXCHANGE_PSK:
#ifdef DTLS_PSK
    {
      unsigned char psk[DTLS_PSK_MAX_KEY_LEN];
      int len;

      len = CALL(ctx, get_psk_info, session, DTLS_PSK_KEY,
             handshake->keyx.psk.identity,
             handshake->keyx.psk.id_length,
             psk, DTLS_PSK_MAX_KEY_LEN);
      if (len < 0) {
        dtls_crit("no psk key for session available\n");
        return len;
      }
    /* Temporarily use the key_block storage space for the pre master secret. */
      pre_master_len = dtls_psk_pre_master_secret(psk, len,
                        pre_master_secret,
                        MAX_KEYBLOCK_LENGTH);

      dtls_debug_hexdump("psk", psk, len);

      memset(psk, 0, DTLS_PSK_MAX_KEY_LEN);
      if (pre_master_len < 0) {
        dtls_crit("the psk was too long, for the pre master secret\n");
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
      }
      break;
    }
#else /* DTLS_PSK */
    dtls_crit("calculate_key_block: PSK not supported!\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
#endif /* DTLS_PSK */
  case DTLS_KEY_EXCHANGE_ECDHE_ECDSA:
#ifdef DTLS_ECC
    {
      pre_master_len = dtls_ecdh_pre_master_secret(
                         handshake->keyx.ecdsa.own_eph_priv,
                         handshake->keyx.ecdsa.other_eph_pub_x,
                         handshake->keyx.ecdsa.other_eph_pub_y,
                         sizeof(handshake->keyx.ecdsa.own_eph_priv),
                         pre_master_secret,
                         MAX_KEYBLOCK_LENGTH);
      if (pre_master_len < 0) {
        dtls_crit("the curve was too long, for the pre master secret\n");
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
      }
      break;
    }
#else /* DTLS_ECC */
    dtls_crit("calculate_key_block: ECC not supported!\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
#endif /* DTLS_ECC */
  case DTLS_KEY_EXCHANGE_NONE:
    assert(!"calculate_key_block: not supported key exchange algorithm\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);
  default: /* the key_exchange_algorithm is always from cipher_suite_params */
    assert(!"cipher_suite_params broken, unknown key exchange algorithm\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);
  }

  dtls_debug_dump("client_random", handshake->tmp.random.client,
                  DTLS_RANDOM_LENGTH);
  dtls_debug_dump("server_random", handshake->tmp.random.server,
                  DTLS_RANDOM_LENGTH);
  dtls_debug_dump("pre_master_secret", pre_master_secret, pre_master_len);

  if (handshake->extended_master_secret) {
    unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];

    dtls_hash_finalize(sha256hash, &peer->handshake_params->hs_state.ext_hash);

    dtls_prf(pre_master_secret, pre_master_len,
  	     PRF_LABEL(extended_master), PRF_LABEL_SIZE(extended_master),
	     sha256hash, sizeof(sha256hash),
	     NULL, 0,
	     master_secret,
	     DTLS_MASTER_SECRET_LENGTH);

    dtls_debug_dump("extended_master_secret", master_secret,
                    DTLS_MASTER_SECRET_LENGTH);
  }
  else {
    dtls_prf(pre_master_secret, pre_master_len,
         PRF_LABEL(master), PRF_LABEL_SIZE(master),
         handshake->tmp.random.client, DTLS_RANDOM_LENGTH,
         handshake->tmp.random.server, DTLS_RANDOM_LENGTH,
         master_secret,
         DTLS_MASTER_SECRET_LENGTH);

    dtls_debug_dump("master_secret", master_secret, DTLS_MASTER_SECRET_LENGTH);
  }

  /* create key_block from master_secret
   * key_block = PRF(master_secret,
                    "key expansion" + tmp.random.server + tmp.random.client) */

  dtls_prf(master_secret,
	   DTLS_MASTER_SECRET_LENGTH,
	   PRF_LABEL(key), PRF_LABEL_SIZE(key),
	   handshake->tmp.random.server, DTLS_RANDOM_LENGTH,
	   handshake->tmp.random.client, DTLS_RANDOM_LENGTH,
	   security->key_block,
	   dtls_kb_size(security, role));

  memcpy(handshake->tmp.master_secret, master_secret, DTLS_MASTER_SECRET_LENGTH);
  dtls_debug_keyblock(security);

  security->cipher_index = handshake->cipher_index;
  security->compression = handshake->compression;
  security->rseq = 0;

  return 0;
}

/* TODO: add a generic method which iterates over a list and
 * searches for a specific key */
static int
verify_ext_eliptic_curves(uint8 *data, size_t data_length) {
  int i, curve_name;

  /* length of curve list */
  i = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  if (i + sizeof(uint16) != data_length) {
    dtls_warn("the list of the supported elliptic curves should be tls extension length - 2\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  for (i = data_length - sizeof(uint16); i > 0; i -= sizeof(uint16)) {
    /* check if this curve is supported */
    curve_name = dtls_uint16_to_int(data);
    data += sizeof(uint16);

    if (curve_name == TLS_EXT_ELLIPTIC_CURVES_SECP256R1)
      return 0;
  }

  dtls_warn("no supported elliptic curve found\n");
  return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
}

static int verify_ext_cert_type(uint8 *data, size_t data_length) {
  int i, cert_type;

  /* length of cert type list */
  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  if (i + sizeof(uint8) != data_length) {
    dtls_warn("the list of the supported certificate types should be tls extension length - 1\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  for (i = data_length - sizeof(uint8); i > 0; i -= sizeof(uint8)) {
    /* check if this cert type is supported */
    cert_type = dtls_uint8_to_int(data);
    data += sizeof(uint8);

    if (cert_type == TLS_CERT_TYPE_RAW_PUBLIC_KEY)
      return 0;
  }

  dtls_warn("no supported certificate type found\n");
  return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
}

static int verify_ext_ec_point_formats(uint8 *data, size_t data_length) {
  int i, cert_type;

  /* length of ec_point_formats list */
  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  if (i + sizeof(uint8) != data_length) {
    dtls_warn("the list of the supported ec_point_formats should be tls extension length - 1\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  for (i = data_length - sizeof(uint8); i > 0; i -= sizeof(uint8)) {
    /* check if this ec_point_format is supported */
    cert_type = dtls_uint8_to_int(data);
    data += sizeof(uint8);

    if (cert_type == TLS_EXT_EC_POINT_FORMATS_UNCOMPRESSED)
      return 0;
  }

  dtls_warn("no supported ec_point_format found\n");
  return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
}

static int verify_ext_sig_hash_algo(uint8 *data, size_t data_length) {
  int i, hash_type, sig_type;

  /* length of sig_hash_algo list */
  i = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  if (i + sizeof(uint16) != data_length) {
    dtls_warn("the list of the supported signature_algorithms should be tls extension length - 2\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  for (i = data_length - sizeof(uint16); i > 0; i -= sizeof(uint16)) {
    /* check if this _sig_hash_algo is supported */
    hash_type = dtls_uint8_to_int(data);
    data += sizeof(uint8);
    sig_type = dtls_uint8_to_int(data);
    data += sizeof(uint8);

    if (hash_type == TLS_EXT_SIG_HASH_ALGO_SHA256 &&
        sig_type == TLS_EXT_SIG_HASH_ALGO_ECDSA)
      return 0;
  }

  dtls_warn("no supported signature_algorithms found\n");
  return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
}

/*
 * Check for some TLS Extensions used by the ECDHE_ECDSA cipher.
 */
static int
dtls_check_tls_extension(dtls_peer_t *peer,
                         uint8 *data, size_t data_length, int is_client_hello)
{
  uint16_t i, j;
  int ext_elliptic_curve = 0;
  int ext_client_cert_type = 0;
  int ext_server_cert_type = 0;
  int ext_ec_point_formats = 0;
  dtls_handshake_parameters_t *config = peer->handshake_params;
  const int ecdsa = is_key_exchange_ecdhe_ecdsa(config->cipher_index);

  if (data_length < sizeof(uint16)) {
    /* no tls extensions specified */
    if (ecdsa) {
      goto error;
    }
    goto check_forced_extensions;
  }

  /* get the length of the tls extension list */
  j = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (data_length < j)
    goto error;

  /* check for TLS extensions needed for this cipher */
  while (data_length) {
    if (data_length < sizeof(uint16) * 2)
      goto error;

    /* get the tls extension type */
    i = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    /* get the length of the tls extension */
    j = dtls_uint16_to_int(data);
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    if (data_length < j)
      goto error;

    switch (i) {
      case TLS_EXT_ELLIPTIC_CURVES:
        ext_elliptic_curve = 1;
        if (verify_ext_eliptic_curves(data, j))
          goto error;
        break;
      case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
        ext_client_cert_type = 1;
        if (is_client_hello) {
          if (verify_ext_cert_type(data, j))
            goto error;
        } else {
          if (dtls_uint8_to_int(data) != TLS_CERT_TYPE_RAW_PUBLIC_KEY)
            goto error;
        }
        break;
      case TLS_EXT_SERVER_CERTIFICATE_TYPE:
        ext_server_cert_type = 1;
        if (is_client_hello) {
          if (verify_ext_cert_type(data, j))
            goto error;
        } else {
          if (dtls_uint8_to_int(data) != TLS_CERT_TYPE_RAW_PUBLIC_KEY)
            goto error;
        }
        break;
      case TLS_EXT_EC_POINT_FORMATS:
        ext_ec_point_formats = 1;
        if (verify_ext_ec_point_formats(data, j))
          goto error;
        break;
      case TLS_EXT_ENCRYPT_THEN_MAC:
        /* As only AEAD cipher suites are currently available, this
         * extension can be skipped.
         */
        dtls_info("skipped encrypt-then-mac extension\n");
        break;
      case TLS_EXT_EXTENDED_MASTER_SECRET:
          config->extended_master_secret = 1;
        break;
      case TLS_EXT_SIG_HASH_ALGO:
        if (verify_ext_sig_hash_algo(data, j))
          goto error;
        break;
      case TLS_EXT_RENEGOTIATION_INFO:
        /* RFC 5746, minimal version, only empty info is supported */
        if (j == 1 && *data == 0) {
          config->renegotiation_info = 1;
        } else {
          dtls_warn("only empty renegotiation info is supported.\n");
          goto error;
        }
        break;
      default:
        dtls_notice("unsupported tls extension: %i\n", i);
        break;
    }
    data += j;
    data_length -= j;
  }
  if (ecdsa) {
    if (is_client_hello) {
      if (!ext_elliptic_curve || !ext_client_cert_type ||
          !ext_server_cert_type || !ext_ec_point_formats) {
        dtls_warn("not all required tls extensions found in client hello\n");
        goto error;
      }
    } else  {
      if (!ext_server_cert_type) {
        dtls_warn("not all required tls extensions found in server hello\n");
        goto error;
      }
    }
  }

check_forced_extensions:
  if (config->user_parameters.force_extended_master_secret) {
     if (!config->extended_master_secret) {
       goto error;
     }
  }
  if (config->user_parameters.force_renegotiation_info) {
     if (!config->renegotiation_info) {
       goto error;
     }
  }
  return 0;

error:
  return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
}

/**
 * Parses the ClientHello from the client and updates the internal handshake
 * parameters with the new data for the given \p peer. When the ClientHello
 * handshake message in \p data does not contain a cipher suite or
 * compression method, it is copied from the the current security parameters.
 *
 * \param ctx   The current DTLS context.
 * \param peer  The remote peer whose security parameters are about to change.
 * \param data  The handshake message with a ClientHello.
 * \param data_length The actual size of \p data.
 * \return \c -Something if an error occurred, \c 0 on success.
 */
static int
dtls_update_parameters(dtls_context_t *ctx,
		       dtls_peer_t *peer,
		       uint8 *data, size_t data_length) {
  int i;
  unsigned int j;
  int ok;
  dtls_handshake_parameters_t *config = peer->handshake_params;

  assert(config);
  assert(data_length > DTLS_HS_LENGTH + DTLS_CH_LENGTH);

  /* skip the handshake header and client version information */
  data += DTLS_HS_LENGTH + sizeof(uint16);
  data_length -= DTLS_HS_LENGTH + sizeof(uint16);

  /* store client random in config */
  memcpy(config->tmp.random.client, data, DTLS_RANDOM_LENGTH);
  data += DTLS_RANDOM_LENGTH;
  data_length -= DTLS_RANDOM_LENGTH;

  /* Caution: SKIP_VAR_FIELD may jump to error: */
  /* skip session_id */
  SKIP_VAR_FIELD(data, data_length, uint8, DTLS_ALERT_HANDSHAKE_FAILURE,
                 "update_parameters, session_id");
  /* skip cookie */
  SKIP_VAR_FIELD(data, data_length, uint8, DTLS_ALERT_HANDSHAKE_FAILURE,
                 "update_parameters, cookie");

  if (data_length < sizeof(uint16)) {
    dtls_debug("cipher suites length exceeds record\n");
    goto error;
  }

  i = dtls_uint16_to_int(data);

  if (i == 0) {
    dtls_debug("cipher suites missing\n");
    goto error;
  }

  if (data_length < i + sizeof(uint16)) {
    dtls_debug("length for cipher suites exceeds record\n");
    goto error;
  }

  if ((i % sizeof(uint16)) != 0) {
    dtls_debug("odd length for cipher suites\n");
    goto error;
  }

  data += sizeof(uint16);
  data_length -= sizeof(uint16) + i;

  config->user_parameters = default_user_parameters;
  if (ctx->h->get_user_parameters != NULL) {
    ctx->h->get_user_parameters(ctx, &peer->session, &config->user_parameters);
  }

  ok = 0;
  while ((i >= (int)sizeof(uint16)) && (!ok || !config->renegotiation_info)) {
    if (dtls_uint16_to_int(data) == TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
      config->renegotiation_info = 1;
    } else if (!ok) {
      config->cipher_index = get_cipher_index(config->user_parameters.cipher_suites, dtls_uint16_to_int(data));
      ok = known_cipher(ctx, config->cipher_index, 0);
    }
    i -= sizeof(uint16);
    data += sizeof(uint16);
  }

  /* skip remaining ciphers */
  data += i;

  if (!ok) {
    /* reset config cipher to a well-defined value */
    config->cipher_index = DTLS_CIPHER_INDEX_NULL;
    dtls_warn("No matching cipher suite found\n");
    goto error;
  }

  if (data_length < sizeof(uint8)) {
    dtls_debug("compression methods length exceeds record\n");
    goto error;
  }

  i = dtls_uint8_to_int(data);

  if (i == 0) {
    dtls_debug("compression methods missing\n");
    goto error;
  }

  if (data_length < i + sizeof(uint8)) {
    dtls_debug("length of compression methods exceeds record\n");
    goto error;
  }

  data += sizeof(uint8);
  data_length -= sizeof(uint8) + i;

  ok = 0;
  while (i && !ok) {
    for (j = 0; j < sizeof(compression_methods) / sizeof(uint8); ++j) {
      if (dtls_uint8_to_int(data) == compression_methods[j]) {
        config->compression = compression_methods[j];
        ok = 1;
      }
    }
    i -= sizeof(uint8);
    data += sizeof(uint8);
  }

  /* skip remaining compression methods */
  data += i;

  if (!ok) {
    /* reset config cipher to a well-defined value */
    goto error;
  }

  return dtls_check_tls_extension(peer, data, data_length, 1);
error:
  return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
}

/**
 * Parse the ClientKeyExchange and update the internal handshake state with
 * the new data.
 */
static inline int
check_client_keyexchange(dtls_context_t *ctx,
			 dtls_handshake_parameters_t *handshake,
			 uint8 *data, size_t length) {

  const cipher_suite_key_exchange_algorithm_t key_exchange_algorithm =
		  get_key_exchange_algorithm(handshake->cipher_index);

  (void) ctx;
#ifdef DTLS_ECC
  if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_ECDHE_ECDSA) {

    if (length < DTLS_HS_LENGTH + DTLS_CKXEC_LENGTH) {
      dtls_debug("The client key exchange is too short\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }
    data += DTLS_HS_LENGTH;

    if (dtls_uint8_to_int(data) != 1 + 2 * DTLS_EC_KEY_SIZE) {
      dtls_alert("expected 65 bytes long public point\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }
    data += sizeof(uint8);

    if (dtls_uint8_to_int(data) != 4) {
      dtls_alert("expected uncompressed public point\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }
    data += sizeof(uint8);

    memcpy(handshake->keyx.ecdsa.other_eph_pub_x, data,
	   sizeof(handshake->keyx.ecdsa.other_eph_pub_x));
    data += sizeof(handshake->keyx.ecdsa.other_eph_pub_x);

    memcpy(handshake->keyx.ecdsa.other_eph_pub_y, data,
	   sizeof(handshake->keyx.ecdsa.other_eph_pub_y));
    data += sizeof(handshake->keyx.ecdsa.other_eph_pub_y);
  }
#endif /* DTLS_ECC */
#ifdef DTLS_PSK
  if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_PSK) {
    int id_length;

    if (length < DTLS_HS_LENGTH + DTLS_CKXPSK_LENGTH_MIN) {
      dtls_debug("The client key exchange is too short\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }
    data += DTLS_HS_LENGTH;

    id_length = dtls_uint16_to_int(data);
    data += sizeof(uint16);

    if (DTLS_HS_LENGTH + DTLS_CKXPSK_LENGTH_MIN + id_length != length) {
      dtls_debug("The identity has a wrong length\n");
      return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
    }

    if (id_length > DTLS_PSK_MAX_CLIENT_IDENTITY_LEN) {
      dtls_warn("please use a smaller client identity\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    handshake->keyx.psk.id_length = id_length;
    memcpy(handshake->keyx.psk.identity, data, id_length);
  }
#endif /* DTLS_PSK */
  return 0;
}

static void
update_hs_hash(dtls_peer_t *peer, uint8 *data, size_t length) {
  dtls_debug_dump("add MAC data", data, length);
  dtls_hash_update(&peer->handshake_params->hs_state.hs_hash, data, length);
}

static void
copy_hs_hash(dtls_peer_t *peer, dtls_hash_ctx *hs_hash) {
  memcpy(hs_hash, &peer->handshake_params->hs_state.hs_hash,
	 sizeof(peer->handshake_params->hs_state.hs_hash));
}

static inline size_t
finalize_hs_hash(dtls_peer_t *peer, uint8 *buf) {
  return dtls_hash_finalize(buf, &peer->handshake_params->hs_state.hs_hash);
}

static inline void
clear_hs_hash(dtls_peer_t *peer) {
  assert(peer);
  dtls_debug("clear MAC\n");
  dtls_hash_init(&peer->handshake_params->hs_state.hs_hash);
}

/**
 * Checks if \p record + \p data contain a Finished message with valid
 * verify_data.
 *
 * \param ctx    The current DTLS context.
 * \param peer   The remote peer of the security association.
 * \param data   The cleartext payload of the message.
 * \param data_length Actual length of \p data.
 * \return \c 0 if the Finished message is valid, \c negative number otherwise.
 */
static int
check_finished(dtls_context_t *ctx, dtls_peer_t *peer,
           uint8 *data, size_t data_length) {
  (void) ctx;
  size_t digest_length, label_size;
  const unsigned char *label;
  unsigned char buf[DTLS_HMAC_MAX];
  (void)ctx;

  if (data_length < DTLS_HS_LENGTH + DTLS_FIN_LENGTH)
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);

  /* Use a union here to ensure that sufficient stack space is
   * reserved. As statebuf and verify_data are not used at the same
   * time, we can re-use the storage safely.
   */
  union {
    unsigned char statebuf[DTLS_HASH_CTX_SIZE];
    unsigned char verify_data[DTLS_FIN_LENGTH];
  } b;

  /* temporarily store hash status for roll-back after finalize */
  memcpy(b.statebuf, &peer->handshake_params->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

  digest_length = finalize_hs_hash(peer, buf);
  /* clear_hash(); */

  /* restore hash status */
  memcpy(&peer->handshake_params->hs_state.hs_hash, b.statebuf, DTLS_HASH_CTX_SIZE);

  if (peer->role == DTLS_CLIENT) {
    label = PRF_LABEL(server);
    label_size = PRF_LABEL_SIZE(server);
  } else { /* server */
    label = PRF_LABEL(client);
    label_size = PRF_LABEL_SIZE(client);
  }

  dtls_prf(peer->handshake_params->tmp.master_secret,
       DTLS_MASTER_SECRET_LENGTH,
       label, label_size,
       PRF_LABEL(finished), PRF_LABEL_SIZE(finished),
       buf, digest_length,
       b.verify_data, sizeof(b.verify_data));

  dtls_debug_dump("d:", data + DTLS_HS_LENGTH, sizeof(b.verify_data));
  dtls_debug_dump("v:", b.verify_data, sizeof(b.verify_data));

  /* compare verify data and create DTLS alert code when they differ */
  return equals(data + DTLS_HS_LENGTH, b.verify_data, sizeof(b.verify_data))
    ? 0
    : dtls_alert_create(DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_DECRYPT_ERROR);
}

/**
 * Prepares the payload given in \p data for sending with
 * dtls_send(). The \p data is encrypted and compressed according to
 * the current security parameters of \p peer. The result of this
 * operation is put into \p sendbuf with a prepended record header of
 * type \p type ready for sending. As some cipher suites add a MAC
 * before encryption, \p data must be large enough to hold this data
 * as well (usually \c dtls_kb_digest_size(CURRENT_CONFIG(peer)).
 *
 * \param peer            The remote peer the packet will be sent to.
 * \param security        The encryption paramater used to encrypt
 * \param type            The content type of this record.
 * \param data_array      Array with payloads in correct order.
 * \param data_len_array  Sizes of the payloads in correct order.
 * \param data_array_len  The number of payloads given.
 * \param sendbuf         The output buffer where the encrypted record
 *                        will be placed.
 * \param rlen            This parameter must be initialized with the
 *                        maximum size of \p sendbuf and will be updated
 *                        to hold the actual size of the stored packet
 *                        on success. On error, the value of \p rlen is
 *                        undefined.
 * \return Less than zero on error, or greater than zero success.
 */
static int
dtls_prepare_record(dtls_peer_t *peer, dtls_security_parameters_t *security,
		    unsigned char type,
		    uint8 *data_array[], size_t data_len_array[],
		    size_t data_array_len,
		    uint8 *sendbuf, size_t *rlen) {
  uint8 *p, *start;
  int res;
  unsigned int i;

  if (*rlen < DTLS_RH_LENGTH) {
    dtls_alert("The sendbuf (%zu bytes) is too small\n", *rlen);
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  if (!peer || !security) {
    dtls_alert("peer or security parameter missing\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  p = dtls_set_record_header(type, security->epoch, &(security->rseq), sendbuf);
  start = p;

  if (security->cipher_index == DTLS_CIPHER_INDEX_NULL) {
    /* no cipher suite */

    res = 0;
    for (i = 0; i < data_array_len; i++) {
      /* check the minimum that we need for packets that are not encrypted */
      if (*rlen < res + DTLS_RH_LENGTH + data_len_array[i]) {
        dtls_debug("dtls_prepare_record: send buffer too small\n");
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
      }

      memcpy(p, data_array[i], data_len_array[i]);
      p += data_len_array[i];
      res += data_len_array[i];
    }
  } else { /* TLS_PSK_WITH_AES_128_CCM_8, TLS_PSK_WITH_AES_128_CCM,
              TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 or
              TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
    /**
     * length of additional_data for the AEAD cipher which consists of
     * seq_num(2+6) + type(1) + version(2) + length(2)
     */
#define A_DATA_LEN 13
    unsigned char nonce[DTLS_CCM_BLOCKSIZE];
    unsigned char A_DATA[A_DATA_LEN];
    const uint8_t mac_len = get_cipher_suite_mac_len(security->cipher_index);
    const cipher_suite_key_exchange_algorithm_t key_exchange_algorithm =
            get_key_exchange_algorithm(security->cipher_index);
    /* For backwards-compatibility, dtls_encrypt_params is called with
     * M=<macLen> and L=3. */
    const dtls_ccm_params_t params = { nonce, mac_len, 3 };

    if (mac_len == 0) {
        dtls_debug("dtls_prepare_record(): encrypt using unknown cipher\n");
    } else {
      if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_PSK) {
        dtls_debug("dtls_prepare_record(): encrypt using "
                   "TLS_PSK_WITH_AES_128_CCM_%d\n", mac_len);
      } else if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_ECDHE_ECDSA) {
        dtls_debug("dtls_prepare_record(): encrypt using "
                   "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_%d\n", mac_len);
      }
    }

    /* set nonce
       from RFC 6655:
   	The "nonce" input to the AEAD algorithm is exactly that of [RFC5288]:
   	the "nonce" SHALL be 12 bytes long and is constructed as follows:
   	(this is an example of a "partially explicit" nonce; see Section
   	3.2.1 in [RFC5116]).

                       struct {
             opaque salt[4];
             opaque nonce_explicit[8];
                       } CCMNonce;

         [...]

  	 In DTLS, the 64-bit seq_num is the 16-bit epoch concatenated with the
   	 48-bit seq_num.

   	 When the nonce_explicit is equal to the sequence number, the CCMNonce
   	 will have the structure of the CCMNonceExample given below.

   	            struct {
   	             uint32 client_write_IV; // low order 32-bits
   	             uint64 seq_num;         // TLS sequence number
   	            } CCMClientNonce.


   	            struct {
   	             uint32 server_write_IV; // low order 32-bits
   	             uint64 seq_num; // TLS sequence number
   	            } CCMServerNonce.


   	            struct {
   	             case client:
   	               CCMClientNonce;
   	             case server:
   	               CCMServerNonce:
   	            } CCMNonceExample;
    */

    memcpy(p, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8);
    p += 8;
    res = 8;

    for (i = 0; i < data_array_len; i++) {
      /* check the minimum that we need for packets that are not encrypted */
      if (*rlen < res + DTLS_RH_LENGTH + data_len_array[i]) {
        dtls_debug("dtls_prepare_record: send buffer too small\n");
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
      }

      memcpy(p, data_array[i], data_len_array[i]);
      p += data_len_array[i];
      res += data_len_array[i];
    }

    memset(nonce, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(nonce, dtls_kb_local_iv(security, peer->role),
	   dtls_kb_iv_size(security, peer->role));
    memcpy(nonce + dtls_kb_iv_size(security, peer->role), start, 8); /* epoch + seq_num */

    dtls_debug_dump("nonce:", nonce, DTLS_CCM_BLOCKSIZE);
    dtls_debug_dump("key:", dtls_kb_local_write_key(security, peer->role),
		    dtls_kb_key_size(security, peer->role));

    /* re-use N to create additional data according to RFC 5246, Section 6.2.3.3:
     *
     * additional_data = seq_num + TLSCompressed.type +
     *                   TLSCompressed.version + TLSCompressed.length;
     */
    memcpy(A_DATA, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8); /* epoch and seq_num */
    memcpy(A_DATA + 8,  &DTLS_RECORD_HEADER(sendbuf)->content_type, 3); /* type and version */
    dtls_int_to_uint16(A_DATA + 11, res - 8); /* length */

    res = dtls_encrypt_params(&params, start + 8, res - 8, start + 8,
               dtls_kb_local_write_key(security, peer->role),
               dtls_kb_key_size(security, peer->role),
               A_DATA, A_DATA_LEN);

    if (res < 0)
      return res;

    res += 8;			/* increment res by size of nonce_explicit */
    dtls_debug_dump("message:", start, res);
  }

  /* fix length of fragment in sendbuf */
  dtls_int_to_uint16(sendbuf + 11, res);

  *rlen = DTLS_RH_LENGTH + res;
  return 0;
}

/**
 * Send Alert in stateless fashion.
 * An Alert is sent to the peer (using the write callback function
 * registered with \p ctx). The return value is the number of bytes sent,
 * or less than 0 on error.
 *
 * \param ctx              The DTLS context.
 * \param ephemeral_peer   The ephemeral remote party we are talking to.
 * \param level            Alert level.
 * \param description      Alert description.
 * \return number of bytes sent, or less than 0 on error.
 */
static int
dtls_0_send_alert(dtls_context_t *ctx,
			     dtls_ephemeral_peer_t *ephemeral_peer,
			     dtls_alert_level_t level,
			     dtls_alert_t description)
{
  uint8 buf[DTLS_RH_LENGTH + DTLS_ALERT_LENGTH];
  uint8 *p = dtls_set_record_header(DTLS_CT_ALERT, 0, &(ephemeral_peer->rseq), buf);

  /* fix length of fragment in sendbuf */
  dtls_int_to_uint16(buf + 11, DTLS_ALERT_LENGTH);

  /* Alert */
  dtls_int_to_uint8(p, level);
  dtls_int_to_uint8(p + 1, description);

  dtls_debug("send alert - protocol version  packet\n");

  dtls_debug_hexdump("send header", buf, DTLS_RH_LENGTH);
  dtls_debug_hexdump("send unencrypted alert", p, DTLS_ALERT_LENGTH);

  return CALL(ctx, write, ephemeral_peer->session, buf, sizeof(buf));
}

static int
dtls_0_send_alert_from_err(dtls_context_t *ctx,
                           dtls_ephemeral_peer_t *ephemeral_peer,
                           int err) {

  assert(ephemeral_peer);

  if (dtls_is_alert(err)) {
    dtls_alert_level_t level = ((-err) & 0xff00) >> 8;
    dtls_alert_t desc = (-err) & 0xff;
    return dtls_0_send_alert(ctx, ephemeral_peer, level, desc);
  } else if (err == -1) {
    return dtls_0_send_alert(ctx, ephemeral_peer, DTLS_ALERT_LEVEL_FATAL,
                             DTLS_ALERT_INTERNAL_ERROR);
  }
  return -1;
}

/**
 * Send HelloVerifyRequest to initial challenge a peer in a stateless fashion.
 * A HelloVerifyRequest is sent to the peer (using the write callback function
 * registered with \p ctx). The return value is the number of bytes sent,
 * or less than 0 on error.
 *
 * \param ctx              The DTLS context.
 * \param ephemeral_peer   The ephemeral remote party we are talking to.
 * \param data             The received datagram.
 * \param data_length      Length of \p msg.
 * \return number of bytes sent, or less than 0 on error.
 */
static int
dtls_0_send_hello_verify_request(dtls_context_t *ctx,
			     dtls_ephemeral_peer_t *ephemeral_peer,
			     uint8 *data, size_t data_length)
{
  uint8 buf[DTLS_RH_LENGTH + DTLS_HS_LENGTH + DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH];
  uint8 *p = dtls_set_record_header(DTLS_CT_HANDSHAKE, 0, &(ephemeral_peer->rseq), buf);

  assert(data_length == DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH);

  /* Signal DTLS version 1.0 in the record layer of ClientHello and
   * HelloVerifyRequest handshake messages according to Section 4.2.1
   * of RFC 6347.
   *
   * This does not apply to a renegotation ClientHello
   */
  dtls_int_to_uint16(buf + 1, DTLS10_VERSION);

  /* fix length of fragment in sendbuf */
  dtls_int_to_uint16(buf + 11, DTLS_HS_LENGTH + data_length);

  p = dtls_set_handshake_header(DTLS_HT_HELLO_VERIFY_REQUEST,
                      &(ephemeral_peer->mseq), data_length, 0, data_length, p);

  memcpy(p, data, data_length);

  dtls_debug("send hello_verify_request packet\n");

  dtls_debug_hexdump("send header", buf, DTLS_RH_LENGTH);
  dtls_debug_hexdump("send unencrypted handshake header", buf + DTLS_RH_LENGTH,
                     DTLS_HS_LENGTH);
  dtls_debug_hexdump("send unencrypted cookie", data, data_length);

  return CALL(ctx, write, ephemeral_peer->session, buf, sizeof(buf));
}

static int
dtls_send_handshake_msg_hash(dtls_context_t *ctx,
			     dtls_peer_t *peer,
			     session_t *session,
			     uint8 header_type,
			     uint8 *data, size_t data_length,
			     int add_hash)
{
  uint8 buf[DTLS_HS_LENGTH];
  uint8 *data_array[2];
  size_t data_len_array[2];
  int i = 0;
  dtls_security_parameters_t *security = dtls_security_params(peer);

  dtls_set_handshake_header(header_type,
                            &(peer->handshake_params->hs_state.mseq_s),
                            data_length, 0, data_length, buf);

  if (add_hash) {
    update_hs_hash(peer, buf, sizeof(buf));
  }
  data_array[i] = buf;
  data_len_array[i] = sizeof(buf);
  i++;

  if (data != NULL) {
    if (add_hash) {
      update_hs_hash(peer, data, data_length);
    }
    data_array[i] = data;
    data_len_array[i] = data_length;
    i++;
  }
  dtls_debug("send handshake packet of type: %s (%i)\n",
	     dtls_handshake_type_to_name(header_type), header_type);
  return dtls_send_multi(ctx, peer, security, session, DTLS_CT_HANDSHAKE,
			 data_array, data_len_array, i);
}

static int
dtls_send_handshake_msg(dtls_context_t *ctx,
			dtls_peer_t *peer,
			uint8 header_type,
			uint8 *data, size_t data_length)
{
  return dtls_send_handshake_msg_hash(ctx, peer, &peer->session,
				      header_type, data, data_length, 1);
}

/**
 * Returns true if the message @p Data is a handshake message that
 * must be included in the calculation of verify_data in the Finished
 * message.
 *
 * @param Type The message type. Only handshake messages but the initial
 * Client Hello and Hello Verify Request are included in the hash,
 * @param Data The PDU to examine.
 * @param Length The length of @p Data.
 *
 * @return @c 1 if @p Data must be included in hash, @c 0 otherwise.
 *
 * @hideinitializer
 */
#define MUST_HASH(Type, Data, Length)					\
  ((Type) == DTLS_CT_HANDSHAKE &&					\
   ((Data) != NULL) && ((Length) > 0)  &&				\
   ((Data)[0] != DTLS_HT_HELLO_VERIFY_REQUEST) &&			\
   ((Data)[0] != DTLS_HT_CLIENT_HELLO ||				\
    ((Length) >= HS_HDR_LENGTH &&					\
     (dtls_uint16_to_int(DTLS_RECORD_HEADER(Data)->epoch > 0) ||	\
      (dtls_uint16_to_int(HANDSHAKE(Data)->message_seq) > 0)))))


#ifdef DTLS_CONSTRAINED_STACK
static dtls_mutex_t static_mutex = DTLS_MUTEX_INITIALIZER;
static unsigned char sendbuf[DTLS_MAX_BUF];
#endif /* DTLS_CONSTRAINED_STACK */

/**
 * Sends the data passed in @p buf as a DTLS record of type @p type to
 * the given peer. The data will be encrypted and compressed according
 * to the security parameters for @p peer.
 *
 * @param ctx             The DTLS context in effect.
 * @param peer            The remote party where the packet is sent.
 * @param security        The encryption paramater used to encrypt.
 * @param session         The transport address of the remote peer.
 * @param type            The content type of this record.
 * @param buf_array       The array of data to send.
 * @param buf_len_array   The number of bytes in each array element.
 * @param buf_array_len   The number of array elements.
 * @return Less than zero in case of an error or the number of
 *   bytes that have been sent otherwise.
 */
static int
dtls_send_multi(dtls_context_t *ctx, dtls_peer_t *peer,
		dtls_security_parameters_t *security , session_t *session,
		unsigned char type, uint8 *buf_array[],
		size_t buf_len_array[], size_t buf_array_len)
{
  /* We cannot use ctx->sendbuf here as it is reserved for collecting
   * the input for this function, i.e. buf == ctx->sendbuf.
   *
   * TODO: check if we can use the receive buf here. This would mean
   * that we might not be able to handle multiple records stuffed in
   * one UDP datagram */
#ifndef DTLS_CONSTRAINED_STACK
  unsigned char sendbuf[DTLS_MAX_BUF];
#endif /* ! DTLS_CONSTRAINED_STACK */
  size_t len = sizeof(sendbuf);
  int res;
  unsigned int i;
  size_t overall_len = 0;

#ifdef DTLS_CONSTRAINED_STACK
  dtls_mutex_lock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */

  res = dtls_prepare_record(peer, security, type, buf_array, buf_len_array,
                            buf_array_len, sendbuf, &len);

  if (res < 0)
    goto return_unlock;

  /* if (peer && MUST_HASH(peer, type, buf, buflen)) */
  /*   update_hs_hash(peer, buf, buflen); */


  /* Signal DTLS version 1.0 in the record layer of ClientHello and
   * HelloVerifyRequest handshake messages according to Section 4.2.1
   * of RFC 6347.
   *
   * This does not apply to a renegotation ClientHello
   */
  if (security->epoch == 0) {
    if (type == DTLS_CT_HANDSHAKE) {
      if (buf_array[0][0] == DTLS_HT_CLIENT_HELLO) {
        dtls_int_to_uint16(sendbuf + 1, DTLS10_VERSION);
      }
    }
  }

  dtls_debug_hexdump("send header", sendbuf, sizeof(dtls_record_header_t));
  for (i = 0; i < buf_array_len; i++) {
    dtls_debug_hexdump("send unencrypted", buf_array[i], buf_len_array[i]);
    overall_len += buf_len_array[i];
  }

  if (type == DTLS_CT_HANDSHAKE || type == DTLS_CT_CHANGE_CIPHER_SPEC) {
    /* copy messages of handshake into retransmit buffer */
    netq_t *n = netq_node_new(overall_len);
    if (n) {
      dtls_tick_t now;
      dtls_ticks(&now);
      n->t = now + 2 * CLOCK_SECOND;
      n->retransmit_cnt = 0;
      n->timeout = 2 * CLOCK_SECOND;
      n->peer = peer;
      n->epoch = (security) ? security->epoch : 0;
      n->type = type;
      n->job = RESEND;
      n->length = 0;
      for (i = 0; i < buf_array_len; i++) {
        memcpy(n->data + n->length, buf_array[i], buf_len_array[i]);
        n->length += buf_len_array[i];
      }

      if (!netq_insert_node(&ctx->sendqueue, n)) {
        dtls_warn("cannot add packet to retransmit buffer\n");
        netq_node_free(n);
#ifdef WITH_CONTIKI
      } else {
        /* must set timer within the context of the retransmit process */
        PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
        etimer_set(&ctx->retransmit_timer, n->timeout);
        PROCESS_CONTEXT_END(&dtls_retransmit_process);
#else /* WITH_CONTIKI */
        dtls_debug("copied to sendqueue\n");
#endif /* WITH_CONTIKI */
      }
    } else {
      dtls_warn("retransmit buffer full\n");
    }
  }

  /* FIXME: copy to peer's sendqueue (after fragmentation if
   * necessary) and initialize retransmit timer */
  res = CALL(ctx, write, session, sendbuf, len);

return_unlock:
#ifdef DTLS_CONSTRAINED_STACK
  dtls_mutex_unlock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */

  /* Guess number of bytes application data actually sent:
   * dtls_prepare_record() tells us in len the number of bytes to
   * send, res will contain the bytes actually sent. */
  return res <= 0 ? res : (int)(overall_len - (len - (unsigned int)res));
}

static inline int
dtls_send_alert(dtls_context_t *ctx, dtls_peer_t *peer, dtls_alert_level_t level,
		dtls_alert_t description) {
  uint8_t msg[] = { level, description };

  dtls_send(ctx, peer, DTLS_CT_ALERT, msg, sizeof(msg));

  /* copy close alert in retransmit buffer to emulate timeout */
  /* not resent, therefore don't copy the complete record */
  netq_t *n = netq_node_new(2);
  if (n) {
    dtls_tick_t now;
    dtls_ticks(&now);
    n->t = now + 2 * CLOCK_SECOND;
    n->retransmit_cnt = 0;
    n->timeout = 2 * CLOCK_SECOND;
    n->peer = peer;
    n->epoch = peer->security_params[0]->epoch;
    n->type = DTLS_CT_ALERT;
    n->length = 2;
    n->data[0] = level;
    n->data[1] = description;
    n->job = TIMEOUT;

    if (!netq_insert_node(&ctx->sendqueue, n)) {
      dtls_warn("cannot add alert to retransmit buffer\n");
      netq_node_free(n);
      n = NULL;
#ifdef WITH_CONTIKI
    } else {
      /* must set timer within the context of the retransmit process */
      PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
      etimer_set(&ctx->retransmit_timer, n->timeout);
      PROCESS_CONTEXT_END(&dtls_retransmit_process);
#else /* WITH_CONTIKI */
      dtls_debug("alert copied to retransmit buffer\n");
#endif /* WITH_CONTIKI */
    }
  } else {
    dtls_warn("cannot add alert, retransmit buffer full\n");
  }
  if (!n) {
    /* timeout not registered */
    handle_alert(ctx, peer, NULL, msg, sizeof(msg));
  }

  return 0;
}

int
dtls_close(dtls_context_t *ctx, const session_t *remote) {
  int res = -1;
  dtls_peer_t *peer;

  peer = dtls_get_peer(ctx, remote);

  if (peer) {
    /* indicate tear down */
    peer->state = DTLS_STATE_CLOSING;
    res = dtls_send_alert(ctx, peer, DTLS_ALERT_LEVEL_WARNING,
                          DTLS_ALERT_CLOSE_NOTIFY);
  }
  return res;
}

static void
dtls_destroy_peer(dtls_context_t *ctx, dtls_peer_t *peer, int flags) {
  if ((flags & DTLS_DESTROY_CLOSE) &&
      (peer->state != DTLS_STATE_CLOSED) &&
      (peer->state != DTLS_STATE_CLOSING)) {
    dtls_close(ctx, &peer->session);
  }
  dtls_stop_retransmission(ctx, peer);
  DEL_PEER(ctx->peers, peer);
  dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "removed peer", &peer->session);
  dtls_free_peer(peer);
}

/**
 * Checks a received ClientHello message for a valid cookie. When the
 * ClientHello contains no cookie, the function fails and a HelloVerifyRequest
 * is sent to the peer (using the write callback function registered
 * with \p ctx). The return value is \c -1 on error, \c 1 when
 * undecided, and \c 0 if the ClientHello was good.
 *
 * \param ctx              The DTLS context.
 * \param ephemeral_peer   The remote party we are talking to, if any.
 * \param data             The received datagram.
 * \param data_length      Length of \p msg.
 *
 * \return \c 0 if msg is a ClientHello with a valid cookie, \c 1 or
 * \c -1 otherwise.
 */
static int
dtls_0_verify_peer(dtls_context_t *ctx,
		 dtls_ephemeral_peer_t *ephemeral_peer,
		 uint8 *data, size_t data_length)
{
  uint8 buf[DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH];
  uint8 *p = buf;
  int len = DTLS_COOKIE_LENGTH;
  uint8 *cookie = NULL;
  int err;
#undef mycookie
#define mycookie (buf + DTLS_HV_LENGTH)

  /* Store cookie where we can reuse it for the HelloVerifyRequest. */
  err = dtls_create_cookie(ctx, ephemeral_peer->session, data, data_length,
                           mycookie, &len);
  if (err < 0)
    return err;

  dtls_debug_dump("create cookie", mycookie, len);

  assert(len == DTLS_COOKIE_LENGTH);

  /* Perform cookie check. */
  len = dtls_get_cookie(data, data_length, &cookie);
  if (len < 0) {
    dtls_warn("error while fetching the cookie, err: %i\n", len);
    if (dtls_alert_fatal_create(DTLS_ALERT_PROTOCOL_VERSION) == len) {
      dtls_0_send_alert(ctx, ephemeral_peer, DTLS_ALERT_LEVEL_FATAL,
                        DTLS_ALERT_PROTOCOL_VERSION);
    }
    return len;
  }

  if (len == 0) {
    dtls_debug("cookie len is 0!\n");
  } else if (len != DTLS_COOKIE_LENGTH) {
    dtls_debug("cookie len mismatch recv. %u != %u!\n", len, DTLS_COOKIE_LENGTH);
  } else if (memcmp(cookie, mycookie, len)) {
    dtls_debug_dump("not matching cookie", cookie, len);
  } else {
    dtls_debug("found matching cookie\n");
    return 0;
  }

  /* ClientHello did not contain any valid cookie, hence we send a
   * HelloVerifyRequest. */

  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  dtls_int_to_uint8(p, DTLS_COOKIE_LENGTH);
  p += sizeof(uint8);

  assert(p == mycookie);

  p += DTLS_COOKIE_LENGTH;

  err = dtls_0_send_hello_verify_request(ctx,
          ephemeral_peer,
          buf, p - buf);
  if (err < 0) {
    dtls_warn("cannot send HelloVerify request\n");
  }
  return err; /* HelloVerifyRequest is sent, now we cannot do anything but wait */

#undef mycookie
}

#ifdef DTLS_ECC
/*
 * Assumes that data_len is at least 1 */
static size_t
dtls_asn1_len(uint8 **data, size_t *data_len)
{
  size_t len = 0;

  if ((**data) & 0x80) {
    size_t octets = (**data) & 0x7f;
    (*data)++;
    (*data_len)--;
    if (octets > *data_len)
      return (size_t)-1;
    while (octets > 0) {
      len = (len << 8) + (**data);
      (*data)++;
      (*data_len)--;
      octets--;
    }
  }
  else {
    len = (**data) & 0x7f;
    (*data)++;
    (*data_len)--;
  }
  return len;
}

static int
dtls_asn1_integer_to_ec_key(uint8 *data, size_t data_len, uint8 *key,
                         size_t key_len)
{
  size_t length;

  if (data_len < 2) {
    dtls_alert("signature data length short\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  if (dtls_uint8_to_int(data) != 0x02) {
    dtls_alert("wrong ASN.1 struct, expected Integer\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint8);
  data_len -= sizeof(uint8);

  length = dtls_asn1_len(&data, &data_len);
  if (length > data_len) {
    dtls_alert("asn1 integer length too long\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  if (length < key_len) {
    /* pad with leading 0s */
    memset(key, 0, key_len - length);
    memcpy(key + key_len - length, data, length); 
  }
  else {
    /* drop leading 0s if needed */
    memcpy(key, data + length - key_len, key_len); 
  }
  return length + 2;
}

static int
dtls_check_ecdsa_signature_elem(uint8 *data, size_t data_length,
				unsigned char *result_r,
				unsigned char *result_s)
{
  int ret;
  uint8 *data_orig = data;

  /*
   * 1 sig hash sha256
   * 1 sig hash ecdsa
   * 2 data length
   * 1 sequence
   * 1 sequence length
   */
  if (data_length < 1 + 1 + 2 + 1 + 1) {
    dtls_alert("signature data length short\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  if (dtls_uint8_to_int(data) != TLS_EXT_SIG_HASH_ALGO_SHA256) {
    dtls_alert("only sha256 is supported in certificate verify\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint8_to_int(data) != TLS_EXT_SIG_HASH_ALGO_ECDSA) {
    dtls_alert("only ecdsa signature is supported in client verify\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (data_length < dtls_uint16_to_int(data)) {
    dtls_alert("signature length wrong\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (dtls_uint8_to_int(data) != 0x30) {
    dtls_alert("wrong ASN.1 struct, expected SEQUENCE\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (data_length < dtls_uint8_to_int(data)) {
    dtls_alert("signature length wrong\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  ret = dtls_asn1_integer_to_ec_key(data, data_length, result_r, DTLS_EC_KEY_SIZE);
  if (ret <= 0)
    return ret;
  data += ret;
  data_length -= ret;

  ret = dtls_asn1_integer_to_ec_key(data, data_length, result_s, DTLS_EC_KEY_SIZE);
  if (ret <= 0)
    return ret;
  data += ret;
  data_length -= ret;

  return data - data_orig;
}

static int
check_client_certificate_verify(dtls_context_t *ctx,
				dtls_peer_t *peer,
				uint8 *data, size_t data_length)
{
  (void) ctx;
  dtls_handshake_parameters_t *config = peer->handshake_params;
  int ret;
  unsigned char result_r[DTLS_EC_KEY_SIZE];
  unsigned char result_s[DTLS_EC_KEY_SIZE];
  dtls_hash_ctx hs_hash;
  unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];

  assert(is_key_exchange_ecdhe_ecdsa(config->cipher_index));

  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  if (data_length < DTLS_CV_LENGTH - 2 * DTLS_EC_KEY_SIZE) {
    /*
     * Some of the ASN.1 integer in the signature may be less than
     * DTLS_EC_KEY_SIZE if leading bits are 0.
     * dtls_check_ecdsa_signature_elem() knows how to handle this undersize.
     */
    dtls_alert("the packet length does not match the expected\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  ret = dtls_check_ecdsa_signature_elem(data, data_length, result_r, result_s);
  if (ret < 0) {
    return ret;
  }
  data += ret;
  data_length -= ret;

  copy_hs_hash(peer, &hs_hash);

  dtls_hash_finalize(sha256hash, &hs_hash);

  ret = dtls_ecdsa_verify_sig_hash(config->keyx.ecdsa.other_pub_x,
                                   config->keyx.ecdsa.other_pub_y,
                                   sizeof(config->keyx.ecdsa.other_pub_x),
                                   sha256hash, sizeof(sha256hash),
                                   result_r, result_s);

  if (ret < 0) {
    dtls_alert("client certificate verify, wrong signature err: %i\n", ret);
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  return 0;
}
#endif /* DTLS_ECC */

static int
dtls_send_server_hello(dtls_context_t *ctx, dtls_peer_t *peer)
{
  /* Ensure that the largest message to create fits in our source
   * buffer. (The size of the destination buffer is checked by the
   * encoding function, so we do not need to guess.)
   *
   * extensions length       := 2 bytes
   * client certificate type := 5 bytes
   * server certificate type := 5 bytes
   * ec_point_formats        := 6 bytes
   * extended master secret  := 4 bytes
   * renegotiation info      := 5 bytes
   *
   * (no elliptic_curves in ServerHello.)
   */
  uint8 buf[DTLS_SH_LENGTH + 2 + 5 + 5 + 6 + 4 + 5];
  uint8 *p;
  uint8 extension_size;
  dtls_handshake_parameters_t * const handshake = peer->handshake_params;
  const dtls_cipher_t cipher_suite = get_cipher_suite(handshake->cipher_index);
  const int ecdsa = is_key_exchange_ecdhe_ecdsa(handshake->cipher_index);

  extension_size = (handshake->extended_master_secret ? 4 : 0) +
                   (handshake->renegotiation_info ? 5 : 0) +
                   (ecdsa ? 5 + 5 + 6 : 0);

  /* Handshake header */
  p = buf;

  /* ServerHello */
  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* Set 32 bytes of server random data. */
  dtls_prng(handshake->tmp.random.server, DTLS_RANDOM_LENGTH);

  memcpy(p, handshake->tmp.random.server, DTLS_RANDOM_LENGTH);
  p += DTLS_RANDOM_LENGTH;

  *p++ = 0;			/* no session id */

  if (cipher_suite != TLS_NULL_WITH_NULL_NULL) {
    /* selected cipher suite */
    dtls_int_to_uint16(p, cipher_suite);
    p += sizeof(uint16);

    /* selected compression method */
    *p++ = compression_methods[handshake->compression];
  }

  if (extension_size) {
    /* length of the extensions */
    dtls_int_to_uint16(p, extension_size);
    p += sizeof(uint16);
  }

  if (ecdsa) {
    /* client certificate type extension, 5 bytes */
    dtls_int_to_uint16(p, TLS_EXT_CLIENT_CERTIFICATE_TYPE);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 1);
    p += sizeof(uint16);

    dtls_int_to_uint8(p, TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    p += sizeof(uint8);

    /* client certificate type extension, 5 bytes */
    dtls_int_to_uint16(p, TLS_EXT_SERVER_CERTIFICATE_TYPE);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 1);
    p += sizeof(uint16);

    dtls_int_to_uint8(p, TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    p += sizeof(uint8);

    /* ec_point_formats, 6 bytes */
    dtls_int_to_uint16(p, TLS_EXT_EC_POINT_FORMATS);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 2);
    p += sizeof(uint16);

    /* number of supported formats */
    dtls_int_to_uint8(p, 1);
    p += sizeof(uint8);

    dtls_int_to_uint8(p, TLS_EXT_EC_POINT_FORMATS_UNCOMPRESSED);
    p += sizeof(uint8);

  }
  if (handshake->extended_master_secret) {
    /* extended master secret, 4 bytes */
    dtls_int_to_uint16(p, TLS_EXT_EXTENDED_MASTER_SECRET);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 0);
    p += sizeof(uint16);
  }

  if (handshake->renegotiation_info) {
    /* RFC5746 minimal version, empty renegotiation info, 5 bytes */
    dtls_int_to_uint16(p, TLS_EXT_RENEGOTIATION_INFO);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 1);
    p += sizeof(uint16);

    /* empty renegotiation info */
    *p++ = 0;
  }

  assert((buf <= p) && ((unsigned int)(p - buf) <= sizeof(buf)));

  /* TODO use the same record sequence number as in the ClientHello,
     see 4.2.1. Denial-of-Service Countermeasures */
  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_SERVER_HELLO,
				 buf, p - buf);
}

#ifdef DTLS_ECC
#define DTLS_EC_SUBJECTPUBLICKEY_SIZE (2 * DTLS_EC_KEY_SIZE + sizeof(cert_asn1_header))

static int
dtls_send_certificate_empty(dtls_context_t *ctx, dtls_peer_t *peer)
{
  uint8 buf[sizeof(uint24)];

  /* length of this certificate */
  dtls_int_to_uint24(buf, 0);

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE,
				 buf, sizeof(buf));
}

static int
dtls_send_certificate_ecdsa(dtls_context_t *ctx, dtls_peer_t *peer,
			    const dtls_ecdsa_key_t *key)
{
  uint8 buf[sizeof(uint24) + DTLS_EC_SUBJECTPUBLICKEY_SIZE];
  uint8 *p;

  /* Certificate
   *
   * Start message construction at beginning of buffer. */
  p = buf;

  /* length of this certificate */
  dtls_int_to_uint24(p, DTLS_EC_SUBJECTPUBLICKEY_SIZE);
  p += sizeof(uint24);

  memcpy(p, &cert_asn1_header, sizeof(cert_asn1_header));
  p += sizeof(cert_asn1_header);

  memcpy(p, key->pub_key_x, DTLS_EC_KEY_SIZE);
  p += DTLS_EC_KEY_SIZE;

  memcpy(p, key->pub_key_y, DTLS_EC_KEY_SIZE);
  p += DTLS_EC_KEY_SIZE;

  assert(p <= (buf + sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE,
				 buf, p - buf);
}

static uint8 *
dtls_add_ecdsa_signature_elem(uint8 *p, uint32_t *point_r, uint32_t *point_s)
{
  int len_r;
  int len_s;

#define R_KEY_OFFSET (1 + 1 + 2 + 1 + 1)
#define S_KEY_OFFSET(len_a) (R_KEY_OFFSET + (len_a))
  /* store the pointer to the r component of the signature and make space */
  len_r = dtls_ec_key_asn1_from_uint32(point_r, DTLS_EC_KEY_SIZE, p + R_KEY_OFFSET);
  len_s = dtls_ec_key_asn1_from_uint32(point_s, DTLS_EC_KEY_SIZE, p + S_KEY_OFFSET(len_r));

#undef R_KEY_OFFSET
#undef S_KEY_OFFSET

  /* sha256 */
  dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_SHA256);
  p += sizeof(uint8);

  /* ecdsa */
  dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_ECDSA);
  p += sizeof(uint8);

  /* length of signature */
  dtls_int_to_uint16(p, len_r + len_s + 2);
  p += sizeof(uint16);

  /* ASN.1 SEQUENCE */
  dtls_int_to_uint8(p, 0x30);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, len_r + len_s);
  p += sizeof(uint8);

  /* ASN.1 Integer r */

  /* the point r ASN.1 integer was added here so skip */
  p += len_r;

  /* ASN.1 Integer s */

  /* the point s ASN.1 integer was added here so skip */
  p += len_s;

  return p;
}

static int
dtls_send_server_key_exchange_ecdh(dtls_context_t *ctx, dtls_peer_t *peer,
				   const dtls_ecdsa_key_t *key)
{
  /* The ASN.1 Integer representation of an 32 byte unsigned int could be
   * 33 bytes long add space for that */
  uint8 buf[DTLS_SKEXEC_LENGTH + 2];
  uint8 *p;
  uint8 *key_params;
  uint8 *ephemeral_pub_x;
  uint8 *ephemeral_pub_y;
  uint32_t point_r[9];
  uint32_t point_s[9];
  dtls_handshake_parameters_t *config = peer->handshake_params;

  /* ServerKeyExchange
   *
   * Start message construction at beginning of buffer. */
  p = buf;

  key_params = p;
  /* ECCurveType curve_type: named_curve */
  dtls_int_to_uint8(p, 3);
  p += sizeof(uint8);

  /* NamedCurve namedcurve: secp256r1 */
  dtls_int_to_uint16(p, TLS_EXT_ELLIPTIC_CURVES_SECP256R1);
  p += sizeof(uint16);

  dtls_int_to_uint8(p, 1 + 2 * DTLS_EC_KEY_SIZE);
  p += sizeof(uint8);

  /* This should be an uncompressed point, but I do not have access to the spec. */
  dtls_int_to_uint8(p, 4);
  p += sizeof(uint8);

  /* store the pointer to the x component of the pub key and make space */
  ephemeral_pub_x = p;
  p += DTLS_EC_KEY_SIZE;

  /* store the pointer to the y component of the pub key and make space */
  ephemeral_pub_y = p;
  p += DTLS_EC_KEY_SIZE;

  dtls_ecdsa_generate_key(config->keyx.ecdsa.own_eph_priv,
			  ephemeral_pub_x, ephemeral_pub_y,
			  DTLS_EC_KEY_SIZE);

  /* sign the ephemeral and its paramaters */
  dtls_ecdsa_create_sig(key->priv_key, DTLS_EC_KEY_SIZE,
		       config->tmp.random.client, DTLS_RANDOM_LENGTH,
		       config->tmp.random.server, DTLS_RANDOM_LENGTH,
		       key_params, p - key_params,
		       point_r, point_s);

  p = dtls_add_ecdsa_signature_elem(p, point_r, point_s);

  assert(p <= (buf + sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_SERVER_KEY_EXCHANGE,
				 buf, p - buf);
}
#endif /* DTLS_ECC */

#ifdef DTLS_PSK
static int
dtls_send_server_key_exchange_psk(dtls_context_t *ctx, dtls_peer_t *peer,
				  const unsigned char *psk_hint, size_t len)
{
  uint8 buf[DTLS_SKEXECPSK_LENGTH_MAX];
  uint8 *p;

  p = buf;

  assert(len <= DTLS_PSK_MAX_CLIENT_IDENTITY_LEN);
  if (len > DTLS_PSK_MAX_CLIENT_IDENTITY_LEN) {
    /* should never happen */
    dtls_warn("psk identity hint is too long\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  dtls_int_to_uint16(p, len);
  p += sizeof(uint16);

  memcpy(p, psk_hint, len);
  p += len;

  assert((buf <= p) && ((unsigned int)(p - buf) <= sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_SERVER_KEY_EXCHANGE,
				 buf, p - buf);
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int
dtls_send_server_certificate_request(dtls_context_t *ctx, dtls_peer_t *peer)
{
  uint8 buf[8];
  uint8 *p;

  /* ServerHelloDone
   *
   * Start message construction at beginning of buffer. */
  p = buf;

  /* certificate_types */
  dtls_int_to_uint8(p, 1);
  p += sizeof(uint8);

  /* ecdsa_sign */
  dtls_int_to_uint8(p, TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN);
  p += sizeof(uint8);

  /* supported_signature_algorithms */
  dtls_int_to_uint16(p, 2);
  p += sizeof(uint16);

  /* sha256 */
  dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_SHA256);
  p += sizeof(uint8);

  /* ecdsa */
  dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_ECDSA);
  p += sizeof(uint8);

  /* certificate_authoritiess */
  dtls_int_to_uint16(p, 0);
  p += sizeof(uint16);

  assert(p <= (buf + sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE_REQUEST,
				 buf, p - buf);
}
#endif /* DTLS_ECC */

static int
dtls_send_server_hello_done(dtls_context_t *ctx, dtls_peer_t *peer)
{

  /* ServerHelloDone
   *
   * Start message construction at beginning of buffer. */

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_SERVER_HELLO_DONE,
				 NULL, 0);
}

static int
dtls_send_server_hello_msgs(dtls_context_t *ctx, dtls_peer_t *peer)
{
  int res;
  cipher_suite_key_exchange_algorithm_t key_exchange_algorithm;

  res = dtls_send_server_hello(ctx, peer);

  if (res < 0) {
    dtls_debug("dtls_server_hello: cannot prepare ServerHello record\n");
    return res;
  }
  key_exchange_algorithm = get_key_exchange_algorithm(peer->handshake_params->cipher_index);

#ifdef DTLS_ECC
  if (DTLS_KEY_EXCHANGE_ECDHE_ECDSA == key_exchange_algorithm) {
    const dtls_ecdsa_key_t *ecdsa_key;

    res = CALL(ctx, get_ecdsa_key, &peer->session, &ecdsa_key);
    if (res < 0) {
      dtls_crit("no ecdsa certificate to send in certificate\n");
      return res;
    }

    res = dtls_send_certificate_ecdsa(ctx, peer, ecdsa_key);

    if (res < 0) {
      dtls_debug("dtls_server_hello: cannot prepare Certificate record\n");
      return res;
    }

    res = dtls_send_server_key_exchange_ecdh(ctx, peer, ecdsa_key);

    if (res < 0) {
      dtls_debug("dtls_server_hello: cannot prepare Server Key Exchange record\n");
      return res;
    }

    if (is_ecdsa_client_auth_supported(ctx)) {
      res = dtls_send_server_certificate_request(ctx, peer);

      if (res < 0) {
        dtls_debug("dtls_server_hello: cannot prepare certificate Request record\n");
        return res;
      }
    }
  }
#endif /* DTLS_ECC */

#ifdef DTLS_PSK
  if (DTLS_KEY_EXCHANGE_PSK == key_exchange_algorithm) {
    unsigned char psk_hint[DTLS_PSK_MAX_CLIENT_IDENTITY_LEN];
    int len;

    /* The identity hint is optional, therefore we ignore the result
     * and check psk only. */
    len = CALL(ctx, get_psk_info, &peer->session, DTLS_PSK_HINT,
	       NULL, 0, psk_hint, DTLS_PSK_MAX_CLIENT_IDENTITY_LEN);

    if (len < 0) {
      dtls_debug("dtls_server_hello: cannot create ServerKeyExchange\n");
      return len;
    }

    if (len > 0) {
      res = dtls_send_server_key_exchange_psk(ctx, peer, psk_hint, (size_t)len);

      if (res < 0) {
	dtls_debug("dtls_server_key_exchange_psk: cannot send server key exchange record\n");
	return res;
      }
    }
  }
#endif /* DTLS_PSK */

  res = dtls_send_server_hello_done(ctx, peer);

  if (res < 0) {
    dtls_debug("dtls_server_hello: cannot prepare ServerHelloDone record\n");
    return res;
  }
  return 0;
}

static inline int
dtls_send_ccs(dtls_context_t *ctx, dtls_peer_t *peer) {
  uint8 buf[1] = {1};

  return dtls_send(ctx, peer, DTLS_CT_CHANGE_CIPHER_SPEC, buf, 1);
}


static int
dtls_send_client_key_exchange(dtls_context_t *ctx, dtls_peer_t *peer)
{
  uint8 buf[DTLS_CKXEC_LENGTH];
  uint8 *p;
  dtls_handshake_parameters_t *handshake = peer->handshake_params;
  const cipher_suite_key_exchange_algorithm_t key_exchange_algorithm =
          get_key_exchange_algorithm(handshake->cipher_index);
  int ret;

  p = buf;

  memset(buf, 0, sizeof(buf));
  switch (key_exchange_algorithm) {
  case DTLS_KEY_EXCHANGE_PSK:
#ifdef DTLS_PSK
  {
      int len;

    len = CALL(ctx, get_psk_info, &peer->session, DTLS_PSK_IDENTITY,
	       handshake->keyx.psk.identity, handshake->keyx.psk.id_length,
	       buf + sizeof(uint16),
	       min(sizeof(buf) - sizeof(uint16),
		   sizeof(handshake->keyx.psk.identity)));
    if (len < 0) {
      dtls_crit("no psk identity set in kx\n");
      return len;
    }

    if (len + sizeof(uint16) > DTLS_CKXEC_LENGTH) {
      memset(&handshake->keyx.psk, 0, sizeof(dtls_handshake_parameters_psk_t));
      dtls_warn("the psk identity is too long\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }
    handshake->keyx.psk.id_length = (unsigned int)len;
    memcpy(handshake->keyx.psk.identity, p + sizeof(uint16), len);

    dtls_int_to_uint16(p, handshake->keyx.psk.id_length);
    p += sizeof(uint16);

    memcpy(p, handshake->keyx.psk.identity, handshake->keyx.psk.id_length);
    p += handshake->keyx.psk.id_length;

    break;
  }
#else /* DTLS_PSK */
    dtls_crit("PSK not supported\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
#endif /* DTLS_PSK */
  case DTLS_KEY_EXCHANGE_ECDHE_ECDSA:
#ifdef DTLS_ECC
    {
      uint8 *ephemeral_pub_x;
      uint8 *ephemeral_pub_y;

      dtls_int_to_uint8(p, 1 + 2 * DTLS_EC_KEY_SIZE);
      p += sizeof(uint8);

      /* This should be an uncompressed point, but I do not have access to the spec. */
      dtls_int_to_uint8(p, 4);
      p += sizeof(uint8);

      ephemeral_pub_x = p;
      p += DTLS_EC_KEY_SIZE;
      ephemeral_pub_y = p;
      p += DTLS_EC_KEY_SIZE;

    dtls_ecdsa_generate_key(peer->handshake_params->keyx.ecdsa.own_eph_priv,
    			    ephemeral_pub_x, ephemeral_pub_y,
    			    DTLS_EC_KEY_SIZE);

      break;
    }
#else /* DTLS_ECC */
    dtls_crit("ECC not supported\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
#endif /* DTLS_ECC */

  case DTLS_KEY_EXCHANGE_NONE:
    assert(!"NULL cipher requested");
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);

  default:
    dtls_crit("key exchange algorithm %d not supported\n", key_exchange_algorithm);
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  assert((buf <= p) && ((unsigned int)(p - buf) <= sizeof(buf)));

  ret = dtls_send_handshake_msg(ctx, peer, DTLS_HT_CLIENT_KEY_EXCHANGE,
				buf, p - buf);

  /* Keep hash information for extended master secret */
  memcpy(&peer->handshake_params->hs_state.ext_hash,
         &peer->handshake_params->hs_state.hs_hash,
         sizeof(peer->handshake_params->hs_state.ext_hash));

  return ret;
}

#ifdef DTLS_ECC
static int
dtls_send_certificate_verify_ecdh(dtls_context_t *ctx, dtls_peer_t *peer,
				   const dtls_ecdsa_key_t *key)
{
  /* The ASN.1 Integer representation of an 32 byte unsigned int could be
   * 33 bytes long add space for that */
  uint8 buf[DTLS_CV_LENGTH + 2];
  uint8 *p;
  uint32_t point_r[9];
  uint32_t point_s[9];
  dtls_hash_ctx hs_hash;
  unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];

  /* ServerKeyExchange
   *
   * Start message construction at beginning of buffer. */
  p = buf;

  copy_hs_hash(peer, &hs_hash);

  dtls_hash_finalize(sha256hash, &hs_hash);

  /* sign the ephemeral and its paramaters */
  dtls_ecdsa_create_sig_hash(key->priv_key, DTLS_EC_KEY_SIZE,
			     sha256hash, sizeof(sha256hash),
			     point_r, point_s);

  p = dtls_add_ecdsa_signature_elem(p, point_r, point_s);

  assert(p <= (buf + sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE_VERIFY,
				 buf, p - buf);
}
#endif /* DTLS_ECC */

static int
dtls_send_finished(dtls_context_t *ctx, dtls_peer_t *peer,
		   const unsigned char *label, size_t labellen)
{
  int length;
  uint8 hash[DTLS_HMAC_MAX];
  uint8 buf[DTLS_FIN_LENGTH];
  dtls_hash_ctx hs_hash;
  uint8 *p = buf;

  copy_hs_hash(peer, &hs_hash);

  length = dtls_hash_finalize(hash, &hs_hash);

  dtls_prf(peer->handshake_params->tmp.master_secret,
	   DTLS_MASTER_SECRET_LENGTH,
	   label, labellen,
	   PRF_LABEL(finished), PRF_LABEL_SIZE(finished),
	   hash, length,
	   p, DTLS_FIN_LENGTH);

  dtls_debug_dump("server finished MAC", p, DTLS_FIN_LENGTH);

  p += DTLS_FIN_LENGTH;

  assert((buf <= p) && ((unsigned int)(p - buf) <= sizeof(buf)));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_FINISHED,
				 buf, p - buf);
}

static int
dtls_send_client_hello(dtls_context_t *ctx, dtls_peer_t *peer,
                       uint8 cookie[], size_t cookie_length) {
  uint8 buf[DTLS_CH_LENGTH_MAX];
  uint8_t *p = buf;
  uint8_t *p_cipher_suites_size = NULL;
  uint8_t index = 0;
  uint8_t cipher_suites_size = 0;
  uint8_t extension_size = 4; /* extended master secret extension */
#ifdef DTLS_ECC
  uint8_t ecdsa = 0;
#endif
  dtls_handshake_parameters_t *handshake = peer->handshake_params;

  handshake->user_parameters = default_user_parameters;
  if (ctx->h->get_user_parameters != NULL) {
    ctx->h->get_user_parameters(ctx, &peer->session, &(handshake->user_parameters));
  }

  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  if (cookie_length > DTLS_COOKIE_LENGTH_MAX) {
    dtls_warn("the cookie is too long\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  if (cookie_length == 0) {
    /* Set 32 bytes of client random data */
    dtls_prng(handshake->tmp.random.client, DTLS_RANDOM_LENGTH);
  }
  /* we must use the same Client Random as for the previous request */
  memcpy(p, handshake->tmp.random.client, DTLS_RANDOM_LENGTH);
  p += DTLS_RANDOM_LENGTH;

  /* session id (length 0) */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  /* cookie */
  dtls_int_to_uint8(p, cookie_length);
  p += sizeof(uint8);
  if (cookie_length != 0) {
    memcpy(p, cookie, cookie_length);
    p += cookie_length;
  }

  /* keep pointer to size of cipher suites */
  p_cipher_suites_size = p;
  /* skip size of cipher suites field */
  p += sizeof(uint16);

  /* add known cipher(s) */
  for (index = 0; handshake->user_parameters.cipher_suites[index] != TLS_NULL_WITH_NULL_NULL; ++index) {
    dtls_cipher_t code = handshake->user_parameters.cipher_suites[index];
    dtls_cipher_index_t cipher_index = get_cipher_index(handshake->user_parameters.cipher_suites, code);
    if (known_cipher(ctx, cipher_index, 1)) {
      dtls_int_to_uint16(p, code);
      p += sizeof(uint16);
#ifdef DTLS_ECC
      ecdsa = ecdsa || is_key_exchange_ecdhe_ecdsa(cipher_index);
#endif /* DTLS_ECC */
    }
    /* ignore not supported cipher suite
       credentials callback is missing */
  }

  cipher_suites_size = (p - p_cipher_suites_size) - sizeof(uint16);
  if (cipher_suites_size == 0) {
    dtls_crit("no supported cipher suite provided!\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  /* RFC5746 add RENEGOTIATION_INFO_SCSV */
  dtls_int_to_uint16(p, TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
  p += sizeof(uint16);
  cipher_suites_size += sizeof(uint16);

  /* set size of known cipher suites */
  dtls_int_to_uint16(p_cipher_suites_size, cipher_suites_size);

#ifdef DTLS_ECC
  if (ecdsa) {
    /*
     * client_cert_type       := 6 bytes
     * server_cert_type       := 6 bytes
     * ec curves              := 8 bytes
     * ec point format        := 6 bytes
     * sign. and hash algos   := 8 bytes
     */
    extension_size += 6 + 6 + 8 + 6 + 8;
  }
#endif

  /* compression method */
  dtls_int_to_uint8(p, 1);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, TLS_COMPRESSION_NULL);
  p += sizeof(uint8);

  /* length of the extensions */
  dtls_int_to_uint16(p, extension_size);
  p += sizeof(uint16);

#ifdef DTLS_ECC
  if (ecdsa) {
    /* client certificate type extension, 6 bytes */
    dtls_int_to_uint16(p, TLS_EXT_CLIENT_CERTIFICATE_TYPE);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 2);
    p += sizeof(uint16);

    /* length of the list */
    dtls_int_to_uint8(p, 1);
    p += sizeof(uint8);

    dtls_int_to_uint8(p, TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    p += sizeof(uint8);

    /* server certificate type extension, 6 bytes */
    dtls_int_to_uint16(p, TLS_EXT_SERVER_CERTIFICATE_TYPE);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 2);
    p += sizeof(uint16);

    /* length of the list */
    dtls_int_to_uint8(p, 1);
    p += sizeof(uint8);

    dtls_int_to_uint8(p, TLS_CERT_TYPE_RAW_PUBLIC_KEY);
    p += sizeof(uint8);

    /* elliptic_curves, 8 bytes */
    dtls_int_to_uint16(p, TLS_EXT_ELLIPTIC_CURVES);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 4);
    p += sizeof(uint16);

    /* length of the list */
    dtls_int_to_uint16(p, 2);
    p += sizeof(uint16);

    dtls_int_to_uint16(p, TLS_EXT_ELLIPTIC_CURVES_SECP256R1);
    p += sizeof(uint16);

    /* ec_point_formats, 6 bytes */
    dtls_int_to_uint16(p, TLS_EXT_EC_POINT_FORMATS);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 2);
    p += sizeof(uint16);

    /* number of supported formats */
    dtls_int_to_uint8(p, 1);
    p += sizeof(uint8);

    dtls_int_to_uint8(p, TLS_EXT_EC_POINT_FORMATS_UNCOMPRESSED);
    p += sizeof(uint8);

    /* signature algorithms extension, 8 bytes */
    dtls_int_to_uint16(p, TLS_EXT_SIG_HASH_ALGO);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 4);
    p += sizeof(uint16);

    /* supported_signature_algorithms */
    dtls_int_to_uint16(p, 2);
    p += sizeof(uint16);

    /* sha256 */
    dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_SHA256);
    p += sizeof(uint8);

    /* ecdsa */
    dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_ECDSA);
    p += sizeof(uint8);

  }
#endif /* DTLS_ECC */

  /* extended master secret, 4 bytes */
  dtls_int_to_uint16(p, TLS_EXT_EXTENDED_MASTER_SECRET);
  p += sizeof(uint16);

  /* length of this extension type */
  dtls_int_to_uint16(p, 0);
  p += sizeof(uint16);
  handshake->extended_master_secret = 1;

  handshake->hs_state.read_epoch = dtls_security_params(peer)->epoch;
  assert((buf <= p) && ((unsigned int)(p - buf) <= sizeof(buf)));

  clear_hs_hash(peer);

  return dtls_send_handshake_msg_hash(ctx, peer, &peer->session,
				      DTLS_HT_CLIENT_HELLO,
				      buf, p - buf, 1);
}

static int
check_server_hello(dtls_context_t *ctx,
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length)
{
  dtls_handshake_parameters_t *handshake = peer->handshake_params;

  /*
   * Check we have enough data for the ServerHello
   *   2 bytes for the version number
   *   1 byte for the session id length
   *   2 bytes for the selected cipher suite
   *   1 byte null compression
   */
  if (data_length < DTLS_HS_LENGTH + 2 + DTLS_RANDOM_LENGTH + 1 + 2 + 1) {
    dtls_alert("Insufficient length for ServerHello\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  update_hs_hash(peer, data, data_length);

  /* Get the server's random data and store selected cipher suite
   * and compression method (like dtls_update_parameters().
   * Then calculate master secret and wait for ServerHelloDone. When received,
   * send ClientKeyExchange (?) and ChangeCipherSpec + ClientFinished. */

  /* check server version */
  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  if (dtls_uint16_to_int(data) != DTLS_VERSION) {
    dtls_alert("unknown DTLS version\n");
    return dtls_alert_fatal_create(DTLS_ALERT_PROTOCOL_VERSION);
  }

  data += sizeof(uint16);	      /* skip version field */
  data_length -= sizeof(uint16);

  /* store server random data */
  memcpy(handshake->tmp.random.server, data, DTLS_RANDOM_LENGTH);
  /* skip server random */
  data += DTLS_RANDOM_LENGTH;
  data_length -= DTLS_RANDOM_LENGTH;

  /* skip session_id */
  SKIP_VAR_FIELD(data, data_length, uint8, DTLS_ALERT_DECODE_ERROR,
                 "ServerHello, session_id");
  /*
   * Need to re-check in case session id was not empty
   *   2 bytes for the selected cipher suite
   *   1 byte null compression
   */
  if (data_length < 2 + 1) {
    dtls_alert("Insufficient length for ServerHello\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  /* Check if the cipher suite selected by the server
   *  is in our list of cipher suites. */
  handshake->cipher_index = get_cipher_index(handshake->user_parameters.cipher_suites, dtls_uint16_to_int(data));

  if (!known_cipher(ctx, handshake->cipher_index, 1)) {
    dtls_alert("unsupported cipher 0x%02x 0x%02x\n", data[0], data[1]);
    handshake->cipher_index = DTLS_CIPHER_INDEX_NULL;
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);
  }

  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  /* Check if NULL compression was selected. We do not know any other. */
  if (dtls_uint8_to_int(data) != TLS_COMPRESSION_NULL) {
    dtls_alert("unsupported compression method 0x%02x\n", data[0]);
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  /* Server may not support extended master secret */
  handshake->extended_master_secret = 0;
  return dtls_check_tls_extension(peer, data, data_length, 0);
}

static int
check_server_hello_verify_request(dtls_context_t *ctx,
				  dtls_peer_t *peer,
				  uint8 *data, size_t data_length)
{
  dtls_hello_verify_t *hv;
  int res;

  if (data_length < DTLS_HS_LENGTH + DTLS_HV_LENGTH)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  hv = (dtls_hello_verify_t *)(data + DTLS_HS_LENGTH);
  if (data_length < DTLS_HS_LENGTH + DTLS_HV_LENGTH + hv->cookie_length)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  res = dtls_send_client_hello(ctx, peer, hv->cookie, hv->cookie_length);

  if (res < 0)
    dtls_warn("cannot send ClientHello\n");

  return res;
}

#ifdef DTLS_ECC
static int
check_server_certificate(dtls_context_t *ctx,
			 dtls_peer_t *peer,
			 uint8 *data, size_t data_length)
{
  int err;
  dtls_handshake_parameters_t *config = peer->handshake_params;

  update_hs_hash(peer, data, data_length);

  assert(is_key_exchange_ecdhe_ecdsa(config->cipher_index));

  data += DTLS_HS_LENGTH;

  if (dtls_uint24_to_int(data) != DTLS_EC_SUBJECTPUBLICKEY_SIZE) {
    dtls_alert("expect length of %zu bytes for certificate\n",
	       DTLS_EC_SUBJECTPUBLICKEY_SIZE);
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint24);

  if (memcmp(data, cert_asn1_header, sizeof(cert_asn1_header))) {
    dtls_alert("got an unexpected Subject public key format\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(cert_asn1_header);

  memcpy(config->keyx.ecdsa.other_pub_x, data,
	 sizeof(config->keyx.ecdsa.other_pub_x));
  data += sizeof(config->keyx.ecdsa.other_pub_x);

  memcpy(config->keyx.ecdsa.other_pub_y, data,
	 sizeof(config->keyx.ecdsa.other_pub_y));
  data += sizeof(config->keyx.ecdsa.other_pub_y);

  err = CALL(ctx, verify_ecdsa_key, &peer->session,
	     config->keyx.ecdsa.other_pub_x,
	     config->keyx.ecdsa.other_pub_y,
	     sizeof(config->keyx.ecdsa.other_pub_x));
  if (err < 0) {
    dtls_info("The server certificate was not accepted\n");
    return err;
  }

  return 0;
}

static int
check_server_key_exchange_ecdsa(dtls_context_t *ctx,
				dtls_peer_t *peer,
				uint8 *data, size_t data_length)
{
  (void) ctx;
  dtls_handshake_parameters_t *config = peer->handshake_params;
  int ret;
  unsigned char result_r[DTLS_EC_KEY_SIZE];
  unsigned char result_s[DTLS_EC_KEY_SIZE];
  unsigned char *key_params;

  update_hs_hash(peer, data, data_length);

  assert(is_key_exchange_ecdhe_ecdsa(config->cipher_index));

  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  if (data_length < DTLS_SKEXEC_LENGTH - 2 * DTLS_EC_KEY_SIZE) {
    /*
     * Some of the ASN.1 integer in the signature may be less than
     * DTLS_EC_KEY_SIZE if leading bits are 0.
     * dtls_check_ecdsa_signature_elem() knows how to handle this undersize.
     */
    dtls_alert("the packet length does not match the expected\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  key_params = data;

  if (dtls_uint8_to_int(data) != TLS_EC_CURVE_TYPE_NAMED_CURVE) {
    dtls_alert("only named curves supported\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint16_to_int(data) != TLS_EXT_ELLIPTIC_CURVES_SECP256R1) {
    dtls_alert("only secp256r1 supported\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (dtls_uint8_to_int(data) != 1 + 2 * DTLS_EC_KEY_SIZE) {
    dtls_alert("expected 65 bytes long public point\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint8_to_int(data) != 4) {
    dtls_alert("expected uncompressed public point\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  memcpy(config->keyx.ecdsa.other_eph_pub_x, data, sizeof(config->keyx.ecdsa.other_eph_pub_y));
  data += sizeof(config->keyx.ecdsa.other_eph_pub_y);
  data_length -= sizeof(config->keyx.ecdsa.other_eph_pub_y);

  memcpy(config->keyx.ecdsa.other_eph_pub_y, data, sizeof(config->keyx.ecdsa.other_eph_pub_y));
  data += sizeof(config->keyx.ecdsa.other_eph_pub_y);
  data_length -= sizeof(config->keyx.ecdsa.other_eph_pub_y);

  ret = dtls_check_ecdsa_signature_elem(data, data_length, result_r, result_s);
  if (ret < 0) {
    return ret;
  }
  data += ret;
  data_length -= ret;

  ret = dtls_ecdsa_verify_sig(config->keyx.ecdsa.other_pub_x, config->keyx.ecdsa.other_pub_y,
			    sizeof(config->keyx.ecdsa.other_pub_x),
			    config->tmp.random.client, DTLS_RANDOM_LENGTH,
			    config->tmp.random.server, DTLS_RANDOM_LENGTH,
			    key_params,
			    1 + 2 + 1 + 1 + (2 * DTLS_EC_KEY_SIZE),
			    result_r, result_s);

  if (ret < 0) {
    dtls_alert("server key exchange wrong signature\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  return 0;
}
#endif /* DTLS_ECC */

#ifdef DTLS_PSK
static int
check_server_key_exchange_psk(dtls_context_t *ctx,
			      dtls_peer_t *peer,
			      uint8 *data, size_t data_length)
{
  dtls_handshake_parameters_t *config = peer->handshake_params;
  uint16_t len;
  (void)ctx;

  update_hs_hash(peer, data, data_length);

  assert(is_key_exchange_psk(config->cipher_index));

  data += DTLS_HS_LENGTH;

  if (data_length < DTLS_HS_LENGTH + DTLS_SKEXECPSK_LENGTH_MIN) {
    dtls_alert("the packet length does not match the expected\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  len = dtls_uint16_to_int(data);
  data += sizeof(uint16);

  if (len != data_length - DTLS_HS_LENGTH - sizeof(uint16)) {
    dtls_warn("the length of the server identity hint is worng\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  if (len > DTLS_PSK_MAX_CLIENT_IDENTITY_LEN) {
    dtls_warn("please use a smaller server identity hint\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  /* store the psk_identity_hint in config->keyx.psk for later use */
  config->keyx.psk.id_length = len;
  memcpy(config->keyx.psk.identity, data, len);
  return 0;
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC

static int
check_certificate_request(dtls_context_t *ctx,
			  dtls_peer_t *peer,
			  uint8 *data, size_t data_length)
{
  unsigned int i;
  int auth_alg;
  int sig_alg;
  int hash_alg;
  (void)ctx;

  update_hs_hash(peer, data, data_length);

  assert(is_key_exchange_ecdhe_ecdsa(peer->handshake_params->cipher_index));

  if (data_length < DTLS_HS_LENGTH + 5) {
    dtls_alert("the packet length does not match the expected\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }

  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  GET_VAR_FIELD(i, data, data_length, uint8, DTLS_ALERT_DECODE_ERROR,
                "CertificateRequest, certificate_types");

  auth_alg = 0;
  for (; i > 0 ; i -= sizeof(uint8)) {
    if (dtls_uint8_to_int(data) == TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN) {
      auth_alg = TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN;
      /* skip the rest of the field value */
      data += i;
      data_length -=i;
      break;
    }
    data += sizeof(uint8);
    data_length -= sizeof(uint8);
  }

  if (auth_alg != TLS_CLIENT_CERTIFICATE_TYPE_ECDSA_SIGN) {
    dtls_alert("the request authentication algorithm is not supported\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  GET_VAR_FIELD(i, data, data_length, uint16, DTLS_ALERT_DECODE_ERROR,
                "CertificateRequest, signature_algorithms");

  hash_alg = 0;
  sig_alg = 0;

  /* Signal error if we do not have an even number of remaining
   * bytes. */
  if ((i & 1) != 0) {
    dtls_alert("illegal certificate request\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  for (; i >= sizeof(uint16); i -= sizeof(uint16)) {
    int current_hash_alg;
    int current_sig_alg;

    current_hash_alg = dtls_uint8_to_int(data);
    data += sizeof(uint8);
    current_sig_alg = dtls_uint8_to_int(data);
    data += sizeof(uint8);

    data_length -= sizeof(uint16);

    if (current_hash_alg == TLS_EXT_SIG_HASH_ALGO_SHA256 && hash_alg == 0 &&
        current_sig_alg == TLS_EXT_SIG_HASH_ALGO_ECDSA && sig_alg == 0) {
      hash_alg = current_hash_alg;
      sig_alg = current_sig_alg;
      break;
    }
  }

  if (hash_alg != TLS_EXT_SIG_HASH_ALGO_SHA256 ||
      sig_alg != TLS_EXT_SIG_HASH_ALGO_ECDSA) {
    dtls_alert("no supported hash and signature algorithm\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  /* common names are ignored */

  peer->handshake_params->do_client_auth = 1;
  return 0;
}
#endif /* DTLS_ECC */

static int
check_server_hellodone(dtls_context_t *ctx,
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length)
{
  int res;
#ifdef DTLS_ECC
  const dtls_ecdsa_key_t *ecdsa_key;
#endif /* DTLS_ECC */

  dtls_handshake_parameters_t *handshake = peer->handshake_params;

  /* calculate master key, send CCS */

  update_hs_hash(peer, data, data_length);

#ifdef DTLS_ECC
  if (handshake->do_client_auth) {

    res = CALL(ctx, get_ecdsa_key, &peer->session, &ecdsa_key);
    if (res < 0) {
      dtls_warn("no ecdsa certificate to send in certificate\n");
      res = dtls_send_certificate_empty(ctx, peer);
      handshake->do_client_auth = 0;
    } else {
      res = dtls_send_certificate_ecdsa(ctx, peer, ecdsa_key);
    }
    if (res < 0) {
      dtls_debug("dtls_server_hello: cannot prepare Certificate record\n");
      return res;
    }
  }
#endif /* DTLS_ECC */

  /* send ClientKeyExchange */
  res = dtls_send_client_key_exchange(ctx, peer);

  if (res < 0) {
    dtls_debug("cannot send KeyExchange message\n");
    return res;
  }

#ifdef DTLS_ECC
  if (handshake->do_client_auth) {

    res = dtls_send_certificate_verify_ecdh(ctx, peer, ecdsa_key);

    if (res < 0) {
      dtls_debug("dtls_server_hello: cannot prepare Certificate record\n");
      return res;
    }
  }
#endif /* DTLS_ECC */

  res = calculate_key_block(ctx, handshake, peer,
			    &peer->session, peer->role);
  if (res < 0) {
    return res;
  }

  res = dtls_send_ccs(ctx, peer);
  if (res < 0) {
    dtls_debug("cannot send CCS message\n");
    return res;
  }

  /* and switch cipher suite */
  dtls_security_params_switch(peer);

  /* Client Finished */
  return dtls_send_finished(ctx, peer, PRF_LABEL(client), PRF_LABEL_SIZE(client));
}

static int
decrypt_verify(dtls_peer_t *peer, uint8 *packet, size_t length,
	       uint8 **cleartext)
{
  dtls_record_header_t *header = DTLS_RECORD_HEADER(packet);
  dtls_security_parameters_t *security = dtls_security_params_read_epoch(peer, dtls_get_epoch(header));
  int clen;

  *cleartext = (uint8 *)packet + sizeof(dtls_record_header_t);
  clen = length - sizeof(dtls_record_header_t);

  if (!security) {
    dtls_alert("No security context for epoch: %i\n", dtls_get_epoch(header));
    return -1;
  }

  if (security->cipher_index == DTLS_CIPHER_INDEX_NULL) {
    /* no cipher suite selected */
    return clen;
  } else { /* TLS_PSK_WITH_AES_128_CCM_8, TLS_PSK_WITH_AES_128_CCM,
              TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 or
              TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
    /**
     * length of additional_data for the AEAD cipher which consists of
     * seq_num(2+6) + type(1) + version(2) + length(2)
     */
#define A_DATA_LEN 13
    unsigned char nonce[DTLS_CCM_BLOCKSIZE];
    unsigned char A_DATA[A_DATA_LEN];
    const uint8_t mac_len = get_cipher_suite_mac_len(security->cipher_index);
    /* For backwards-compatibility, dtls_encrypt_params is called with
     * M=<macLen> and L=3. */
    const dtls_ccm_params_t params = { nonce, mac_len, 3 };

    if (clen < 8 + mac_len)		/* need at least IV and MAC */
      return -1;

    memset(nonce, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(nonce, dtls_kb_remote_iv(security, peer->role),
	   dtls_kb_iv_size(security, peer->role));

    /* read epoch and seq_num from message */
    memcpy(nonce + dtls_kb_iv_size(security, peer->role), *cleartext, 8);
    *cleartext += 8;
    clen -= 8; /* length without nonce_explicit */

    dtls_debug_dump("nonce", nonce, DTLS_CCM_BLOCKSIZE);
    dtls_debug_dump("key", dtls_kb_remote_write_key(security, peer->role),
		    dtls_kb_key_size(security, peer->role));
    dtls_debug_dump("ciphertext", *cleartext, clen);

    /* re-use N to create additional data according to RFC 5246, Section 6.2.3.3:
     *
     * additional_data = seq_num + TLSCompressed.type +
     *                   TLSCompressed.version + TLSCompressed.length;
     */
    memcpy(A_DATA, &DTLS_RECORD_HEADER(packet)->epoch, 8); /* epoch and seq_num */
    memcpy(A_DATA + 8,  &DTLS_RECORD_HEADER(packet)->content_type, 3); /* type and version */

    dtls_int_to_uint16(A_DATA + 11, clen - mac_len); /* length without MAC */

    clen = dtls_decrypt_params(&params, *cleartext, clen, *cleartext,
               dtls_kb_remote_write_key(security, peer->role),
               dtls_kb_key_size(security, peer->role),
               A_DATA, A_DATA_LEN);
    if (clen < 0)
      dtls_warn("decryption failed\n");
    else {
      dtls_debug("decrypt_verify(): found %i bytes cleartext\n", clen);
      dtls_security_params_free_other(peer);
      dtls_debug_dump("cleartext", *cleartext, clen);
    }
  }
  return clen;
}

/**
 * Process verified ClientHellos.
 *
 * For a verified ClientHello a peer is available/created. This function
 * returns the number of bytes that were sent, or \c -1 if an error occurred.
 *
 * \param ctx          The DTLS context to use.
 * \param peer         The remote peer to exchange the handshake messages.
 * \param data         The data of the ClientHello containing the proposed crypto parameter.
 * \param data_length  The actual length of \p data.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static int
handle_verified_client_hello(dtls_context_t *ctx, dtls_peer_t *peer,
		uint8 *data, size_t data_length) {

  clear_hs_hash(peer);

  /* First negotiation step: check for PSK
   *
   * Note that we already have checked that msg is a Handshake
   * message containing a ClientHello. dtls_get_cipher() therefore
   * does not check again.
   */
  int err = dtls_update_parameters(ctx, peer, data, data_length);
  if (err < 0) {
    dtls_warn("error updating security parameters\n");
    return err;
  }

  /* update finish MAC */
  update_hs_hash(peer, data, data_length);

  err = dtls_send_server_hello_msgs(ctx, peer);
  if (err < 0) {
    return err;
  }
  if (is_key_exchange_ecdhe_ecdsa(peer->handshake_params->cipher_index) &&
		  is_ecdsa_client_auth_supported(ctx))
    peer->state = DTLS_STATE_WAIT_CLIENTCERTIFICATE;
  else
    peer->state = DTLS_STATE_WAIT_CLIENTKEYEXCHANGE;

  return err;
}

static int
handle_handshake_msg(dtls_context_t *ctx, dtls_peer_t *peer, uint8 *data, size_t data_length) {

  int err = 0;
  const dtls_peer_type role = peer->role;
  const dtls_state_t state = peer->state;
  const cipher_suite_key_exchange_algorithm_t key_exchange_algorithm =
              get_key_exchange_algorithm(peer->handshake_params->cipher_index);

  /* This will clear the retransmission buffer if we get an expected
   * handshake message. We have to make sure that no handshake message
   * should get expected when we still should retransmit something, when
   * we do everything accordingly to the DTLS 1.2 standard this should
   * not be a problem. */
  dtls_stop_retransmission(ctx, peer);

  /* The following switch construct handles the given message with
   * respect to the current internal state for this peer. In case of
   * error, it is left with return 0. */

  dtls_debug("handle handshake packet of type: %s (%i)\n",
	     dtls_handshake_type_to_name(data[0]), data[0]);
  switch (data[0]) {

  /************************************************************************
   * Client states
   ************************************************************************/
  case DTLS_HT_HELLO_VERIFY_REQUEST:

    if (state != DTLS_STATE_CLIENTHELLO) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_server_hello_verify_request(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_server_hello_verify_request err: %i\n", err);
      return err;
    }

    break;
  case DTLS_HT_SERVER_HELLO:

    if (state != DTLS_STATE_CLIENTHELLO) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_server_hello(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_server_hello err: %i\n", err);
      return err;
    }
    /* check_server_hello sets the cipher_index */
    if (is_key_exchange_ecdhe_ecdsa(peer->handshake_params->cipher_index))
      peer->state = DTLS_STATE_WAIT_SERVERCERTIFICATE;
    else {
      peer->optional_handshake_message = DTLS_HT_SERVER_KEY_EXCHANGE;
      peer->state = DTLS_STATE_WAIT_SERVERHELLODONE;
    }
    /* update_hs_hash(peer, data, data_length); */

    break;

#ifdef DTLS_ECC
  case DTLS_HT_CERTIFICATE:

    if ((role == DTLS_CLIENT && state != DTLS_STATE_WAIT_SERVERCERTIFICATE) ||
        (role == DTLS_SERVER && state != DTLS_STATE_WAIT_CLIENTCERTIFICATE)) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }
    err = check_server_certificate(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_server_certificate err: %i\n", err);
      return err;
    }
    if (role == DTLS_CLIENT) {
      peer->state = DTLS_STATE_WAIT_SERVERKEYEXCHANGE;
    } else if (role == DTLS_SERVER){
      peer->state = DTLS_STATE_WAIT_CLIENTKEYEXCHANGE;
    }
    /* update_hs_hash(peer, data, data_length); */

    break;
#endif /* DTLS_ECC */

  case DTLS_HT_SERVER_KEY_EXCHANGE:
    if (state != DTLS_STATE_WAIT_SERVERKEYEXCHANGE &&
        state != DTLS_STATE_WAIT_SERVERHELLODONE) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

#ifdef DTLS_ECC
    if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_ECDHE_ECDSA) {
      if (state != DTLS_STATE_WAIT_SERVERKEYEXCHANGE) {
        return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
      }
      peer->optional_handshake_message = DTLS_HT_CERTIFICATE_REQUEST;
      err = check_server_key_exchange_ecdsa(ctx, peer, data, data_length);
    }
#endif /* DTLS_ECC */
#ifdef DTLS_PSK
    if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_PSK) {
      if (state != DTLS_STATE_WAIT_SERVERHELLODONE ||
          peer->optional_handshake_message != DTLS_HT_SERVER_KEY_EXCHANGE) {
        return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
      }
      peer->optional_handshake_message = DTLS_HT_NO_OPTIONAL_MESSAGE;
      err = check_server_key_exchange_psk(ctx, peer, data, data_length);
    }
#endif /* DTLS_PSK */

    if (err < 0) {
      dtls_warn("error in check_server_key_exchange err: %i\n", err);
      return err;
    }
    peer->state = DTLS_STATE_WAIT_SERVERHELLODONE;
    /* update_hs_hash(peer, data, data_length); */

    break;

  case DTLS_HT_SERVER_HELLO_DONE:

    if (state != DTLS_STATE_WAIT_SERVERHELLODONE) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_server_hellodone(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_server_hellodone err: %i\n", err);
      return err;
    }
    peer->state = DTLS_STATE_WAIT_CHANGECIPHERSPEC;
    /* update_hs_hash(peer, data, data_length); */

    break;

#ifdef DTLS_ECC
  case DTLS_HT_CERTIFICATE_REQUEST:

    if (state != DTLS_STATE_WAIT_SERVERHELLODONE ||
        peer->optional_handshake_message != DTLS_HT_CERTIFICATE_REQUEST ||
        key_exchange_algorithm != DTLS_KEY_EXCHANGE_ECDHE_ECDSA) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }
    peer->optional_handshake_message = DTLS_HT_NO_OPTIONAL_MESSAGE;
    err = check_certificate_request(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_certificate_request err: %i\n", err);
      return err;
    }

    break;
#endif /* DTLS_ECC */

  case DTLS_HT_FINISHED:
    /* expect a Finished message from server */

    if (state != DTLS_STATE_WAIT_FINISHED) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_finished(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_finished err: %i\n", err);
      return err;
    }
    if (role == DTLS_SERVER) {
      /* send ServerFinished */
      update_hs_hash(peer, data, data_length);

      /* send change cipher spec message and switch to new configuration */
      err = dtls_send_ccs(ctx, peer);
      if (err < 0) {
        dtls_warn("cannot send CCS message\n");
        return err;
      }

      dtls_security_params_switch(peer);

      err = dtls_send_finished(ctx, peer, PRF_LABEL(server), PRF_LABEL_SIZE(server));
      if (err < 0) {
        dtls_warn("sending server Finished failed\n");
        return err;
      }
    }
    dtls_handshake_free(peer->handshake_params);
    peer->handshake_params = NULL;
    dtls_debug("Handshake complete\n");
    check_stack();
    peer->state = DTLS_STATE_CONNECTED;

    /* return here to not increase the message receive counter */
    return err;

  /************************************************************************
   * Server states
   ************************************************************************/

  case DTLS_HT_CLIENT_KEY_EXCHANGE:
    /* handle ClientHello, update msg and msglen and goto next if not finished */

    if (state != DTLS_STATE_WAIT_CLIENTKEYEXCHANGE) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_client_keyexchange(ctx, peer->handshake_params, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_client_keyexchange err: %i\n", err);
      return err;
    }
    update_hs_hash(peer, data, data_length);

    /* Keep hash information for extended master secret */
    memcpy(&peer->handshake_params->hs_state.ext_hash,
           &peer->handshake_params->hs_state.hs_hash,
	   sizeof(peer->handshake_params->hs_state.ext_hash));

    if (key_exchange_algorithm == DTLS_KEY_EXCHANGE_ECDHE_ECDSA &&
        is_ecdsa_client_auth_supported(ctx))
      peer->state = DTLS_STATE_WAIT_CERTIFICATEVERIFY;
    else
      peer->state = DTLS_STATE_WAIT_CHANGECIPHERSPEC;
    break;

#ifdef DTLS_ECC
  case DTLS_HT_CERTIFICATE_VERIFY:

    if (state != DTLS_STATE_WAIT_CERTIFICATEVERIFY) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    err = check_client_certificate_verify(ctx, peer, data, data_length);
    if (err < 0) {
      dtls_warn("error in check_client_certificate_verify err: %i\n", err);
      return err;
    }

    update_hs_hash(peer, data, data_length);
    peer->state = DTLS_STATE_WAIT_CHANGECIPHERSPEC;
    break;
#endif /* DTLS_ECC */

  case DTLS_HT_CLIENT_HELLO:

    if (state != DTLS_STATE_CONNECTED) {
      return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
    }

    /* At this point, we have a good relationship with this peer. This
     * state is left for re-negotiation of key material. */
     /* As per RFC 6347 - section 4.2.8 if this is an attempt to
      * rehandshake, we can delete the existing key material
      * as the client has demonstrated reachibility by completing
      * the cookie exchange */
    if (!peer->handshake_params) {
      dtls_handshake_header_t *hs_header = DTLS_HANDSHAKE_HEADER(data);

      peer->handshake_params = dtls_handshake_new();
      if (!peer->handshake_params)
        return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);

      peer->handshake_params->hs_state.mseq_r = dtls_uint16_to_int(hs_header->message_seq);
      peer->handshake_params->hs_state.mseq_s = 1;
      peer->handshake_params->hs_state.read_epoch = dtls_security_params(peer)->epoch;
    }
    err = handle_verified_client_hello(ctx, peer, data, data_length);

    /* after sending the ServerHelloDone, we expect the
     * ClientKeyExchange (possibly containing the PSK id),
     * followed by a ChangeCipherSpec and an encrypted Finished.
     */

    break;

  case DTLS_HT_HELLO_REQUEST:

    if (state != DTLS_STATE_CONNECTED) {
      /* we should just ignore such packets when in handshake */
      return 0;
    }

    dtls_warn("renegotiation is not supported!\n");
    /* RFC5246, 7.2.2. Error Alerts, "no_renegotiation" is always a warning */
    return dtls_alert_create(DTLS_ALERT_LEVEL_WARNING, DTLS_ALERT_NO_RENEGOTIATION);

  default:
    dtls_crit("unhandled message %d\n", data[0]);
    return dtls_alert_fatal_create(DTLS_ALERT_UNEXPECTED_MESSAGE);
  }

  if (peer->handshake_params && err >= 0) {
    peer->handshake_params->hs_state.mseq_r++;
  }

  return err;
}

/**
 * Process verified ClientHellos of epoch 0.
 *
 * This function returns the number of bytes that were sent, or less than zero
 * if an error occurred.
 *
 * \param ctx              The DTLS context to use.
 * \param ephemeral_peer   The ephemeral remote peer.
 * \param data             The data received.
 * \param data_length      The actual length of \p buf.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static int
handle_0_verified_client_hello(dtls_context_t *ctx,
         dtls_ephemeral_peer_t *ephemeral_peer,
         uint8 *data, size_t data_length) {
  int err;

  dtls_peer_t *peer = dtls_get_peer(ctx, ephemeral_peer->session);
  if (peer) {
     dtls_debug("removing the peer, new handshake\n");
     dtls_destroy_peer(ctx, peer, 0);
     peer = NULL;
  }
  dtls_debug("creating new peer\n");

  /* msg contains a ClientHello with a valid cookie, so we can
   * safely create the server state machine and continue with
   * the handshake. */
  peer = dtls_new_peer(ephemeral_peer->session);
  if (!peer) {
    dtls_alert("cannot create peer\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }
  peer->role = DTLS_SERVER;

  dtls_security_parameters_t *security = dtls_security_params(peer);
  security->rseq = ephemeral_peer->rseq;
  security->cseq.cseq = ephemeral_peer->rseq;
  /* bitfield. B0 last seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
  /* => set all, older "stateless records" will be duplicates. */
  security->cseq.bitfield = (uint64_t) -1L;

  if (dtls_add_peer(ctx, peer) < 0) {
    dtls_alert("cannot add peer\n");
    dtls_free_peer(peer);
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  peer->handshake_params = dtls_handshake_new();
  if (!peer->handshake_params) {
    dtls_alert("cannot create handshake parameter\n");
    DEL_PEER(ctx->peers, peer);
    dtls_free_peer(peer);
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  peer->handshake_params->hs_state.read_epoch = dtls_security_params(peer)->epoch;
  peer->handshake_params->hs_state.mseq_r = ephemeral_peer->mseq;
  peer->handshake_params->hs_state.mseq_s = ephemeral_peer->mseq;

  err = handle_verified_client_hello(ctx, peer, data, data_length);
  if (err < 0) {
    dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
    return err;
  }

  peer->handshake_params->hs_state.mseq_r++;

  return err;
}

/**
 * Process initial ClientHello of epoch 0.
 *
 * In order to protect against "denial of service" attacks, RFC6347
 * contains in https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
 * the advice to process initial a ClientHello in a stateless fashion.
 * If a ClientHello doesn't provide a matching cookie, a HelloVerifyRequest
 * is sent back based on the record and handshake message sequence numbers
 * contained in the \p ephemeral_peer. If a matching cookie is provided,
 * the server starts the handshake, also based on the record and handshake
 * message sequence numbers contained in the \p ephemeral_peer. This function
 * returns the number of bytes that were sent, or \c -1 if an error occurred.
 *
 * \param ctx              The DTLS context to use.
 * \param ephemeral_peer   The ephemeral remote peer.
 * \param data             The data to send.
 * \param data_length      The actual length of \p buf.
 * \return Less than zero on error, the number of bytes written otherwise.
 */
static int
handle_0_client_hello(dtls_context_t *ctx, dtls_ephemeral_peer_t *ephemeral_peer,
         uint8 *data, size_t data_length)
{
  dtls_handshake_header_t *hs_header;
  size_t packet_length;
  size_t fragment_length;
  size_t fragment_offset;
  int err;

  hs_header = DTLS_HANDSHAKE_HEADER(data);

  dtls_debug("received initial client hello\n");

  packet_length = dtls_uint24_to_int(hs_header->length);
  fragment_length = dtls_uint24_to_int(hs_header->fragment_length);
  fragment_offset = dtls_uint24_to_int(hs_header->fragment_offset);
  if (packet_length != fragment_length || fragment_offset != 0) {
    dtls_warn("No fragment support (yet)\n");
    return 0;
  }
  if (fragment_length + DTLS_HS_LENGTH != data_length) {
    dtls_warn("Fragment size does not match packet size\n");
    return 0;
  }
  ephemeral_peer->mseq = dtls_uint16_to_int(hs_header->message_seq);
  err = dtls_0_verify_peer(ctx, ephemeral_peer, data, data_length);
  if (err < 0) {
    dtls_warn("error in dtls_verify_peer err: %i\n", err);
    return err;
  }

  if (err > 0) {
    dtls_debug("server hello verify was sent\n");
    return err;
  }

  err = handle_0_verified_client_hello(ctx, ephemeral_peer, data, data_length);
  if (err < 0) {
    dtls_0_send_alert_from_err(ctx, ephemeral_peer, err);
  }
  return err;
}

static int
handle_handshake(dtls_context_t *ctx, dtls_peer_t *peer, uint8 *data, size_t data_length)
{
  dtls_handshake_header_t *hs_header;
  int res;
  size_t packet_length;
  size_t fragment_length;
  size_t fragment_offset;

  assert(peer);

  if (data_length < DTLS_HS_LENGTH) {
    dtls_warn("handshake message too short\n");
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  }
  hs_header = DTLS_HANDSHAKE_HEADER(data);

  dtls_debug("received handshake packet of type: %s (%i)\n",
             dtls_handshake_type_to_name(hs_header->msg_type),
             hs_header->msg_type);

  packet_length = dtls_uint24_to_int(hs_header->length);
  fragment_length = dtls_uint24_to_int(hs_header->fragment_length);
  fragment_offset = dtls_uint24_to_int(hs_header->fragment_offset);
  if (packet_length != fragment_length || fragment_offset != 0) {
    dtls_warn("No fragment support (yet)\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }
  if (fragment_length + DTLS_HS_LENGTH != data_length) {
    dtls_warn("Fragment size does not match packet size\n");
    return dtls_alert_fatal_create(DTLS_ALERT_HANDSHAKE_FAILURE);
  }

  if (!peer->handshake_params) {

    dtls_warn("ignore unexpected handshake message\n");
    return 0;
  }
  uint16_t mseq = dtls_uint16_to_int(hs_header->message_seq);
  if (mseq < peer->handshake_params->hs_state.mseq_r) {
    dtls_warn("The message sequence number is too small, expected %i, got: %i\n",
	      peer->handshake_params->hs_state.mseq_r, mseq);
    return 0;
  } else if (mseq > peer->handshake_params->hs_state.mseq_r) {
    /* A packet in between is missing, buffer this packet. */
    netq_t *n;

    dtls_info("The message sequence number is too larger, expected %i, got: %i\n",
	      peer->handshake_params->hs_state.mseq_r, mseq);

    /* TODO: only add packet that are not too new. */
    if (data_length > DTLS_MAX_BUF) {
      dtls_warn("the packet is too big to buffer for reoder\n");
      return 0;
    }

    netq_t *node = netq_head(&peer->handshake_params->reorder_queue);
    while (node) {
      dtls_handshake_header_t *node_header = DTLS_HANDSHAKE_HEADER(node->data);
      if (dtls_uint16_to_int(node_header->message_seq) == mseq) {
        dtls_warn("a packet with this sequence number is already stored\n");
        return 0;
      }
      node = netq_next(node);
    }

    n = netq_node_new(data_length);
    if (!n) {
      dtls_warn("no space in reorder buffer\n");
      return 0;
    }

    n->peer = peer;
    n->length = data_length;
    memcpy(n->data, data, data_length);

    if (!netq_insert_node(&peer->handshake_params->reorder_queue, n)) {
      dtls_warn("cannot add packet to reorder buffer\n");
      netq_node_free(n);
    }
    dtls_info("Added packet %u for reordering\n", mseq);
    return 0;
  } else if (mseq == peer->handshake_params->hs_state.mseq_r) {
    /* Found the expected packet, use this and all the buffered packet */
    int next = 1;

    res = handle_handshake_msg(ctx, peer, data, data_length);
    if (res < 0)
      return res;

    /* We do not know in which order the packet are in the list just search the list for every packet. */
    while (next && peer->handshake_params) {
      next = 0;
      netq_t *node = netq_head(&peer->handshake_params->reorder_queue);
      while (node) {
        dtls_handshake_header_t *node_header = DTLS_HANDSHAKE_HEADER(node->data);

        if (dtls_uint16_to_int(node_header->message_seq) == peer->handshake_params->hs_state.mseq_r) {
          netq_remove(&peer->handshake_params->reorder_queue, node);
          next = 1;
          res = handle_handshake_msg(ctx, peer, node->data, node->length);

          /* free message data */
          netq_node_free(node);

          if (res < 0) {
            return res;
          }

          break;
        } else {
          node = netq_next(node);
        }
      }
    }
    return res;
  }
  assert(0);
  return 0;
}

static int
handle_ccs(dtls_context_t *ctx, dtls_peer_t *peer,
	   uint8 *record_header, uint8 *data, size_t data_length)
{
  int err;
  (void)record_header;

  assert(peer);

  /* A CCS message is handled after a KeyExchange message was
   * received from the client. When security parameters have been
   * updated successfully and a ChangeCipherSpec message was sent
   * by ourself, the security context is switched and the record
   * sequence number is reset. */

  if (peer->state != DTLS_STATE_WAIT_CHANGECIPHERSPEC) {
    dtls_warn("unexpected ChangeCipherSpec during handshake\n");
    return 0;
  }

  if (data_length != 1 || data[0] != 1)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  /* Just change the cipher when we are on the same epoch */
  if (peer->role == DTLS_SERVER) {
    err = calculate_key_block(ctx, peer->handshake_params, peer,
			      &peer->session, peer->role);
    if (err < 0) {
      return err;
    }
  }

  peer->handshake_params->hs_state.read_epoch++;
  assert(peer->handshake_params->hs_state.read_epoch > 0);
  peer->state = DTLS_STATE_WAIT_FINISHED;

  return 0;
}

/**
 * Handles incoming Alert messages. This function returns \c 1 if the
 * connection should be closed and the peer is to be invalidated.
 * \c 0 if the Alert is valid, but not closing the connection.
 * Less than \c 0 if the Alert could not be decoded.
 */
static int
handle_alert(dtls_context_t *ctx, dtls_peer_t *peer,
	     uint8 *record_header, uint8 *data, size_t data_length) {
  int free_peer = 0;		/* indicates whether to free peer */
  int close_notify = 0;
  (void)record_header;

  assert(peer);

  if (data_length < 2)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);

  dtls_info("** Alert: level %d, description %d\n", data[0], data[1]);

  /* The peer object is invalidated for FATAL alerts and close
   * notifies. This is done in two steps.: First, remove the object
   * from our list of peers. After that, the event handler callback is
   * invoked with the still existing peer object. Finally, the storage
   * used by peer is released.
   */
  close_notify = data[1] == DTLS_ALERT_CLOSE_NOTIFY;
  if (data[0] == DTLS_ALERT_LEVEL_FATAL || close_notify) {
    if (close_notify)
      dtls_info("invalidate peer (Close Notify)\n");
    else
      dtls_alert("%d invalidate peer\n", data[1]);

    DEL_PEER(ctx->peers, peer);

#ifdef WITH_CONTIKI
#ifndef NDEBUG
    PRINTF("removed peer [");
    PRINT6ADDR(&peer->session.addr);
    PRINTF("]:%d\n", uip_ntohs(peer->session.port));
#endif
#endif /* WITH_CONTIKI */

    free_peer = 1;

  }

  (void)CALL(ctx, event, &peer->session,
	     (dtls_alert_level_t)data[0], (unsigned short)data[1]);
  if (close_notify) {
    /* If state is DTLS_STATE_CLOSING, we have already sent a
     * close_notify so, do not send that again. */
    if (peer->state != DTLS_STATE_CLOSING) {
      peer->state = DTLS_STATE_CLOSING;
      dtls_send_alert(ctx, peer, DTLS_ALERT_LEVEL_WARNING,
                      DTLS_ALERT_CLOSE_NOTIFY);
    } else
      peer->state = DTLS_STATE_CLOSED;
  }

  if (free_peer) {
    dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
  }

  return free_peer;
}

static int dtls_alert_send_from_err(dtls_context_t *ctx, dtls_peer_t *peer, int err)
{
  assert(peer);

  if (dtls_is_alert(err)) {
    dtls_alert_level_t level = ((-err) & 0xff00) >> 8;
    dtls_alert_t desc = (-err) & 0xff;
    peer->state = DTLS_STATE_CLOSING;
    return dtls_send_alert(ctx, peer, level, desc);
  } else if (err == -1) {
    peer->state = DTLS_STATE_CLOSING;
    return dtls_send_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_INTERNAL_ERROR);
  }
  return -1;
}

/**
 * Handles incoming data as DTLS message from given peer.
 */
int
dtls_handle_message(dtls_context_t *ctx,
		    session_t *session,
		    uint8 *msg, int msglen) {
  dtls_peer_t *peer = NULL;
  unsigned int rlen;		/* record length */
  uint8 *data = NULL;		/* (decrypted) payload */
  int data_length;		/* length of decrypted payload
				   (without MAC and padding) */
  int err;

  /* check for ClientHellos of epoch 0, maybe a peer's start over */
  if ((rlen = is_record(msg,msglen))) {
    dtls_record_header_t *header = DTLS_RECORD_HEADER(msg);
    uint16_t epoch = dtls_get_epoch(header);
    uint8_t content_type = dtls_get_content_type(header);
    const char* content_type_name = dtls_message_type_to_name(content_type);
    if (content_type_name) {
      dtls_info("received message (%d bytes), starting with '%s', epoch %u\n", msglen, content_type_name, epoch);
    } else {
      dtls_info("received message (%d bytes), starting with unknown ct '%u', epoch %u\n", msglen, content_type, epoch);
    }
    if (DTLS_CT_HANDSHAKE == content_type && 0 == epoch) {
      dtls_info("handshake message epoch 0\n");
      data = msg + DTLS_RH_LENGTH;
      data_length = rlen - DTLS_RH_LENGTH;
      if ((size_t) data_length < DTLS_HS_LENGTH) {
        dtls_warn("ignore too short handshake message\n");
        return 0;
      }
      dtls_handshake_header_t *hs_header = DTLS_HANDSHAKE_HEADER(data);
      if (hs_header->msg_type == DTLS_HT_CLIENT_HELLO) {
        /*
         * Stateless processing of ClientHello in epoch 0.
         *
         * In order to protect against "denial of service" attacks, RFC6347
         * contains in https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
         * the advice to process initial a ClientHello in a stateless fashion.
         * Therefore no peer is used, but a ephemeral peer with the required
         * record and handshake sequence numbers along with the ip-endoint.
         * If the ClientHello contains no matching cookie, the client will be
         * challenged using a HelloVerifyRequest. If a matching cookie is provided,
         * a peer is created and the handshake is continued using the state of the
         * peer.
         */
        dtls_info("client_hello epoch 0\n");
        dtls_ephemeral_peer_t ephemeral_peer = {session, dtls_uint48_to_int(header->sequence_number), 0};
        err = handle_0_client_hello(ctx, &ephemeral_peer, data, data_length);
        if (err < 0) {
          dtls_warn("error while handling handshake packet\n");
        }
        return 0;
      }
    }
  } else {
     /** no payload */
    return 0;
  }

  while ((rlen = is_record(msg,msglen))) {
    dtls_record_header_t *header = DTLS_RECORD_HEADER(msg);
    uint16_t epoch = dtls_get_epoch(header);
    uint8_t content_type = dtls_get_content_type(header);
    const char* content_type_name = dtls_message_type_to_name(content_type);
    uint64_t pkt_seq_nr = dtls_uint48_to_int(header->sequence_number);

    if (content_type_name) {
      dtls_info("got '%s' epoch %u sequence %" PRIu64 " (%d bytes)\n",
                 content_type_name, epoch, pkt_seq_nr, rlen);
    }
    else {
      dtls_info("got 'unknown %u' epoch %u sequence %" PRIu64 " (%d bytes)\n",
                 content_type, epoch, pkt_seq_nr, rlen);
    }

    /* check if we have DTLS state for addr/port/ifindex */
    peer = dtls_get_peer(ctx, session);
    if (peer) {
        dtls_debug("dtls_handle_message: FOUND PEER\n");
    } else {
      if (data) {
        dtls_info("Additional record after peer has been removed.\n");
      } else {
        dtls_debug("dtls_handle_message: PEER NOT FOUND\n");
        dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "peer addr", session);
      }
      /** no peer => drop it */
      return 0;
    }

    dtls_security_parameters_t *security = dtls_security_params_read_epoch(peer, epoch);
    if (!security) {
      if (content_type_name) {
        dtls_warn("No security context for epoch: %i (%s)\n", epoch, content_type_name);
      } else {
        dtls_warn("No security context for epoch: %i (%u)\n", epoch, content_type);
      }
      data_length = -1;
    } else {
      dtls_debug("bitfield is %" PRIx64 " sequence base %" PRIx64 " rseqn %" PRIx64 "\n",
                  security->cseq.bitfield, security->cseq.cseq, pkt_seq_nr);
      if (security->cseq.bitfield == 0) { /* first message of epoch */
        data_length = decrypt_verify(peer, msg, rlen, &data);
        if(data_length > 0) {
            security->cseq.cseq = pkt_seq_nr;
            security->cseq.bitfield = 1;
            dtls_debug("init bitfield is %" PRIx64 " sequence base %" PRIx64 "\n",
                        security->cseq.bitfield, security->cseq.cseq);
        }
      } else {
        int64_t seqn_diff = (int64_t)(pkt_seq_nr - security->cseq.cseq);
        if(seqn_diff == 0) {
          /* already seen */
          dtls_debug("Drop: duplicate packet arrived (cseq=%" PRIu64 " bitfield's start)\n", pkt_seq_nr);
          return 0;
        } else if (seqn_diff < 0) { /* older pkt_seq_nr < security->cseq.cseq */
          if (seqn_diff < -63) { /* too old */
            dtls_debug("Drop: packet from before the bitfield arrived\n");
            return 0;
          }
          uint64_t seqn_bit = ((uint64_t)1 << -seqn_diff);
          if (security->cseq.bitfield & seqn_bit) { /* seen it */
            dtls_debug("Drop: duplicate packet arrived (bitfield)\n");
            return 0;
          }
          dtls_debug("Packet arrived out of order\n");
          data_length = decrypt_verify(peer, msg, rlen, &data);
          if(data_length > 0) {
            security->cseq.bitfield |= seqn_bit;
            dtls_debug("update bitfield is %" PRIx64 " keep sequence base %" PRIx64 "\n",
                        security->cseq.bitfield, security->cseq.cseq);
          }
        } else { /* newer pkt_seq_nr > security->cseq.cseq */
          data_length = decrypt_verify(peer, msg, rlen, &data);
          if(data_length > 0) {
            security->cseq.cseq = pkt_seq_nr;
            /* bitfield. B0 last seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
            if (seqn_diff > 63) {
              /* reset bitfield if new packet number is beyond its boundaries */
              security->cseq.bitfield = 1;
            } else {
              /* shift bitfield */
              security->cseq.bitfield <<= seqn_diff;
              security->cseq.bitfield |= 1;
            }
            dtls_debug("update bitfield is %" PRIx64 " new sequence base %" PRIx64 "\n",
                        security->cseq.bitfield, security->cseq.cseq);
          }
        }
      }
    }
    if (data_length < 0) {
      dtls_info("decrypt_verify() failed, drop message.\n");
      return 0;
    }

    dtls_debug_hexdump("receive header", msg, sizeof(dtls_record_header_t));
    dtls_debug_hexdump("receive unencrypted", data, data_length);

    /* Handle received record according to the first byte of the
     * message, i.e. the subprotocol. We currently do not support
     * combining multiple fragments of one type into a single
     * record. */

    switch (content_type) {

    case DTLS_CT_CHANGE_CIPHER_SPEC:
      err = handle_ccs(ctx, peer, msg, data, data_length);
      if (err < 0) {
        dtls_warn("error while handling ChangeCipherSpec message\n");
        dtls_stop_retransmission(ctx, peer);
        dtls_alert_send_from_err(ctx, peer, err);

        /* invalidate peer */
        dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
        peer = NULL;

        return err;
      }
      break;

    case DTLS_CT_ALERT:
      if (peer->state == DTLS_STATE_WAIT_FINISHED) {
        dtls_info("** drop alert before Finish.\n");
        return 0;
      }
      err = handle_alert(ctx, peer, msg, data, data_length);
      if (err < 0) {
        /* Alert could not be decoded, ignore it */
        dtls_info("** drop alert, decode error.\n");
        return err;
      }
      if (err == 1) {
        if (data[1] == DTLS_ALERT_CLOSE_NOTIFY)
          dtls_info("received close_notify alert, peer has been invalidated\n");
        else
          dtls_warn("received fatal alert, peer has been invalidated\n");
        /* handle alert has invalidated peer */
        peer = NULL;
        err = -1;
        /* no more valid records after fatal alerts */
        return 0;
      } else {
        dtls_stop_retransmission(ctx, peer);
      }
      break;

    case DTLS_CT_HANDSHAKE:

      err = handle_handshake(ctx, peer, data, data_length);
      if (err < 0) {
        dtls_warn("error 0x%04x handling handshake packet of type: %s (%i),"
                  " state %d\n", -err, dtls_handshake_type_to_name(data[0]),
                  data[0], peer->state);
        dtls_alert_send_from_err(ctx, peer, err);

        if (peer && DTLS_ALERT_LEVEL_FATAL == ((-err) & 0xff00) >> 8) {
          /* invalidate peer */
          peer->state = DTLS_STATE_CLOSED;
          dtls_stop_retransmission(ctx, peer);
          dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
          peer = NULL;
        }
        return err;
      }
      if (peer && peer->state == DTLS_STATE_CONNECTED) {
	/* stop retransmissions */
	dtls_stop_retransmission(ctx, peer);
	CALL(ctx, event, &peer->session, 0, DTLS_EVENT_CONNECTED);
      }
      break;

    case DTLS_CT_APPLICATION_DATA:
      if (epoch == 0 || peer->state == DTLS_STATE_WAIT_FINISHED) {
          dtls_info("** drop application data before Finish.\n");
          return 0;
      }
      dtls_info("** application data:\n");
      dtls_stop_retransmission(ctx, peer);
      CALL(ctx, read, &peer->session, data, data_length);
      break;
    default:
      dtls_info("dropped unknown message of type %d\n",msg[0]);
    }

    /* advance msg by length of ciphertext */
    msg += rlen;
    msglen -= rlen;
  }

  return 0;
}

dtls_context_t *
dtls_new_context(void *app_data) {
  dtls_context_t *c;
  dtls_tick_t now;

  dtls_ticks(&now);
  dtls_prng_init(now);

  c = malloc_context();
  if (!c)
    goto error;

  memset(c, 0, sizeof(dtls_context_t));
  c->app = app_data;

#ifdef WITH_CONTIKI
  process_start(&dtls_retransmit_process, (char *)c);
  PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
  /* the retransmit timer must be initialized to some large value */
  etimer_set(&c->retransmit_timer, 0xFFFF);
  PROCESS_CONTEXT_END(&coap_retransmit_process);
#endif /* WITH_CONTIKI */

  if (dtls_prng(c->cookie_secret, DTLS_COOKIE_SECRET_LENGTH))
    c->cookie_secret_age = now;
  else
    goto error;

  return c;

 error:
  dtls_alert("cannot create DTLS context\n");
  if (c)
    dtls_free_context(c);
  return NULL;
}

void dtls_reset_peer(dtls_context_t *ctx, dtls_peer_t *peer)
{
  dtls_destroy_peer(ctx, peer, DTLS_DESTROY_CLOSE);
}

void
dtls_free_context(dtls_context_t *ctx) {
  dtls_peer_t *p, *tmp;

  if (!ctx) {
    return;
  }

  if (ctx->peers) {
#ifdef DTLS_PEERS_NOHASH
    LL_FOREACH_SAFE(ctx->peers, p, tmp) {
#else /* DTLS_PEERS_NOHASH */
    HASH_ITER(hh, ctx->peers, p, tmp) {
#endif /* DTLS_PEERS_NOHASH */
      dtls_destroy_peer(ctx, p, DTLS_DESTROY_CLOSE);
    }
  }

  free_context(ctx);
}

int
dtls_connect_peer(dtls_context_t *ctx, dtls_peer_t *peer) {
  int res;
  dtls_peer_t* previous_peer;

  assert(peer);
  if (!peer)
    return -1;

  previous_peer = dtls_get_peer(ctx, &peer->session);
  /* check if the same peer is already in our list */
  if (previous_peer) {
    if (previous_peer->role == DTLS_SERVER) {
        dtls_debug("found peer in server role, exchange role to client\n");
    } else {
        dtls_debug("found peer in client role\n");
    }
    /* no close_notify, otherwise the other peer may respond. */
    dtls_destroy_peer(ctx, previous_peer, 0);
  }

  /* set local peer role to client, remote is server */
  peer->role = DTLS_CLIENT;

  if (dtls_add_peer(ctx, peer) < 0) {
    dtls_alert("cannot add peer\n");
    return -1;
  }

  /* send ClientHello with empty Cookie */
  peer->handshake_params = dtls_handshake_new();
      if (!peer->handshake_params)
        return -1;

  peer->handshake_params->hs_state.mseq_r = 0;
  peer->handshake_params->hs_state.mseq_s = 0;
  res = dtls_send_client_hello(ctx, peer, NULL, 0);
  if (res < 0)
    dtls_warn("cannot send ClientHello\n");
  else
    peer->state = DTLS_STATE_CLIENTHELLO;

  return res;
}

int
dtls_connect(dtls_context_t *ctx, const session_t *dst) {
  dtls_peer_t *peer;
  int res;

  peer = dtls_get_peer(ctx, dst);

  if (!peer)
    peer = dtls_new_peer(dst);

  if (!peer) {
    dtls_crit("cannot create new peer\n");
    return -1;
  }

  res = dtls_connect_peer(ctx, peer);

  /* Invoke event callback to indicate connection attempt or
   * re-negotiation. */
  if (res > 0) {
    CALL(ctx, event, &peer->session, 0, DTLS_EVENT_CONNECT);
  }

  return res;
}

static void
dtls_retransmit(dtls_context_t *context, netq_t *node) {
  if (!context || !node)
    return;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if (node->retransmit_cnt < DTLS_DEFAULT_MAX_RETRANSMIT) {
#ifndef DTLS_CONSTRAINED_STACK
      unsigned char sendbuf[DTLS_MAX_BUF];
#endif /* ! DTLS_CONSTRAINED_STACK */
      size_t len = sizeof(sendbuf);
      int err;
      unsigned char *data = node->data;
      size_t length = node->length;
      dtls_tick_t now;
      dtls_security_parameters_t *security = dtls_security_params_epoch(node->peer, node->epoch);

      if (node->job == TIMEOUT) {
        if (node->type == DTLS_CT_ALERT) {
          dtls_debug("** alert times out\n");
          handle_alert(context, node->peer, NULL, data, length);
        }
        netq_node_free(node);
        return;
      }

#ifdef DTLS_CONSTRAINED_STACK
      dtls_mutex_lock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */

      dtls_ticks(&now);
      node->retransmit_cnt++;
      node->t = now + (node->timeout << node->retransmit_cnt);
      netq_insert_node(&context->sendqueue, node);

      if (node->type == DTLS_CT_HANDSHAKE) {
        dtls_handshake_header_t *hs_header = DTLS_HANDSHAKE_HEADER(data);
        dtls_debug("** retransmit handshake packet of type: %s (%i)\n",
                   dtls_handshake_type_to_name(hs_header->msg_type),
                   hs_header->msg_type);
      } else {
        dtls_debug("** retransmit packet\n");
      }

      err = dtls_prepare_record(node->peer, security, node->type, &data, &length,
                1, sendbuf, &len);
      if (err < 0) {
        dtls_warn("can not retransmit packet, err: %i\n", err);
        goto return_unlock;
      }
      dtls_debug_hexdump("retransmit header", sendbuf, sizeof(dtls_record_header_t));
      dtls_debug_hexdump("retransmit unencrypted", node->data, node->length);

      (void)CALL(context, write, &node->peer->session, sendbuf, len);
return_unlock:
#ifdef DTLS_CONSTRAINED_STACK
      dtls_mutex_unlock(&static_mutex);
#endif /* DTLS_CONSTRAINED_STACK */

      return;
  }

  /* no more retransmissions, remove node from system */

  dtls_debug("** removed transaction\n");

  /* And finally delete the node */
  netq_node_free(node);
}

static void
dtls_stop_retransmission(dtls_context_t *context, dtls_peer_t *peer) {
  netq_t *node;
  node = netq_head(&context->sendqueue);

  while (node) {
    if (dtls_session_equals(&node->peer->session, &peer->session)) {
      netq_t *tmp = node;
      node = netq_next(node);
      netq_remove(&context->sendqueue, tmp);
      netq_node_free(tmp);
    } else
      node = netq_next(node);
  }
}

void
dtls_check_retransmit(dtls_context_t *context, clock_time_t *next) {
  dtls_tick_t now;
  netq_t *node = netq_head(&context->sendqueue);

  dtls_ticks(&now);
  /* comparison considering 32bit overflow */
  while (node && DTLS_IS_BEFORE_TIME(node->t, now)) {
    netq_pop_first(&context->sendqueue);
    dtls_retransmit(context, node);
    node = netq_head(&context->sendqueue);
  }

  if (next) {
    *next = node ? node->t : 0;
  }
}

#ifdef WITH_CONTIKI
/*---------------------------------------------------------------------------*/
/* message retransmission */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtls_retransmit_process, ev, data)
{
  clock_time_t now;
  netq_t *node;

  PROCESS_BEGIN();

  dtls_debug("Started DTLS retransmit process\r\n");

  while(1) {
    PROCESS_YIELD();
    if (ev == PROCESS_EVENT_TIMER) {
      if (etimer_expired(&the_dtls_context.retransmit_timer)) {

	node = netq_head(&the_dtls_context.sendqueue);

	now = clock_time();
	if (node && node->t <= now) {
	  netq_pop_first(&the_dtls_context.sendqueue);
	  dtls_retransmit(&the_dtls_context, node);
	  node = netq_head(&the_dtls_context.sendqueue);
	}

	/* need to set timer to some value even if no nextpdu is available */
	if (node) {
	  etimer_set(&the_dtls_context.retransmit_timer,
		     node->t <= now ? 1 : node->t - now);
	} else {
	  etimer_set(&the_dtls_context.retransmit_timer, 0xFFFF);
	}
      }
    }
  }

  PROCESS_END();
}
#endif /* WITH_CONTIKI */
