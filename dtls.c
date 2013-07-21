/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011--2012 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2013 Hauke Mehrtens <hauke@hauke-m.de>
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#define clock_time() (time(NULL))
#ifndef CLOCK_SECOND
# define CLOCK_SECOND 1024
#endif
#endif
#ifndef WITH_CONTIKI
#include <stdlib.h>
#include "uthash.h"
#else /* WITH_CONTIKI */
# ifndef NDEBUG
#   define DEBUG DEBUG_PRINT
#   include "net/uip-debug.h"
#  endif /* NDEBUG */
#endif /* WITH_CONTIKI */

#include "debug.h"
#include "numeric.h"
#include "netq.h"
#include "dtls.h"

#ifdef WITH_SHA256
#  include "sha2/sha2.h"
#endif

#define dtls_set_version(H,V) dtls_int_to_uint16(&(H)->version, (V))
#define dtls_set_content_type(H,V) ((H)->content_type = (V) & 0xff)
#define dtls_set_length(H,V)  ((H)->length = (V))

#define dtls_get_content_type(H) ((H)->content_type & 0xff)
#define dtls_get_version(H) dtls_uint16_to_int(&(H)->version)
#define dtls_get_epoch(H) dtls_uint16_to_int(&(H)->epoch)
#define dtls_get_sequence_number(H) dtls_uint48_to_ulong(&(H)->sequence_number)
#define dtls_get_fragment_length(H) dtls_uint24_to_int(&(H)->fragment_length)

#ifndef WITH_CONTIKI
#define HASH_FIND_PEER(head,sess,out)		\
  HASH_FIND(hh,head,sess,sizeof(session_t),out)
#define HASH_ADD_PEER(head,sess,add)		\
  HASH_ADD(hh,head,sess,sizeof(session_t),add)
#define HASH_DEL_PEER(head,delptr)		\
  HASH_DELETE(hh,head,delptr)
#endif /* WITH_CONTIKI */

#define DTLS_RH_LENGTH sizeof(dtls_record_header_t)
#define DTLS_HS_LENGTH sizeof(dtls_handshake_header_t)
#define DTLS_CH_LENGTH sizeof(dtls_client_hello_t) /* no variable length fields! */
#define DTLS_CH_LENGTH_MAX sizeof(dtls_client_hello_t) + 32 + 20
#define DTLS_HV_LENGTH sizeof(dtls_hello_verify_t)
#define DTLS_SH_LENGTH (2 + 32 + 1 + 2 + 1)
#define DTLS_CE_LENGTH (3 + 3 + 27 + DTLS_EC_KEY_SIZE + DTLS_EC_KEY_SIZE)
#define DTLS_SKEXEC_LENGTH (1 + 2 + 1 + 1 + DTLS_EC_KEY_SIZE + DTLS_EC_KEY_SIZE + 2 + 70)
#define DTLS_CKX_LENGTH 1
#define DTLS_CKXEC_LENGTH (1 + 1 + DTLS_EC_KEY_SIZE + DTLS_EC_KEY_SIZE)
#define DTLS_CV_LENGTH (1 + 1 + 2 + 1 + 1 + 1 + 1 + DTLS_EC_KEY_SIZE + 1 + 1 + DTLS_EC_KEY_SIZE)
#define DTLS_FIN_LENGTH 12

#define HS_HDR_LENGTH  DTLS_RH_LENGTH + DTLS_HS_LENGTH
#define HV_HDR_LENGTH  HS_HDR_LENGTH + DTLS_HV_LENGTH

#define HIGH(V) (((V) >> 8) & 0xff)
#define LOW(V)  ((V) & 0xff)

#define DTLS_RECORD_HEADER(M) ((dtls_record_header_t *)(M))
#define DTLS_HANDSHAKE_HEADER(M) ((dtls_handshake_header_t *)(M))

#define HANDSHAKE(M) ((dtls_handshake_header_t *)((M) + DTLS_RH_LENGTH))
#define CLIENTHELLO(M) ((dtls_client_hello_t *)((M) + HS_HDR_LENGTH))

#define IS_HELLOVERIFY(M,L) \
      ((L) >= DTLS_HS_LENGTH + DTLS_HV_LENGTH && (M)[0] == DTLS_HT_HELLO_VERIFY_REQUEST)
#define IS_SERVERHELLO(M,L) \
      ((L) >= DTLS_HS_LENGTH + 6 && (M)[0] == DTLS_HT_SERVER_HELLO)
#define IS_SERVERKEYEXCHANGE(M,L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_SERVER_KEY_EXCHANGE)
#define IS_CERTIFICATEREQUEST(M,L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_CERTIFICATE_REQUEST)
#define IS_SERVERHELLODONE(M,L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_SERVER_HELLO_DONE)
#define IS_CERTIFICATE(M,L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_CERTIFICATE)
#define IS_CERTIFICATEVERIFY(M,L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_CERTIFICATE_VERIFY)
#define IS_FINISHED(M,L) \
      ((L) >= DTLS_HS_LENGTH + DTLS_FIN_LENGTH && (M)[0] == DTLS_HT_FINISHED)

/* The length check here should work because dtls_*_to_int() works on
 * unsigned char. Otherwise, broken messages could cause severe
 * trouble. Note that this macro jumps out of the current program flow
 * when the message is too short. Beware!
 */
#define SKIP_VAR_FIELD(P,L,T) {						\
    if (L < dtls_ ## T ## _to_int(P) + sizeof(T))			\
      goto error;							\
    L -= dtls_ ## T ## _to_int(P) + sizeof(T);				\
    P += dtls_ ## T ## _to_int(P) + sizeof(T);				\
  }

#define CURRENT_CONFIG(Peer) (&(Peer)->security_params[(Peer)->config])
#define OTHER_CONFIG(Peer) (&(Peer)->security_params[!((Peer)->config & 0x01)])

#define SWITCH_CONFIG(Peer) ((Peer)->config = !((Peer)->config & 0x01))

uint8 _clear[DTLS_MAX_BUF]; /* target buffer message decryption */
uint8 _buf[DTLS_MAX_BUF]; /* target buffer for several crypto operations */

/* some constants for the PRF */
#define PRF_LABEL(Label) prf_label_##Label
#define PRF_LABEL_SIZE(Label) (sizeof(PRF_LABEL(Label)) - 1)

static const unsigned char prf_label_master[] = "master secret";
static const unsigned char prf_label_key[] = "key expansion";
static const unsigned char prf_label_client[] = "client";
static const unsigned char prf_label_server[] = "server";
static const unsigned char prf_label_finished[] = " finished";

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

extern void netq_init();
extern void crypto_init();

dtls_context_t the_dtls_context;

#ifndef WITH_CONTIKI
static inline dtls_peer_t *
dtls_malloc_peer() {
  return (dtls_peer_t *)malloc(sizeof(dtls_peer_t));
}

static inline void
dtls_free_peer(dtls_peer_t *peer) {
  free(peer);
}
#else /* WITH_CONTIKI */
PROCESS(dtls_retransmit_process, "DTLS retransmit process");

#include "memb.h"
MEMB(peer_storage, dtls_peer_t, DTLS_PEER_MAX);

static inline dtls_peer_t *
dtls_malloc_peer() {
  return memb_alloc(&peer_storage);
}
static inline void
dtls_free_peer(dtls_peer_t *peer) {
  memb_free(&peer_storage, peer);
}
#endif /* WITH_CONTIKI */

void
dtls_init() {
  netq_init();
  crypto_init();

#ifdef WITH_CONTIKI
  memb_init(&peer_storage);
#endif /* WITH_CONTIKI */
}

/* Calls cb_alert() with given arguments if defined, otherwise an
 * error message is logged and the result is -1. This is just an
 * internal helper.
 */
#define CALL(Context, which, ...)					\
  ((Context)->h && (Context)->h->which					\
   ? (Context)->h->which((Context), ##__VA_ARGS__)			\
   : -1)

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
int dtls_send(dtls_context_t *ctx, dtls_peer_t *peer, unsigned char type,
	      uint8 *buf, size_t buflen);

/**
 * Stops ongoing retransmissions of handshake messages for @p peer.
 */
void dtls_stop_retransmission(dtls_context_t *context, dtls_peer_t *peer);

dtls_peer_t *
dtls_get_peer(struct dtls_context_t *ctx, const session_t *session) {
  dtls_peer_t *p = NULL;

#ifndef WITH_CONTIKI
  HASH_FIND_PEER(ctx->peers, session, p);
#else /* WITH_CONTIKI */
  for (p = list_head(ctx->peers); p; p = list_item_next(p))
    if (dtls_session_equals(&p->session, session))
      return p;
#endif /* WITH_CONTIKI */
  
  return p;
}

int
dtls_write(struct dtls_context_t *ctx, 
	   session_t *dst, uint8 *buf, size_t len) {
  
  dtls_peer_t *peer = dtls_get_peer(ctx, dst);
  
  if (peer && peer->state == DTLS_STATE_CONNECTED)
    return dtls_send(ctx, peer, DTLS_CT_APPLICATION_DATA, buf, len);
  else
    return peer ? 0 : -1;
}

int
dtls_get_cookie(uint8 *msg, int msglen, uint8 **cookie) {
  /* To access the cookie, we have to determine the session id's
   * length and skip the whole thing. */
  if (msglen < DTLS_HS_LENGTH + DTLS_CH_LENGTH + sizeof(uint8)
      || dtls_uint16_to_int(msg + DTLS_HS_LENGTH) != DTLS_VERSION)
    return -1;
  msglen -= DTLS_HS_LENGTH + DTLS_CH_LENGTH;
  msg += DTLS_HS_LENGTH + DTLS_CH_LENGTH;

  SKIP_VAR_FIELD(msg, msglen, uint8); /* skip session id */

  if (msglen < (*msg & 0xff) + sizeof(uint8))
    return -1;
  
  *cookie = msg + sizeof(uint8);
  return dtls_uint8_to_int(msg);

 error:
  return -1;
}

int
dtls_create_cookie(dtls_context_t *ctx, 
		   session_t *session,
		   uint8 *msg, int msglen,
		   uint8 *cookie, int *clen) {
  unsigned char buf[DTLS_HMAC_MAX];
  size_t len, e;

  /* create cookie with HMAC-SHA256 over:
   * - SECRET
   * - session parameters (only IP address?)
   * - client version 
   * - random gmt and bytes
   * - session id
   * - cipher_suites 
   * - compression method
   */

  /* We use our own buffer as hmac_context instead of a dynamic buffer
   * created by dtls_hmac_new() to separate storage space for cookie
   * creation from storage that is used in real sessions. Note that
   * the buffer size must fit with the default hash algorithm (see
   * implementation of dtls_hmac_context_new()). */

  dtls_hmac_context_t hmac_context;
  dtls_hmac_init(&hmac_context, ctx->cookie_secret, DTLS_COOKIE_SECRET_LENGTH);

  dtls_hmac_update(&hmac_context, 
		   (unsigned char *)&session->addr, session->size);

  /* feed in the beginning of the Client Hello up to and including the
     session id */
  e = sizeof(dtls_client_hello_t);
  e += (*(msg + DTLS_HS_LENGTH + e) & 0xff) + sizeof(uint8);
  if (e + DTLS_HS_LENGTH > msglen)
    return -1;

  dtls_hmac_update(&hmac_context, msg + DTLS_HS_LENGTH, e);
  
  /* skip cookie bytes and length byte */
  e += *(uint8 *)(msg + DTLS_HS_LENGTH + e) & 0xff;
  e += sizeof(uint8);
  if (e + DTLS_HS_LENGTH > msglen)
    return -1;

  dtls_hmac_update(&hmac_context, 
		   msg + DTLS_HS_LENGTH + e,
		   dtls_get_fragment_length(DTLS_HANDSHAKE_HEADER(msg)) - e);

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
#endif

/**
 * Checks if \p msg points to a valid DTLS record. If
 * 
 */
static unsigned int
is_record(uint8 *msg, int msglen) {
  unsigned int rlen = 0;

  if (msglen >= DTLS_RH_LENGTH	/* FIXME allow empty records? */
#ifdef DTLS_CHECK_CONTENTTYPE
      && strchr(content_types, msg[0])
#endif
      && msg[1] == HIGH(DTLS_VERSION)
      && msg[2] == LOW(DTLS_VERSION)) 
    {
      rlen = DTLS_RH_LENGTH + 
	dtls_uint16_to_int(DTLS_RECORD_HEADER(msg)->length);
      
      /* we do not accept wrong length field in record header */
      if (rlen > msglen)	
	rlen = 0;
  } 
  
  return rlen;
}

/**
 * Initializes \p buf as record header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_record_header_t)
 * bytes. Increments sequence number counter of \p peer.
 * \return pointer to the next byte after the written header
 */ 
static inline uint8 *
dtls_set_record_header(uint8 type, dtls_peer_t *peer, uint8 *buf) {
  
  dtls_int_to_uint8(buf, type);
  buf += sizeof(uint8);

  dtls_int_to_uint16(buf, DTLS_VERSION);
  buf += sizeof(uint16);

  if (peer) {
    memcpy(buf, &peer->epoch, sizeof(uint16) + sizeof(uint48));

    /* increment record sequence counter by 1 */
    inc_uint(uint48, peer->rseq);
  } else {
    memset(buf, 0, sizeof(uint16) + sizeof(uint48));
  }

  buf += sizeof(uint16) + sizeof(uint48);

  memset(buf, 0, sizeof(uint16));
  return buf + sizeof(uint16);
}

/**
 * Initializes \p buf as handshake header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_handshake_header_t)
 * bytes. Increments message sequence number counter of \p peer.
 * \return pointer to the next byte after \p buf
 */ 
static inline uint8 *
dtls_set_handshake_header(uint8 type, dtls_peer_t *peer, 
			  int length, 
			  int frag_offset, int frag_length, 
			  uint8 *buf) {
  
  dtls_int_to_uint8(buf, type);
  buf += sizeof(uint8);

  dtls_int_to_uint24(buf, length);
  buf += sizeof(uint24);

  if (peer) {
    /* increment handshake message sequence counter by 1 */
    inc_uint(uint16, peer->hs_state.mseq);
  
    /* and copy the result to buf */
    memcpy(buf, &peer->hs_state.mseq, sizeof(uint16));
  } else {
    memset(buf, 0, sizeof(uint16));    
  }
  buf += sizeof(uint16);
  
  dtls_int_to_uint24(buf, frag_offset);
  buf += sizeof(uint24);

  dtls_int_to_uint24(buf, frag_length);
  buf += sizeof(uint24);
  
  return buf;
}

/** only one compression method is currently defined */
uint8 compression_methods[] = { 
  TLS_COMP_NULL 
};

static inline int is_psk_supported(dtls_context_t *ctx){
  return ctx && ctx->h && ctx->h->get_psk_key;
}

static inline int is_ecdsa_supported(dtls_context_t *ctx, int is_client){
  return ctx && ctx->h && ((!is_client && ctx->h->get_ecdsa_key) || 
			   (is_client && ctx->h->verify_ecdsa_key));
}

/**
 * Returns @c 1 if @p code is a cipher suite other than @c
 * TLS_NULL_WITH_NULL_NULL that we recognize.
 *
 * @param ctx   The current DTLS context
 * @param code The cipher suite identifier to check
 * @param is_client 1 for a dtls client, 0 for server
 * @return @c 1 iff @p code is recognized,
 */ 
static int
known_cipher(dtls_context_t *ctx, dtls_cipher_t code, int is_client) {
  int psk;
  int ecdsa;

  psk = is_psk_supported(ctx);
  ecdsa = is_ecdsa_supported(ctx, is_client);
  return (psk && code == TLS_PSK_WITH_AES_128_CCM_8) ||
	 (ecdsa && code == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
}

static void dtls_debug_keyblock(dtls_security_parameters_t *config)
{
  dsrv_log(LOG_DEBUG, "key_block (%d bytes):\n", dtls_kb_size(config));
  dtls_dsrv_hexdump_log(LOG_DEBUG, "  client_MAC_secret",
			dtls_kb_client_mac_secret(config),
			dtls_kb_mac_secret_size(config), 0);

  dtls_dsrv_hexdump_log(LOG_DEBUG, "  server_MAC_secret",
			dtls_kb_server_mac_secret(config),
			dtls_kb_mac_secret_size(config), 0);

  dtls_dsrv_hexdump_log(LOG_DEBUG, "  client_write_key",
			dtls_kb_client_write_key(config), 
			dtls_kb_key_size(config), 0);

  dtls_dsrv_hexdump_log(LOG_DEBUG, "  server_write_key",
			dtls_kb_server_write_key(config), 
			dtls_kb_key_size(config), 0);

  dtls_dsrv_hexdump_log(LOG_DEBUG, "  client_IV",
			dtls_kb_client_iv(config), 
			dtls_kb_iv_size(config), 0);

  dtls_dsrv_hexdump_log(LOG_DEBUG, "  server_IV",
			dtls_kb_server_iv(config), 
			dtls_kb_iv_size(config), 0);
}

int
calculate_key_block(dtls_context_t *ctx, 
		    dtls_security_parameters_t *config,
		    session_t *session,
		    unsigned char client_random[32],
		    unsigned char server_random[32]) {
  unsigned char *pre_master_secret;
  size_t pre_master_len = 0;
  pre_master_secret = config->key_block;
  int err;

  switch (config->cipher) {
  case TLS_PSK_WITH_AES_128_CCM_8: {
    const dtls_psk_key_t *psk;

    err = CALL(ctx, get_psk_key, session, NULL, 0, &psk);
    if (err < 0) {
      dsrv_log(LOG_CRIT, "no psk key for session available\n");
      return err;
    }
  /* Temporarily use the key_block storage space for the pre master secret. */
    pre_master_len = dtls_psk_pre_master_secret(psk->key, psk->key_length, 
						pre_master_secret);

    dtls_dsrv_hexdump_log(LOG_DEBUG, "psk", psk->key, psk->key_length, 1);

    break;
  }
  case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: {
    pre_master_len = dtls_ecdh_pre_master_secret(config->ecdsa.own_eph_priv,
						 config->ecdsa.other_eph_pub_x,
						 config->ecdsa.other_eph_pub_y,
						 sizeof(config->ecdsa.own_eph_priv),
						 pre_master_secret);
    break;
  }
  default:
    dsrv_log(LOG_CRIT, "calculate_key_block: unknown cipher\n");
    return -1;
  }

  dtls_dsrv_hexdump_log(LOG_DEBUG, "client_random", client_random, 32, 0);
  dtls_dsrv_hexdump_log(LOG_DEBUG, "server_random", server_random, 32, 0);
  dtls_dsrv_hexdump_log(LOG_DEBUG, "pre_master_secret", pre_master_secret,
			pre_master_len, 0);

  dtls_prf(pre_master_secret, pre_master_len,
	   PRF_LABEL(master), PRF_LABEL_SIZE(master),
	   client_random, 32,
	   server_random, 32,
	   config->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH);

  dtls_dsrv_hexdump_log(LOG_DEBUG, "master_secret", config->master_secret,
			DTLS_MASTER_SECRET_LENGTH, 0);

  /* create key_block from master_secret
   * key_block = PRF(master_secret,
                    "key expansion" + server_random + client_random) */

  dtls_prf(config->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   PRF_LABEL(key), PRF_LABEL_SIZE(key),
	   server_random, 32,
	   client_random, 32,
	   config->key_block,
	   dtls_kb_size(config));

  dtls_debug_keyblock(config);
  return 0;
}

int
init_cipher(dtls_security_parameters_t *config)
{
  /* set crypto context for TLS_PSK_WITH_AES_128_CCM_8 */
  dtls_cipher_free(config->read_cipher);

  assert(config->cipher != TLS_NULL_WITH_NULL_NULL);
  config->read_cipher = dtls_cipher_new(config->cipher,
					dtls_kb_remote_write_key(config),
					dtls_kb_key_size(config));

  if (!config->read_cipher) {
    warn("cannot create read cipher\n");
    return -1;
  }

  dtls_cipher_set_iv(config->read_cipher,
		     dtls_kb_remote_iv(config),
		     dtls_kb_iv_size(config));


  dtls_cipher_free(config->write_cipher);
  
  config->write_cipher = dtls_cipher_new(config->cipher,
					 dtls_kb_local_write_key(config),
					 dtls_kb_key_size(config));

  if (!config->write_cipher) {
    dtls_cipher_free(config->read_cipher);
    warn("cannot create write cipher\n");
    return -1;
  }

  dtls_cipher_set_iv(config->write_cipher,
		     dtls_kb_local_iv(config),
		     dtls_kb_iv_size(config));
  return 0;
}

/* TODO: add a generic method which iterates over a list and searches for a specific key */
static int verify_ext_eliptic_curves(uint8 *data, size_t data_length) {
  int i, curve_name;

  /* length of curve list */
  i = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  if (i + sizeof(uint16) != data_length) {
    warn("the list of the supported elliptic curves should be tls extension length - 2\n");
    return -1;
  }

  for (i = data_length - sizeof(uint16); i > 0; i -= sizeof(uint16)) {
    /* check if this curve is supported */
    curve_name = dtls_uint16_to_int(data);
    data += sizeof(uint16);

    if (curve_name == TLS_EXT_ELLIPTIC_CURVES_SECP256R1)
      return 0;
  }

  warn("no supported elliptic curve found\n");
  return -2;
}

static int verify_ext_cert_type(uint8 *data, size_t data_length) {
  int i, cert_type;

  /* length of cert type list */
  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  if (i + sizeof(uint8) != data_length) {
    warn("the list of the supported certificate types should be tls extension length - 1\n");
    return -1;
  }

  for (i = data_length - sizeof(uint8); i > 0; i -= sizeof(uint8)) {
    /* check if this cert type is supported */
    cert_type = dtls_uint8_to_int(data);
    data += sizeof(uint8);

    if (cert_type == TLS_CERT_TYPE_OOB)
      return 0;
  }

  warn("no supported certificate type found\n");
  return -2;
}

/**
 * Updates the security parameters of given \p peer.  As this must be
 * done before the new configuration is activated, it changes the
 * OTHER_CONFIG only. When the ClientHello handshake message in \p
 * data does not contain a cipher suite or compression method, it is 
 * copied from the CURRENT_CONFIG.
 *
 * \param ctx   The current DTLS context.
 * \param peer  The remote peer whose security parameters are about to change.
 * \param data  The handshake message with a ClientHello. 
 * \param data_length The actual size of \p data.
 * \return \c 0 if an error occurred, \c 1 otherwise.
 */
int
dtls_update_parameters(dtls_context_t *ctx, 
		       dtls_peer_t *peer,
		       uint8 *data, size_t data_length) {
  int i, j;
  int ok;
  int ext_elliptic_curve;
  int ext_client_cert_type;
  int ext_server_cert_type;
  dtls_security_parameters_t *config = OTHER_CONFIG(peer);

  assert(config);
  assert(data_length > DTLS_HS_LENGTH + DTLS_CH_LENGTH);

  /* debug("dtls_update_parameters: msglen is %d\n", data_length); */

  /* skip the handshake header and client version information */
  data += DTLS_HS_LENGTH + sizeof(uint16);
  data_length -= DTLS_HS_LENGTH + sizeof(uint16);

  /* store client random in config 
   * FIXME: if we send the ServerHello here, we do not need to store
   * the client's random bytes */
  memcpy(config->client_random, data, sizeof(config->client_random));
  data += sizeof(config->client_random);
  data_length -= sizeof(config->client_random);

  /* Caution: SKIP_VAR_FIELD may jump to error: */
  SKIP_VAR_FIELD(data, data_length, uint8);	/* skip session id */
  SKIP_VAR_FIELD(data, data_length, uint8);	/* skip cookie */

  i = dtls_uint16_to_int(data);
  if (data_length < i + sizeof(uint16)) {
    /* Looks like we do not have a cipher nor compression. This is ok
     * for renegotiation, but not for the initial handshake. */

    if (CURRENT_CONFIG(peer)->cipher == TLS_NULL_WITH_NULL_NULL)
      goto error;

    config->cipher = CURRENT_CONFIG(peer)->cipher;
    config->compression = CURRENT_CONFIG(peer)->compression;

    return 0;
  }

  data += sizeof(uint16);
  data_length -= sizeof(uint16) + i;

  ok = 0;
  while (i && !ok) {
    config->cipher = dtls_uint16_to_int(data);
    ok = known_cipher(ctx, config->cipher, 0);
    i -= sizeof(uint16);
    data += sizeof(uint16);
  }

  /* skip remaining ciphers */
  data += i;

  if (!ok) {
    /* reset config cipher to a well-defined value */
    config->cipher = TLS_NULL_WITH_NULL_NULL;
    return -1;
  }

  if (data_length < sizeof(uint8)) { 
    /* no compression specified, take the current compression method */
    config->compression = CURRENT_CONFIG(peer)->compression;
    return -1;
  }

  i = dtls_uint8_to_int(data);
  if (data_length < i + sizeof(uint8))
    goto error;

  data += sizeof(uint8);
  data_length -= sizeof(uint8) + i;

  ok = 0;
  while (i && !ok) {
    for (j = 0; j < sizeof(compression_methods) / sizeof(uint8); ++j)
      if (dtls_uint8_to_int(data) == compression_methods[j]) {
	config->compression = compression_methods[j];
	ok = 1;
      }
    i -= sizeof(uint8);
    data += sizeof(uint8);    
  }

  if (data_length < sizeof(uint16)) { 
    /* no tls extensions specified */
    if (config->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8) {
      return -1;
    }
    return 0;
  }

  /* get the length of the tls extension list */
  j = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (data_length < j)
    goto error;

  ext_elliptic_curve = 0;
  ext_client_cert_type = 0;
  ext_server_cert_type = 0;

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
      case TLS_EXT_CLIENT_CERIFICATE_TYPE:
        ext_client_cert_type = 1;
        if (verify_ext_cert_type(data, j))
          goto error;
        break;
      case TLS_EXT_SERVER_CERIFICATE_TYPE:
        ext_server_cert_type = 1;
        if (verify_ext_cert_type(data, j))
          goto error;
        break;
      default:
        warn("unsupported tls extension: %i\n", i);
        break;
    }
    data += j;
    data_length -= j;
  }
  if (config->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8) {
    if (!ext_elliptic_curve && !ext_client_cert_type && !ext_server_cert_type) {
      warn("not all required tls extensions found in client hello\n");
      return -1;
    }
  }

  return !ok;
 error:
  warn("ClientHello too short (%d bytes)\n", data_length);
  return -1;
}

static inline int
check_client_keyexchange(dtls_context_t *ctx, 
			 dtls_peer_t *peer,
			 uint8 *data, size_t length) {

  if (data[0] != DTLS_HT_CLIENT_KEY_EXCHANGE) {
    debug("This is not a client key exchange\n");
    return -1;
  }

  if (OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8) {

    if (length < DTLS_HS_LENGTH + DTLS_CKXEC_LENGTH) {
      debug("The client key exchange is too short\n");
      return -1;
    }
    data += DTLS_HS_LENGTH;

    if (dtls_uint8_to_int(data) != 65) {
      dsrv_log(LOG_ALERT, "expected 65 bytes long public point\n");
      return -1;
    }
    data += sizeof(uint8);

    if (dtls_uint8_to_int(data) != 4) {
      dsrv_log(LOG_ALERT, "expected uncompressed public point\n");
      return -1;
    }
    data += sizeof(uint8);

    memcpy(OTHER_CONFIG(peer)->ecdsa.other_eph_pub_x, data,
	   sizeof(OTHER_CONFIG(peer)->ecdsa.other_eph_pub_x));
    data += sizeof(OTHER_CONFIG(peer)->ecdsa.other_eph_pub_x);

    memcpy(OTHER_CONFIG(peer)->ecdsa.other_eph_pub_y, data,
	   sizeof(OTHER_CONFIG(peer)->ecdsa.other_eph_pub_y));
    data += sizeof(OTHER_CONFIG(peer)->ecdsa.other_eph_pub_y);
  } else {
    if (length < DTLS_CKX_LENGTH) {
      debug("The client key exchange is too short\n");
      return -1;
    }
  }
  return 0;
}

static int
check_ccs(dtls_context_t *ctx, 
	  dtls_peer_t *peer,
	  uint8 *record, uint8 *data, size_t data_length) {

  if (DTLS_RECORD_HEADER(record)->content_type != DTLS_CT_CHANGE_CIPHER_SPEC
      || data_length < 1 || data[0] != 1)
    return 0;

  return 1;
}

dtls_peer_t *
dtls_new_peer(dtls_context_t *ctx, 
	      const session_t *session) {
  dtls_peer_t *peer;

  peer = dtls_malloc_peer();
  if (peer) {
    memset(peer, 0, sizeof(dtls_peer_t));
    memcpy(&peer->session, session, sizeof(session_t));

    dtls_dsrv_log_addr(LOG_DEBUG, "dtls_new_peer", session);
    /* initially allow the NULL cipher */
    CURRENT_CONFIG(peer)->cipher = TLS_NULL_WITH_NULL_NULL;

    /* initialize the handshake hash wrt. the hard-coded DTLS version */
    debug("DTLSv12: initialize HASH_SHA256\n");
    /* TLS 1.2:  PRF(secret, label, seed) = P_<hash>(secret, label + seed) */
    /* FIXME: we use the default SHA256 here, might need to support other 
              hash functions as well */
    dtls_hash_init(&peer->hs_state.hs_hash);
  }
  
  return peer;
}

static inline void
update_hs_hash(dtls_peer_t *peer, uint8 *data, size_t length) {
  dtls_dsrv_hexdump_log(LOG_DEBUG, "add MAC data", data, length, 0);
  dtls_hash_update(&peer->hs_state.hs_hash, data, length);
}

static void
copy_hs_hash(dtls_peer_t *peer, dtls_hash_ctx *hs_hash) {
  memcpy(hs_hash, &peer->hs_state.hs_hash, sizeof(peer->hs_state.hs_hash));
}

static inline size_t
finalize_hs_hash(dtls_peer_t *peer, uint8 *buf) {
  return dtls_hash_finalize(buf, &peer->hs_state.hs_hash);
}

static inline void
clear_hs_hash(dtls_peer_t *peer) {
  assert(peer);
  dtls_hash_init(&peer->hs_state.hs_hash);
}

/** 
 *Checks if \p record + \p data contain a Finished message with valid
 * verify_data. 
 *
 * \param ctx    The current DTLS context.
 * \param peer   The remote peer of the security association.
 * \param record The message record header.
 * \param rlen   The actual length of \p record.
 * \param data   The cleartext payload of the message.
 * \param data_length Actual length of \p data.
 * \return \c 1 if the Finished message is valid, \c 0 otherwise.
 */
static int
check_finished(dtls_context_t *ctx, dtls_peer_t *peer,
	       uint8 *record, uint8 *data, size_t data_length) {
  size_t digest_length, label_size;
  const unsigned char *label;
  unsigned char buf[DTLS_HMAC_MAX];

  /* Use a union here to ensure that sufficient stack space is
   * reserved. As statebuf and verify_data are not used at the same
   * time, we can re-use the storage safely.
   */
  union {
    unsigned char statebuf[DTLS_HASH_CTX_SIZE];
    unsigned char verify_data[DTLS_FIN_LENGTH];
  } b;

  debug("check Finish message\n");
  if (record[0] != DTLS_CT_HANDSHAKE || !IS_FINISHED(data, data_length)) {
    debug("failed\n");
    return -1;
  }

  /* temporarily store hash status for roll-back after finalize */
  memcpy(b.statebuf, &peer->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

  digest_length = finalize_hs_hash(peer, buf);
  /* clear_hash(); */

  /* restore hash status */
  memcpy(&peer->hs_state.hs_hash, b.statebuf, DTLS_HASH_CTX_SIZE);

  if (CURRENT_CONFIG(peer)->role == DTLS_SERVER) {
    label = PRF_LABEL(server);
    label_size = PRF_LABEL_SIZE(server);
  } else { /* client */
    label = PRF_LABEL(client);
    label_size = PRF_LABEL_SIZE(client);
  }

  dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   label, label_size,
	   PRF_LABEL(finished), PRF_LABEL_SIZE(finished),
	   buf, digest_length,
	   b.verify_data, sizeof(b.verify_data));

  dtls_dsrv_hexdump_log(LOG_DEBUG, "d:", data + DTLS_HS_LENGTH, sizeof(b.verify_data), 0);
  dtls_dsrv_hexdump_log(LOG_DEBUG, "v:", b.verify_data, sizeof(b.verify_data), 0);
  return memcmp(data + DTLS_HS_LENGTH, b.verify_data, sizeof(b.verify_data));
}

/**
 * Prepares the payload given in \p data for sending with
 * dtls_send(). The \p data is encrypted and compressed according to
 * the current security parameters of \p peer.  The result of this
 * operation is put into \p sendbuf with a prepended record header of
 * type \p type ready for sending. As some cipher suites add a MAC
 * before encryption, \p data must be large enough to hold this data
 * as well (usually \c dtls_kb_digest_size(CURRENT_CONFIG(peer)).
 *
 * \param peer    The remote peer the packet will be sent to.
 * \param type    The content type of this record.
 * \param data    The payload to send.
 * \param data_length The size of \p data.
 * \param sendbuf The output buffer where the encrypted record
 *                will be placed.
 * \param rlen    This parameter must be initialized with the 
 *                maximum size of \p sendbuf and will be updated
 *                to hold the actual size of the stored packet
 *                on success. On error, the value of \p rlen is
 *                undefined. 
 * \return Less than zero on error, or greater than zero success.
 */
int
dtls_prepare_record(dtls_peer_t *peer,
		    unsigned char type,
		    uint8 *data_array[], size_t data_len_array[],
		    size_t data_array_len,
		    uint8 *sendbuf, size_t *rlen) {
  uint8 *p, *start;
  int res;
  int i;
  
  p = dtls_set_record_header(type, peer, sendbuf);
  start = p;

  if (!peer || CURRENT_CONFIG(peer)->cipher == TLS_NULL_WITH_NULL_NULL) {
    /* no cipher suite */

    res = 0;
    for (i = 0; i < data_array_len; i++) {
      /* check the minimum that we need for packets that are not encrypted */
      if (*rlen < (p - start) + data_len_array[i]) {
        debug("dtls_prepare_record: send buffer too small\n");
        return -1;
      }

      memcpy(p, data_array[i], data_len_array[i]);
      p += data_len_array[i];
      res += data_len_array[i];
    }
  } else { /* TLS_PSK_WITH_AES_128_CCM_8 */   
    dtls_cipher_context_t *cipher_context;

    /** 
     * length of additional_data for the AEAD cipher which consists of
     * seq_num(2+6) + type(1) + version(2) + length(2)
     */
#define A_DATA_LEN 13
#define A_DATA N
    unsigned char N[max(DTLS_CCM_BLOCKSIZE, A_DATA_LEN)];
    
    debug("dtls_prepare_record(): encrypt using TLS_PSK_WITH_AES_128_CCM_8\n");

    /* set nonce       
       from http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-03:
        struct {
               case client:
                  uint32 client_write_IV;  // low order 32-bits
               case server:
                  uint32 server_write_IV;  // low order 32-bits
               uint64 seq_num;
            } CCMNonce.

	    In DTLS, the 64-bit seq_num is the 16-bit epoch concatenated with the
	    48-bit seq_num.
    */

    memcpy(p, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8);
    p += 8;
    res = 8;

    for (i = 0; i < data_array_len; i++) {
      /* check the minimum that we need for packets that are not encrypted */
      if (*rlen < res + data_len_array[i]) {
        debug("dtls_prepare_record: send buffer too small\n");
        return -1;
      }

      memcpy(p, data_array[i], data_len_array[i]);
      p += data_len_array[i];
      res += data_len_array[i];
    }

    memset(N, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(N, dtls_kb_local_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));
    memcpy(N + dtls_kb_iv_size(CURRENT_CONFIG(peer)), start, 8); /* epoch + seq_num */

    cipher_context = CURRENT_CONFIG(peer)->write_cipher;

    if (!cipher_context) {
      warn("no write_cipher available!\n");
      return -1;
    }

    dtls_dsrv_hexdump_log(LOG_DEBUG, "nonce:", N, DTLS_CCM_BLOCKSIZE, 0);
    dtls_dsrv_hexdump_log(LOG_DEBUG, "key:",
			  dtls_kb_local_write_key(CURRENT_CONFIG(peer)),
			  dtls_kb_key_size(CURRENT_CONFIG(peer)), 0);

    dtls_cipher_set_iv(cipher_context, N, DTLS_CCM_BLOCKSIZE);
    
    /* re-use N to create additional data according to RFC 5246, Section 6.2.3.3:
     * 
     * additional_data = seq_num + TLSCompressed.type +
     *                   TLSCompressed.version + TLSCompressed.length;
     */
    memcpy(A_DATA, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8); /* epoch and seq_num */
    memcpy(A_DATA + 8,  &DTLS_RECORD_HEADER(sendbuf)->content_type, 3); /* type and version */
    dtls_int_to_uint16(A_DATA + 11, res - 8); /* length */
    
    res = dtls_encrypt(cipher_context, start + 8, res - 8, start + 8,
		       A_DATA, A_DATA_LEN);

    if (res < 0)
      return res;

    res += 8;			/* increment res by size of nonce_explicit */
    dtls_dsrv_hexdump_log(LOG_DEBUG, "message:", start, res, 0);
  }

  /* fix length of fragment in sendbuf */
  dtls_int_to_uint16(sendbuf + 11, res);
  
  *rlen = DTLS_RH_LENGTH + res;
  return 1;
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
  uint8 sendbuf[DTLS_MAX_BUF];
  size_t len = sizeof(sendbuf);

  dtls_set_handshake_header(header_type, (add_hash) ? peer : NULL, data_length, 0,
			    data_length, buf);

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
  i = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE, data_array, data_len_array,
			  i, sendbuf, &len);
  if (i < 0) {
    return i;
  }

  return CALL(ctx, write, session, sendbuf, len);
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

/**
 * Sends the data passed in @p buf as a DTLS record of type @p type to
 * the given peer. The data will be encrypted and compressed according
 * to the security parameters for @p peer.
 *
 * @param ctx    The DTLS context in effect.
 * @param peer   The remote party where the packet is sent.
 * @param type   The content type of this record.
 * @param buf    The data to send.
 * @param buflen The number of bytes to send from @p buf.
 * @return Less than zero in case of an error or the number of
 *   bytes that have been sent otherwise.
 */
int
dtls_send(dtls_context_t *ctx, dtls_peer_t *peer,
	  unsigned char type,
	  uint8 *buf, size_t buflen) {
  
  /* We cannot use ctx->sendbuf here as it is reserved for collecting
   * the input for this function, i.e. buf == ctx->sendbuf.
   *
   * TODO: check if we can use the receive buf here. This would mean
   * that we might not be able to handle multiple records stuffed in
   * one UDP datagram */
  unsigned char sendbuf[DTLS_MAX_BUF];
  size_t len = sizeof(sendbuf);
  int res;

  res = dtls_prepare_record(peer, type, &buf, &buflen, 1, sendbuf, &len);

  if (res < 0)
    return res;

  /* if (peer && MUST_HASH(peer, type, buf, buflen)) */
  /*   update_hs_hash(peer, buf, buflen); */

  dtls_dsrv_hexdump_log(LOG_DEBUG, "send header", sendbuf,
			sizeof(dtls_record_header_t), 1);
  dtls_dsrv_hexdump_log(LOG_DEBUG, "send unencrypted", buf, buflen, 1);

  if (type == DTLS_CT_HANDSHAKE && buf[0] != DTLS_HT_HELLO_VERIFY_REQUEST) {
    /* copy handshake messages other than HelloVerify into retransmit buffer */
    netq_t *n = netq_node_new();
    if (n) {
      n->t = clock_time() + 2 * CLOCK_SECOND;
      n->retransmit_cnt = 0;
      n->timeout = 2 * CLOCK_SECOND;
      n->peer = peer;
      n->length = buflen;
      memcpy(n->data, buf, buflen);

      if (!netq_insert_node((netq_t **)ctx->sendqueue, n)) {
	warn("cannot add packet to retransmit buffer\n");
	netq_node_free(n);
#ifdef WITH_CONTIKI
      } else {
	/* must set timer within the context of the retransmit process */
	PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
	etimer_set(&ctx->retransmit_timer, n->timeout);
	PROCESS_CONTEXT_END(&dtls_retransmit_process);
#endif /* WITH_CONTIKI */
      }
    } else 
      warn("retransmit buffer full\n");
  }

  /* FIXME: copy to peer's sendqueue (after fragmentation if
   * necessary) and initialize retransmit timer */
  res = CALL(ctx, write, &peer->session, sendbuf, len);

  /* Guess number of bytes application data actually sent:
   * dtls_prepare_record() tells us in len the number of bytes to
   * send, res will contain the bytes actually sent. */
  return res <= 0 ? res : buflen - (len - res);
}

static inline int
dtls_alert(dtls_context_t *ctx, dtls_peer_t *peer, dtls_alert_level_t level,
	   dtls_alert_t description) {
  uint8_t msg[] = { level, description };

  dtls_send(ctx, peer, DTLS_CT_ALERT, msg, sizeof(msg));
  return 0;
}

int 
dtls_close(dtls_context_t *ctx, const session_t *remote) {
  int res = -1;
  dtls_peer_t *peer;

  peer = dtls_get_peer(ctx, remote);

  if (peer) {
    res = dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_CLOSE_NOTIFY);
    /* indicate tear down */
    peer->state = DTLS_STATE_CLOSING;
  }
  return res;
}

/**
 * Checks a received Client Hello message for a valid cookie. When the
 * Client Hello contains no cookie, the function fails and a Hello
 * Verify Request is sent to the peer (using the write callback function
 * registered with \p ctx). The return value is \c -1 on error, \c 0 when
 * undecided, and \c 1 if the Client Hello was good. 
 * 
 * \param ctx     The DTLS context.
 * \param peer    The remote party we are talking to, if any.
 * \param session Transport address of the remote peer.
 * \param msg     The received datagram.
 * \param msglen  Length of \p msg.
 * \return \c 1 if msg is a Client Hello with a valid cookie, \c 0 or
 * \c -1 otherwise.
 */
int
dtls_verify_peer(dtls_context_t *ctx, 
		 dtls_peer_t *peer, 
		 session_t *session,
		 uint8 *record, 
		 uint8 *data, size_t data_length)
{
  uint8 buf[DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH];
  uint8 *p = buf;
  int len = DTLS_COOKIE_LENGTH;
  uint8 *cookie;
  int err;
#undef mycookie
#define mycookie (buf + DTLS_HV_LENGTH)

  /* check if we can access at least all fields from the handshake header */
  if (record[0] == DTLS_CT_HANDSHAKE
      && data_length >= DTLS_HS_LENGTH 
      && data[0] == DTLS_HT_CLIENT_HELLO) {

    /* Store cookie where we can reuse it for the HelloVerify request. */
    err = dtls_create_cookie(ctx, session, data, data_length, mycookie, &len);
    if (err < 0)
      return err;

    dtls_dsrv_hexdump_log(LOG_DEBUG, "create cookie", mycookie, len, 0);

    assert(len == DTLS_COOKIE_LENGTH);
    
    /* Perform cookie check. */
    len = dtls_get_cookie(data, data_length, &cookie);

    dtls_dsrv_hexdump_log(LOG_DEBUG, "compare with cookie", cookie, len, 0);

    /* check if cookies match */
    if (len == DTLS_COOKIE_LENGTH && memcmp(cookie, mycookie, len) == 0) {
      debug("found matching cookie\n");
      return 1;      
    }

    if (len > 0) {
      dtls_dsrv_hexdump_log(LOG_DEBUG, "invalid cookie", cookie, len, 0);
    } else {
      debug("cookie len is 0!\n");
    }

    /* ClientHello did not contain any valid cookie, hence we send a
     * HelloVerify request. */

    dtls_int_to_uint16(p, DTLS_VERSION);
    p += sizeof(uint16);

    dtls_int_to_uint8(p, DTLS_COOKIE_LENGTH);
    p += sizeof(uint8);

    assert(p == mycookie);

    p += DTLS_COOKIE_LENGTH;

    err = dtls_send_handshake_msg_hash(ctx, peer, session,
				       DTLS_HT_HELLO_VERIFY_REQUEST,
				       buf, p - buf, 0);
    if (err < 0) {
      warn("cannot send HelloVerify request\n");
      return err;
    }
    return 0; /* HelloVerify is sent, now we cannot do anything but wait */
  }

  return -1;			/* not a ClientHello, signal error */
#undef mycookie
}

static int
check_client_certificate_verify(dtls_context_t *ctx, 
				dtls_peer_t *peer,
				uint8 *data, size_t data_length)
{
  dtls_security_parameters_t *config = OTHER_CONFIG(peer);
  int i;
  unsigned char *result_r;
  unsigned char *result_s;
  dtls_hash_ctx hs_hash;
  unsigned char sha256hash[DTLS_HMAC_DIGEST_SIZE];

  if (!IS_CERTIFICATEVERIFY(data, data_length))
    return -1;

  assert(config->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

  data += DTLS_HS_LENGTH;

  if (data_length < DTLS_HS_LENGTH + DTLS_CV_LENGTH) {
    dsrv_log(LOG_ALERT, "the package length does not match the expected\n");
    return -1;
  }

  if (dtls_uint8_to_int(data) != TLS_EXT_SIG_HASH_ALGO_SHA256) {
    dsrv_log(LOG_ALERT, "only sha256 is supported in certificate verify\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint8_to_int(data) != TLS_EXT_SIG_HASH_ALGO_ECDSA) {
    dsrv_log(LOG_ALERT, "only ecdsa signature is supported in client verify\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (data_length < dtls_uint16_to_int(data)) {
    dsrv_log(LOG_ALERT, "signature length wrong\n");
    return -1;
  }
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (dtls_uint8_to_int(data) != 0x30) {
    dsrv_log(LOG_ALERT, "wrong ASN.1 struct, expected SEQUENCE\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (data_length < dtls_uint8_to_int(data)) {
    dsrv_log(LOG_ALERT, "signature length wrong\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint8_to_int(data) != 0x02) {
    dsrv_log(LOG_ALERT, "wrong ASN.1 struct, expected Integer\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  /* Sometimes these values have a leeding 0 byte */
  result_r = data + i - DTLS_EC_KEY_SIZE;

  data += i;
  data_length -= i;

  if (dtls_uint8_to_int(data) != 0x02) {
    dsrv_log(LOG_ALERT, "wrong ASN.1 struct, expected Integer\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  /* Sometimes these values have a leeding 0 byte */
  result_s = data + i - DTLS_EC_KEY_SIZE;

  data += i;
  data_length -= i;

  copy_hs_hash(peer, &hs_hash);

  dtls_hash_finalize(sha256hash, &hs_hash);

  i = dtls_ecdsa_verify_sig_hash(config->ecdsa.other_pub_x, config->ecdsa.other_pub_y,
  			    sizeof(config->ecdsa.other_pub_x),
			    sha256hash, sizeof(sha256hash),
			    result_r, result_s);

  if (i < 0) {
    dsrv_log(LOG_ALERT, "wrong signature\n");
    return i;
  }
  return 0;
}

static int
dtls_send_server_hello(dtls_context_t *ctx, dtls_peer_t *peer)
{
  /* Ensure that the largest message to create fits in our source
   * buffer. (The size of the destination buffer is checked by the
   * encoding function, so we do not need to guess.) */
  uint8 buf[DTLS_SH_LENGTH + 2 + 5 + 5 + 8];
  uint8 *p;
  int ecdsa;
  uint8 extension_size;

  ecdsa = OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;

  extension_size = (ecdsa) ? 2 + 5 + 5 + 8 : 0;

  /* Handshake header */
  p = buf;

  /* ServerHello */
  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* Set server random: First 4 bytes are the server's Unix timestamp,
   * followed by 28 bytes of generate random data. */
  dtls_int_to_uint32(OTHER_CONFIG(peer)->server_random, clock_time());
  prng(OTHER_CONFIG(peer)->server_random + 4, 28);

  memcpy(p, OTHER_CONFIG(peer)->server_random,
         sizeof(OTHER_CONFIG(peer)->server_random));
  p += sizeof(OTHER_CONFIG(peer)->server_random);

  *p++ = 0;			/* no session id */

  if (OTHER_CONFIG(peer)->cipher != TLS_NULL_WITH_NULL_NULL) {
    /* selected cipher suite */
    dtls_int_to_uint16(p, OTHER_CONFIG(peer)->cipher);
    p += sizeof(uint16);

    /* selected compression method */
    if (OTHER_CONFIG(peer)->compression >= 0)
      *p++ = compression_methods[OTHER_CONFIG(peer)->compression];
  }

  if (extension_size) {
    /* length of the extensions */
    dtls_int_to_uint16(p, extension_size - 2);
    p += sizeof(uint16);
  }

  if (ecdsa) {
    /* client certificate type extension */
    dtls_int_to_uint16(p, TLS_EXT_CLIENT_CERIFICATE_TYPE);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 1);
    p += sizeof(uint16);

    dtls_int_to_uint8(p, TLS_CERT_TYPE_OOB);
    p += sizeof(uint8);

    /* client certificate type extension */
    dtls_int_to_uint16(p, TLS_EXT_SERVER_CERIFICATE_TYPE);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 1);
    p += sizeof(uint16);

    dtls_int_to_uint8(p, TLS_CERT_TYPE_OOB);
    p += sizeof(uint8);

    /* elliptic_curves */
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
  }

  /* FIXME: if key->psk.id != NULL we need the server key exchange */

  assert(p - buf <= sizeof(buf));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_SERVER_HELLO,
				 buf, p - buf);
}

static int
dtls_send_certificate_ecdsa(dtls_context_t *ctx, dtls_peer_t *peer,
			    const dtls_ecdsa_key_t *key)
{
  uint8 buf[DTLS_CE_LENGTH];
  uint8 *p;

  /* Certificate 
   *
   * Start message construction at beginning of buffer. */
  p = buf;

  dtls_int_to_uint24(p, 94);
  p += sizeof(uint24);

  dtls_int_to_uint24(p, 91);
  p += sizeof(uint24);
  
  memcpy(p, &cert_asn1_header, sizeof(cert_asn1_header));
  p += sizeof(cert_asn1_header);

  memcpy(p, key->pub_key_x, DTLS_EC_KEY_SIZE);
  p += DTLS_EC_KEY_SIZE;

  memcpy(p, key->pub_key_y, DTLS_EC_KEY_SIZE);
  p += DTLS_EC_KEY_SIZE;

  assert(p - buf <= sizeof(buf));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE,
				 buf, p - buf);
}

static uint8 *
dtls_add_ecdsa_signature_elem(uint8 *p, uint32_t *point_r, uint32_t *point_s)
{
  int len_r;
  int len_s;

#define R_KEY_OFFSET (2 + 1 + 1 + 1 + 1)
#define S_KEY_OFFSET(len_s) (R_KEY_OFFSET + (len_s) + 1 + 1)
  /* store the pointer to the r component of the signature and make space */
  len_r = dtls_ec_key_from_uint32_asn1(point_r, DTLS_EC_KEY_SIZE, p + R_KEY_OFFSET);
  len_s = dtls_ec_key_from_uint32_asn1(point_s, DTLS_EC_KEY_SIZE, p + S_KEY_OFFSET(len_r));

#undef R_KEY_OFFSET
#undef S_KEY_OFFSET

  /* length of signature */
  dtls_int_to_uint16(p, len_r + len_s + 2 + 2 + 2);
  p += sizeof(uint16);

  /* ASN.1 SEQUENCE */
  dtls_int_to_uint8(p, 0x30);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, len_r + len_s + 2 + 2);
  p += sizeof(uint8);

  /* ASN.1 Integer r */
  dtls_int_to_uint8(p, 0x02);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, len_r);
  p += sizeof(uint8);

  /* the pint r was added here */
  p += len_r;

  /* ASN.1 Integer s */
  dtls_int_to_uint8(p, 0x02);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, len_s);
  p += sizeof(uint8);

  /* the pint s was added here */
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
  dtls_security_parameters_t *config = OTHER_CONFIG(peer);

  /* ServerKeyExchange 
   *
   * Start message construction at beginning of buffer. */
  p = buf;

  key_params = p;
  /* ECCurveType curve_type: named_curve */
  dtls_int_to_uint8(p, 3);
  p += sizeof(uint8);

  /* NamedCurve namedcurve: secp256r1 */
  dtls_int_to_uint16(p, 23);
  p += sizeof(uint16);

  dtls_int_to_uint8(p, 1 + 2 * DTLS_EC_KEY_SIZE);
  p += sizeof(uint8);

  /* This should be an uncompressed point, but I do not have access to the sepc. */
  dtls_int_to_uint8(p, 4);
  p += sizeof(uint8);

  /* store the pointer to the x component of the pub key and make space */
  ephemeral_pub_x = p;
  p += DTLS_EC_KEY_SIZE;

  /* store the pointer to the y component of the pub key and make space */
  ephemeral_pub_y = p;
  p += DTLS_EC_KEY_SIZE;

  dtls_ecdsa_generate_key(config->ecdsa.own_eph_priv,
			  ephemeral_pub_x, ephemeral_pub_y,
			  DTLS_EC_KEY_SIZE);

  /* sign the ephemeral and its paramaters */
  dtls_ecdsa_create_sig(key->priv_key, DTLS_EC_KEY_SIZE,
		       config->client_random, sizeof(config->client_random),
		       config->server_random, sizeof(config->server_random),
		       key_params, p - key_params,
		       point_r, point_s);

  p = dtls_add_ecdsa_signature_elem(p, point_r, point_s);

  assert(p - buf <= sizeof(buf));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_SERVER_KEY_EXCHANGE,
				 buf, p - buf);
}

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
  dtls_int_to_uint8(p, 64);
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

  assert(p - buf <= sizeof(buf));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE_REQUEST,
				 buf, p - buf);
}

static int
dtls_send_server_hello_done(dtls_context_t *ctx, dtls_peer_t *peer)
{

  /* ServerHelloDone 
   *
   * Start message construction at beginning of buffer. */

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_SERVER_HELLO_DONE,
				 NULL, 0);
}

int
dtls_send_server_hello_msgs(dtls_context_t *ctx, dtls_peer_t *peer)
{
  int res;

  res = dtls_send_server_hello(ctx, peer);

  if (res < 0) {
    debug("dtls_server_hello: cannot prepare ServerHello record\n");
    return res;
  }

  if (OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8) {
    const dtls_ecdsa_key_t *ecdsa_key;

    res = CALL(ctx, get_ecdsa_key, &peer->session, &ecdsa_key);
    if (res < 0) {
      dsrv_log(LOG_CRIT, "no ecdsa certificate to send in certificate\n");
      return res;
    }

    res = dtls_send_certificate_ecdsa(ctx, peer, ecdsa_key);

    if (res < 0) {
      debug("dtls_server_hello: cannot prepare Certificate record\n");
      return res;
    }

    res = dtls_send_server_key_exchange_ecdh(ctx, peer, ecdsa_key);

    if (res < 0) {
      debug("dtls_server_hello: cannot prepare Server Key Exchange record\n");
      return res;
    }

    if (OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 &&
	ctx && ctx->h && ctx->h->verify_ecdsa_key) {
      res = dtls_send_server_certificate_request(ctx, peer);

      if (res < 0) {
        debug("dtls_server_hello: cannot prepare certificate Request record\n");
        return res;
      }
    }
  }

  res = dtls_send_server_hello_done(ctx, peer);

  if (res < 0) {
    debug("dtls_server_hello: cannot prepare ServerHelloDone record\n");
    return res;
  }
  return 0;
}

static inline int 
dtls_send_ccs(dtls_context_t *ctx, dtls_peer_t *peer) {
  uint8 buf[1];
  buf[0] = 1;

  return dtls_send(ctx, peer, DTLS_CT_CHANGE_CIPHER_SPEC, buf, 1);
}

    
int
dtls_send_client_key_exchange(dtls_context_t *ctx, dtls_peer_t *peer,
			      dtls_security_parameters_t *config)
{
  uint8 buf[DTLS_CKXEC_LENGTH];
  uint8 *p;
  size_t size;

  switch (config->cipher) {
  case TLS_PSK_WITH_AES_128_CCM_8: {
    const dtls_psk_key_t *psk;

    if (CALL(ctx, get_psk_key, &peer->session, NULL, 0, &psk) < 0) {
      dsrv_log(LOG_CRIT, "no psk key to send in kx\n");
      return -2;
    }

    size = psk->id_length + sizeof(uint16);
    p = buf;

    dtls_int_to_uint16(p, psk->id_length);
    memcpy(p + sizeof(uint16), psk->id, psk->id_length);
    p += size;

    break;
  }
  case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: {
    uint8 *ephemeral_pub_x;
    uint8 *ephemeral_pub_y;

    size = DTLS_CKXEC_LENGTH;

    p = buf;

    dtls_int_to_uint8(p, 1 + 2 * DTLS_EC_KEY_SIZE);
    p += sizeof(uint8);

    /* This should be an uncompressed point, but I do not have access to the sepc. */
    dtls_int_to_uint8(p, 4);
    p += sizeof(uint8);

    ephemeral_pub_x = p;
    p += DTLS_EC_KEY_SIZE;
    ephemeral_pub_y = p;
    p += DTLS_EC_KEY_SIZE;

    dtls_ecdsa_generate_key(OTHER_CONFIG(peer)->ecdsa.own_eph_priv,
    			    ephemeral_pub_x, ephemeral_pub_y,
    			    DTLS_EC_KEY_SIZE);

    break;
  }
  default:
    dsrv_log(LOG_CRIT, "cipher not supported\n");
    return -3;
  }

  assert(p - buf <= sizeof(buf));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CLIENT_KEY_EXCHANGE,
				 buf, p - buf);
}

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

  /* sha256 */
  dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_SHA256);
  p += sizeof(uint8);

  /* ecdsa */
  dtls_int_to_uint8(p, TLS_EXT_SIG_HASH_ALGO_ECDSA);
  p += sizeof(uint8);

  copy_hs_hash(peer, &hs_hash);

  dtls_hash_finalize(sha256hash, &hs_hash);

  /* sign the ephemeral and its paramaters */
  dtls_ecdsa_create_sig_hash(key->priv_key, DTLS_EC_KEY_SIZE,
			     sha256hash, sizeof(sha256hash),
			     point_r, point_s);

  p = dtls_add_ecdsa_signature_elem(p, point_r, point_s);

  assert(p - buf <= sizeof(buf));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_CERTIFICATE_VERIFY,
				 buf, p - buf);
}

#define msg_overhead(Peer,Length) (DTLS_RH_LENGTH +	\
  ((Length + dtls_kb_iv_size(CURRENT_CONFIG(Peer)) + \
    dtls_kb_digest_size(CURRENT_CONFIG(Peer))) /     \
   DTLS_BLK_LENGTH + 1) * DTLS_BLK_LENGTH)

int
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

  dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   label, labellen,
	   PRF_LABEL(finished), PRF_LABEL_SIZE(finished), 
	   hash, length,
	   p, DTLS_FIN_LENGTH);

  dtls_dsrv_hexdump_log(LOG_DEBUG, "server finished MAC", p, DTLS_FIN_LENGTH, 0);

  p += DTLS_FIN_LENGTH;

  assert(p - buf <= sizeof(buf));

  return dtls_send_handshake_msg(ctx, peer, DTLS_HT_FINISHED,
				 buf, p - buf);
}

static int
dtls_send_client_hello(dtls_context_t *ctx, dtls_peer_t *peer,
                       uint8 cookie[], size_t cookie_length) {
  uint8 buf[DTLS_CH_LENGTH_MAX];
  uint8 *p = buf;
  uint8_t cipher_size;
  uint8_t extension_size;
  int psk;
  int ecdsa;

  psk = is_psk_supported(ctx);
  ecdsa = is_ecdsa_supported(ctx, 1);

  cipher_size = 2 + ((ecdsa) ? 2 : 0) + ((psk) ? 2 : 0);
  extension_size = (ecdsa) ? 2 + 6 + 6 + 8 : 0;

  if (cipher_size == 0) {
    dsrv_log(LOG_CRIT, "no cipher callbacks implemented\n");
  }

  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  if (cookie_length == 0) {
    /* Set client random: First 4 bytes are the client's Unix timestamp,
     * followed by 28 bytes of generate random data. */
    dtls_int_to_uint32(&OTHER_CONFIG(peer)->client_random, clock_time());
    prng(OTHER_CONFIG(peer)->client_random + sizeof(uint32),
         sizeof(OTHER_CONFIG(peer)->client_random) - sizeof(uint32));
  }
  /* we must use the same Client Random as for the previous request */
  memcpy(p, OTHER_CONFIG(peer)->client_random,
	 sizeof(OTHER_CONFIG(peer)->client_random));
  p += sizeof(OTHER_CONFIG(peer)->client_random);

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

  /* add known cipher(s) */
  dtls_int_to_uint16(p, cipher_size - 2);
  p += sizeof(uint16);

  if (ecdsa) {
    dtls_int_to_uint16(p, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
    p += sizeof(uint16);
  }
  if (psk) {
    dtls_int_to_uint16(p, TLS_PSK_WITH_AES_128_CCM_8);
    p += sizeof(uint16);
  }

  /* compression method */
  dtls_int_to_uint8(p, 1);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, TLS_COMP_NULL);
  p += sizeof(uint8);

  if (extension_size) {
    /* length of the extensions */
    dtls_int_to_uint16(p, extension_size - 2);
    p += sizeof(uint16);
  }

  if (ecdsa) {
    /* client certificate type extension */
    dtls_int_to_uint16(p, TLS_EXT_CLIENT_CERIFICATE_TYPE);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 2);
    p += sizeof(uint16);

    /* length of the list */
    dtls_int_to_uint8(p, 1);
    p += sizeof(uint8);

    dtls_int_to_uint8(p, TLS_CERT_TYPE_OOB);
    p += sizeof(uint8);

    /* client certificate type extension */
    dtls_int_to_uint16(p, TLS_EXT_SERVER_CERIFICATE_TYPE);
    p += sizeof(uint16);

    /* length of this extension type */
    dtls_int_to_uint16(p, 2);
    p += sizeof(uint16);

    /* length of the list */
    dtls_int_to_uint8(p, 1);
    p += sizeof(uint8);

    dtls_int_to_uint8(p, TLS_CERT_TYPE_OOB);
    p += sizeof(uint8);

    /* elliptic_curves */
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
  }

  assert(p - buf <= sizeof(buf));

  return dtls_send_handshake_msg_hash(ctx, peer, &peer->session,
				      DTLS_HT_CLIENT_HELLO,
				      buf, p - buf, cookie_length != 0);
}

static int
check_server_hello(dtls_context_t *ctx, 
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length) {
  dtls_hello_verify_t *hv;
  int res;

  /* This function is called when we expect a ServerHello (i.e. we
   * have sent a ClientHello).  We might instead receive a HelloVerify
   * request containing a cookie. If so, we must repeat the
   * ClientHello with the given Cookie.
   */

  if (IS_SERVERHELLO(data, data_length)) {
    debug("handle ServerHello\n");

    update_hs_hash(peer, data, data_length);

    /* FIXME: check data_length before accessing fields */

    /* Get the server's random data and store selected cipher suite
     * and compression method (like dtls_update_parameters().
     * Then calculate master secret and wait for ServerHelloDone. When received,
     * send ClientKeyExchange (?) and ChangeCipherSpec + ClientFinished. */
    
    /* check server version */
    data += DTLS_HS_LENGTH;
    data_length -= DTLS_HS_LENGTH;
    
    if (dtls_uint16_to_int(data) != DTLS_VERSION) {
      dsrv_log(LOG_ALERT, "unknown DTLS version\n");
      goto error;
    }

    data += sizeof(uint16);	      /* skip version field */
    data_length -= sizeof(uint16);

    /* store server random data */
    memcpy(OTHER_CONFIG(peer)->server_random, data,
	   sizeof(OTHER_CONFIG(peer)->server_random));
    /* skip server random */
    data += sizeof(OTHER_CONFIG(peer)->server_random);
    data_length -= sizeof(OTHER_CONFIG(peer)->server_random);

    SKIP_VAR_FIELD(data, data_length, uint8); /* skip session id */
    
    /* Check cipher suite. As we offer all we have, it is sufficient
     * to check if the cipher suite selected by the server is in our
     * list of known cipher suites. Subsets are not supported. */
    OTHER_CONFIG(peer)->cipher = dtls_uint16_to_int(data);
    if (!known_cipher(ctx, OTHER_CONFIG(peer)->cipher, 1)) {
      dsrv_log(LOG_ALERT, "unsupported cipher 0x%02x 0x%02x\n", 
	       data[0], data[1]);
      goto error;
    }
    data += sizeof(uint16);
    data_length -= sizeof(uint16);

    /* Check if NULL compression was selected. We do not know any other. */
    if (dtls_uint8_to_int(data) != TLS_COMP_NULL) {
      dsrv_log(LOG_ALERT, "unsupported compression method 0x%02x\n", data[0]);
      goto error;
    }

    /* FIXME: check PSK hint */

    return 0;
  }

  if (!IS_HELLOVERIFY(data, data_length)) {
    debug("no HelloVerify\n");
    return -1;
  }

  hv = (dtls_hello_verify_t *)(data + DTLS_HS_LENGTH);

  res = dtls_send_client_hello(ctx, peer, hv->cookie, hv->cookie_length);

  if (res < 0)
    warn("cannot send ClientHello\n");

 error: 
  return -1;
}

static int
check_server_certificate(dtls_context_t *ctx, 
			 dtls_peer_t *peer,
			 uint8 *data, size_t data_length)
{
  int err;
  dtls_security_parameters_t *config = OTHER_CONFIG(peer);

  if (!IS_CERTIFICATE(data, data_length))
    return -1;

  update_hs_hash(peer, data, data_length);

  assert(config->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

  data += DTLS_HS_LENGTH;

  if (dtls_uint24_to_int(data) != 94) {
    dsrv_log(LOG_ALERT, "expect length of 94 bytes for server certificate message\n");
    return -1;
  }
  data += sizeof(uint24);

  if (dtls_uint24_to_int(data) != 91) {
    dsrv_log(LOG_ALERT, "expect length of 91 bytes for certificate\n");
    return -1;
  }
  data += sizeof(uint24);

  if (memcmp(data, cert_asn1_header, sizeof(cert_asn1_header))) {
    dsrv_log(LOG_ALERT, "got an unexpected Subject public key format\n");
    return -1;
  }
  data += sizeof(cert_asn1_header);

  memcpy(config->ecdsa.other_pub_x, data,
	 sizeof(config->ecdsa.other_pub_x));
  data += sizeof(config->ecdsa.other_pub_x);

  memcpy(config->ecdsa.other_pub_y, data,
	 sizeof(config->ecdsa.other_pub_y));
  data += sizeof(config->ecdsa.other_pub_y);

  err = CALL(ctx, verify_ecdsa_key, &peer->session,
	     config->ecdsa.other_pub_x,
	     config->ecdsa.other_pub_y,
	     sizeof(config->ecdsa.other_pub_x));
  if (err < 0) {
    warn("The certificate was not accepted\n");
    return err;
  }

  return 0;
}

static int
check_server_key_exchange(dtls_context_t *ctx, 
			  dtls_peer_t *peer,
			  uint8 *data, size_t data_length)
{
  dtls_security_parameters_t *config = OTHER_CONFIG(peer);
  int i;
  unsigned char *result_r;
  unsigned char *result_s;
  unsigned char *key_params;

  if (!IS_SERVERKEYEXCHANGE(data, data_length))
    return -1;

  update_hs_hash(peer, data, data_length);

  assert(config->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

  data += DTLS_HS_LENGTH;

  if (data_length < DTLS_HS_LENGTH + DTLS_SKEXEC_LENGTH) {
    dsrv_log(LOG_ALERT, "the package length does not match the expected\n");
    return -1;
  }
  key_params = data;

  if (dtls_uint8_to_int(data) != 3) {
    dsrv_log(LOG_ALERT, "Only named curves supported\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint16_to_int(data) != 23) {
    dsrv_log(LOG_ALERT, "secp256r1 supported\n");
    return -1;
  }
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (dtls_uint8_to_int(data) != 65) {
    dsrv_log(LOG_ALERT, "expected 65 bytes long public point\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint8_to_int(data) != 4) {
    dsrv_log(LOG_ALERT, "expected uncompressed public point\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  memcpy(config->ecdsa.other_eph_pub_x, data, sizeof(config->ecdsa.other_eph_pub_y));
  data += sizeof(config->ecdsa.other_eph_pub_y);
  data_length -= sizeof(config->ecdsa.other_eph_pub_y);

  memcpy(config->ecdsa.other_eph_pub_y, data, sizeof(config->ecdsa.other_eph_pub_y));
  data += sizeof(config->ecdsa.other_eph_pub_y);
  data_length -= sizeof(config->ecdsa.other_eph_pub_y);


  if (data_length < dtls_uint16_to_int(data)) {
    dsrv_log(LOG_ALERT, "signature length wrong\n");
    return -1;
  }
  data += sizeof(uint16);
  data_length -= sizeof(uint16);

  if (dtls_uint8_to_int(data) != 0x30) {
    dsrv_log(LOG_ALERT, "wrong ASN.1 struct, expected SEQUENCE\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (data_length < dtls_uint8_to_int(data)) {
    dsrv_log(LOG_ALERT, "signature length wrong\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  if (dtls_uint8_to_int(data) != 0x02) {
    dsrv_log(LOG_ALERT, "wrong ASN.1 struct, expected Integer\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  /* Sometimes these values have a leeding 0 byte */
  result_r = data + i - DTLS_EC_KEY_SIZE;

  data += i;
  data_length -= i;

  if (dtls_uint8_to_int(data) != 0x02) {
    dsrv_log(LOG_ALERT, "wrong ASN.1 struct, expected Integer\n");
    return -1;
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

  /* Sometimes these values have a leeding 0 byte */
  result_s = data + i - DTLS_EC_KEY_SIZE;

  data += i;
  data_length -= i;

  i = dtls_ecdsa_verify_sig(config->ecdsa.other_pub_x, config->ecdsa.other_pub_y,
  			    sizeof(config->ecdsa.other_pub_x),
			    config->client_random, sizeof(config->client_random),
			    config->server_random, sizeof(config->server_random),
			    key_params,
			    1 + 2 + 1 + 1 + (2 * DTLS_EC_KEY_SIZE),
			    result_r, result_s);

  if (i < 0) {
    dsrv_log(LOG_ALERT, "wrong signature\n");
    return i;
  }
  return 0;
}

static int
check_certificate_request(dtls_context_t *ctx, 
			  dtls_peer_t *peer,
			  uint8 *data, size_t data_length)
{
  int i;
  int auth_alg;
  int sig_alg;
  int hash_alg;

  if (!IS_CERTIFICATEREQUEST(data, data_length))
    return -1;

  update_hs_hash(peer, data, data_length);

  assert(OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

  data += DTLS_HS_LENGTH;

  if (data_length < DTLS_HS_LENGTH + 5) {
    dsrv_log(LOG_ALERT, "the package length does not match the expected\n");
    return -1;
  }

  i = dtls_uint8_to_int(data);
  data += sizeof(uint8);
  if (i + 1 > data_length) {
    dsrv_log(LOG_ALERT, "the cerfificate types are too long\n");
    return -1;
  }

  auth_alg = 0;
  for (; i > 0 ; i -= sizeof(uint8)) {
    if (dtls_uint8_to_int(data) == 64 && auth_alg == 0)
      auth_alg = dtls_uint8_to_int(data);
    data += sizeof(uint8);
  }

  if (auth_alg != 64) {
    dsrv_log(LOG_ALERT, "the request authentication algorithem is not supproted\n");
    return -1;
  }

  i = dtls_uint16_to_int(data);
  data += sizeof(uint16);
  if (i + 1 > data_length) {
    dsrv_log(LOG_ALERT, "the signature and hash algorithm list is too long\n");
    return -1;
  }

  hash_alg = 0;
  sig_alg = 0;
  for (; i > 0 ; i -= sizeof(uint16)) {
    int current_hash_alg;
    int current_sig_alg;

    current_hash_alg = dtls_uint8_to_int(data);
    data += sizeof(uint8);
    current_sig_alg = dtls_uint8_to_int(data);
    data += sizeof(uint8);

    if (current_hash_alg == 4 && hash_alg == 0 && 
        current_sig_alg == 3 && sig_alg == 0) {
      hash_alg = current_hash_alg;
      sig_alg = current_sig_alg;
    }
  }

  if (hash_alg != 4 || sig_alg != 3) {
    dsrv_log(LOG_ALERT, "no supported hash and signature algorithem\n");
    return -1;
  }

  /* common names are ignored */

  OTHER_CONFIG(peer)->do_client_auth = 1;
  return 0;
}

static int
check_server_hellodone(dtls_context_t *ctx, 
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length)
{
  int res;
  const dtls_ecdsa_key_t *ecdsa_key;

  /* calculate master key, send CCS */
  if (!IS_SERVERHELLODONE(data, data_length))
    return -1;
  
  update_hs_hash(peer, data, data_length);

  if (OTHER_CONFIG(peer)->do_client_auth) {

    res = CALL(ctx, get_ecdsa_key, &peer->session, &ecdsa_key);
    if (res < 0) {
      dsrv_log(LOG_CRIT, "no ecdsa certificate to send in certificate\n");
      return res;
    }

    res = dtls_send_certificate_ecdsa(ctx, peer, ecdsa_key);

    if (res < 0) {
      debug("dtls_server_hello: cannot prepare Certificate record\n");
      return res;
    }
  }

  /* send ClientKeyExchange */
  res = dtls_send_client_key_exchange(ctx, peer, OTHER_CONFIG(peer));

  if (res < 0) {
    debug("cannot send KeyExchange message\n");
    return res;
  }

  if (OTHER_CONFIG(peer)->do_client_auth) {

    res = dtls_send_certificate_verify_ecdh(ctx, peer, ecdsa_key);

    if (res < 0) {
      debug("dtls_server_hello: cannot prepare Certificate record\n");
      return res;
    }
  }

  res = calculate_key_block(ctx, OTHER_CONFIG(peer), &peer->session,
			    OTHER_CONFIG(peer)->client_random,
			    OTHER_CONFIG(peer)->server_random);
  if (res < 0) {
    return res;
  }

  res = init_cipher(OTHER_CONFIG(peer));
  if (res < 0) {
    return res;
  }

  /* and switch cipher suite */
  res = dtls_send_ccs(ctx, peer);
  if (res < 0) {
    debug("cannot send CCS message\n");
    return res;
  }

  SWITCH_CONFIG(peer);
  inc_uint(uint16, peer->epoch);
  memset(peer->rseq, 0, sizeof(peer->rseq));

  dtls_debug_keyblock(CURRENT_CONFIG(peer));

  /* Client Finished */
  debug ("send Finished\n");
  return dtls_send_finished(ctx, peer, PRF_LABEL(client), PRF_LABEL_SIZE(client));
}

int
decrypt_verify(dtls_peer_t *peer,
	       uint8 *packet, size_t length,
	       uint8 **cleartext, size_t *clen) {
  int ok = 0;
  
  *cleartext = (uint8 *)packet + sizeof(dtls_record_header_t);
  *clen = length - sizeof(dtls_record_header_t);

  if (CURRENT_CONFIG(peer)->cipher == TLS_NULL_WITH_NULL_NULL) {
    /* no cipher suite selected */
    return 1;
  } else {			/* TLS_PSK_WITH_AES_128_CCM_8 */   
    dtls_cipher_context_t *cipher_context;
    /** 
     * length of additional_data for the AEAD cipher which consists of
     * seq_num(2+6) + type(1) + version(2) + length(2)
     */
#define A_DATA_LEN 13
#define A_DATA N
    unsigned char N[max(DTLS_CCM_BLOCKSIZE, A_DATA_LEN)];
    long int len;


    if (*clen < 16)		/* need at least IV and MAC */
      return -1;

    memset(N, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(N, dtls_kb_remote_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));

    /* read epoch and seq_num from message */
    memcpy(N + dtls_kb_iv_size(CURRENT_CONFIG(peer)), *cleartext, 8);
    *cleartext += 8;
    *clen -= 8;

    cipher_context = CURRENT_CONFIG(peer)->read_cipher;
    
    if (!cipher_context) {
      warn("no read_cipher available!\n");
      return 0;
    }

    dtls_dsrv_hexdump_log(LOG_DEBUG, "nonce", N, DTLS_CCM_BLOCKSIZE, 0);
    dtls_dsrv_hexdump_log(LOG_DEBUG, "key",
			  dtls_kb_remote_write_key(CURRENT_CONFIG(peer)),
			  dtls_kb_key_size(CURRENT_CONFIG(peer)), 0);
    dtls_dsrv_hexdump_log(LOG_DEBUG, "ciphertext", *cleartext, *clen, 0);

    dtls_cipher_set_iv(cipher_context, N, DTLS_CCM_BLOCKSIZE);

    /* re-use N to create additional data according to RFC 5246, Section 6.2.3.3:
     * 
     * additional_data = seq_num + TLSCompressed.type +
     *                   TLSCompressed.version + TLSCompressed.length;
     */
    memcpy(A_DATA, &DTLS_RECORD_HEADER(packet)->epoch, 8); /* epoch and seq_num */
    memcpy(A_DATA + 8,  &DTLS_RECORD_HEADER(packet)->content_type, 3); /* type and version */
    dtls_int_to_uint16(A_DATA + 11, *clen - 8); /* length without nonce_explicit */

    len = dtls_decrypt(cipher_context, *cleartext, *clen, *cleartext,
		       A_DATA, A_DATA_LEN);

    ok = len >= 0;
    if (!ok)
      warn("decryption failed\n");
    else {
#ifndef NDEBUG
      printf("decrypt_verify(): found %ld bytes cleartext\n", len);
#endif
      *clen = len;
    }
    dtls_dsrv_hexdump_log(LOG_DEBUG, "cleartext", *cleartext, *clen, 0);
  }

  return ok;
}


int
handle_handshake(dtls_context_t *ctx, dtls_peer_t *peer, 
		 uint8 *record_header, uint8 *data, size_t data_length) {

  int err = 0;

  /* The following switch construct handles the given message with
   * respect to the current internal state for this peer. In case of
   * error, it is left with return 0. */

  switch (peer->state) {

  /************************************************************************
   * Client states
   ************************************************************************/

  case DTLS_STATE_CLIENTHELLO:
    /* here we expect a HelloVerify or ServerHello */

    debug("DTLS_STATE_CLIENTHELLO\n");
    err = check_server_hello(ctx, peer, data, data_length);
    if (err < 0) {
      warn("error in check_server_hello err: %i\n", err);
      return err;
    }
    if (OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
      peer->state = DTLS_STATE_WAIT_SERVERCERTIFICATE;
    else
      peer->state = DTLS_STATE_WAIT_SERVERHELLODONE;
    /* update_hs_hash(peer, data, data_length); */

    break;

  case DTLS_STATE_WAIT_SERVERCERTIFICATE:
    /* expect a Certificate */

    debug("DTLS_STATE_WAIT_SERVERCERTIFICATE\n");

    err = check_server_certificate(ctx, peer, data, data_length);
    if (err < 0) {
      warn("error in check_server_certificate err: %i\n", err);
      return err;
    }
    peer->state = DTLS_STATE_WAIT_SERVERKEYEXCHANGE;
    /* update_hs_hash(peer, data, data_length); */

    break;

  case DTLS_STATE_WAIT_SERVERKEYEXCHANGE:
    /* expect a ServerKeyExchange */

    debug("DTLS_STATE_WAIT_SERVERKEYEXCHANGE\n");

    err = check_server_key_exchange(ctx, peer, data, data_length);
    if (err < 0) {
      warn("error in check_server_key_exchange err: %i\n", err);
      return err;
    }
    peer->state = DTLS_STATE_WAIT_SERVERHELLODONE;
    /* update_hs_hash(peer, data, data_length); */

    break;
  case DTLS_STATE_WAIT_SERVERHELLODONE:
    /* expect a ServerHelloDone */

    debug("DTLS_STATE_WAIT_SERVERHELLODONE\n");

    /* TODO: use the hadnshae type in state machine */
    if (IS_CERTIFICATEREQUEST(data, data_length)) {
      err = check_certificate_request(ctx, peer, data, data_length);
      if (err < 0) {
        warn("error in check_certificate_request err: %i\n", err);
        return err;
      }
    } else {
      err = check_server_hellodone(ctx, peer, data, data_length);
      if (err < 0) {
        warn("error in check_server_hellodone err: %i\n", err);
        return err;
      }
      peer->state = DTLS_STATE_WAIT_SERVERFINISHED;
      /* update_hs_hash(peer, data, data_length); */
    }

    break;

  case DTLS_STATE_WAIT_SERVERFINISHED:
    /* expect a Finished message from server */

    debug("DTLS_STATE_WAIT_SERVERFINISHED\n");
    err = check_finished(ctx, peer, record_header, data, data_length);
    if (err < 0) {
      warn("error in check_finished err: %i\n", err);
      return err;
    }
    peer->state = DTLS_STATE_CONNECTED;

    break;

  /************************************************************************
   * Server states
   ************************************************************************/
  case DTLS_STATE_WAIT_CLIENTCERTIFICATE:
    /* expect a Certificate */

    debug("DTLS_STATE_WAIT_SERVERCERTIFICATE\n");
    err = check_server_certificate(ctx, peer, data, data_length);
    if (err < 0) {
      warn("error in check_server_certificate err: %i\n", err);
      return err;
    }
    peer->state = DTLS_STATE_WAIT_CLIENTKEYEXCHANGE;
    /* update_hs_hash(peer, data, data_length); */
    break;

  case DTLS_STATE_WAIT_CLIENTKEYEXCHANGE:
    /* here we expect a ClientHello */
    /* handle ClientHello, update msg and msglen and goto next if not finished */

    debug("DTLS_STATE_WAIT_CLIENTKEYEXCHANGE\n");
    err = check_client_keyexchange(ctx, peer, data, data_length);
    if (err < 0) {
      warn("error in check_client_keyexchange err: %i\n", err);
      return err;
    }
    update_hs_hash(peer, data, data_length);

    if (OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 &&
	ctx && ctx->h && ctx->h->verify_ecdsa_key)
      peer->state = DTLS_STATE_WAIT_CERTIFICATEVERIFY;
    else
      peer->state = DTLS_STATE_WAIT_CLIENTCHANGECIPHERSPEC;
    break;

  case DTLS_STATE_WAIT_CERTIFICATEVERIFY:
    /* expect a Certificate */

    debug("DTLS_STATE_WAIT_CERTIFICATEVERIFY\n");

    err = check_client_certificate_verify(ctx, peer, data, data_length);
    if (err < 0) {
      warn("error in check_client_certificate_verify err: %i\n", err);
      return err;
    }

    update_hs_hash(peer, data, data_length);
    peer->state = DTLS_STATE_WAIT_CLIENTCHANGECIPHERSPEC;
    break;

  case DTLS_STATE_WAIT_FINISHED:
    debug("DTLS_STATE_WAIT_FINISHED\n");
    err = check_finished(ctx, peer, record_header, data, data_length);

    if (err < 0) {
      warn("error in check_finished err: %i\n", err);
      return err;
    }

    debug("finished!\n");
	
    /* send ServerFinished */
    update_hs_hash(peer, data, data_length);

    if (dtls_send_finished(ctx, peer, PRF_LABEL(server),
			   PRF_LABEL_SIZE(server)) > 0) {
      peer->state = DTLS_STATE_CONNECTED;
    } else {
      warn("sending server Finished failed\n");
    }
    break;
      
  case DTLS_STATE_CONNECTED:
    /* At this point, we have a good relationship with this peer. This
     * state is left for re-negotiation of key material. */
    
    debug("DTLS_STATE_CONNECTED\n");

    /* renegotiation */
    err = dtls_verify_peer(ctx, peer, &peer->session, record_header, data,
			   data_length);
    if (err < 0) {
      warn("error in dtls_verify_peer err: %i\n", err);
      return err;
    }

    clear_hs_hash(peer);

    err = dtls_update_parameters(ctx, peer, data, data_length);
    if (err < 0) {

      warn("error updating security parameters\n");
      dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_WARNING,
		 DTLS_ALERT_NO_RENEGOTIATION);
      return err;
    }

    /* update finish MAC */
    update_hs_hash(peer, data, data_length);

    if (dtls_send_server_hello_msgs(ctx, peer) > 0) {
      if (OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 &&
	  ctx && ctx->h && ctx->h->verify_ecdsa_key)
        peer->state = DTLS_STATE_WAIT_CLIENTCERTIFICATE;
      else
        peer->state = DTLS_STATE_WAIT_CLIENTKEYEXCHANGE;
    }

    /* after sending the ServerHelloDone, we expect the
     * ClientKeyExchange (possibly containing the PSK id),
     * followed by a ChangeCipherSpec and an encrypted Finished.
     */

    break;
    
  case DTLS_STATE_INIT:	      /* these states should not occur here */
  case DTLS_STATE_WAIT_CLIENTCHANGECIPHERSPEC:
  default:
    dsrv_log(LOG_CRIT, "unhandled state %d\n", peer->state);
    err = -1;
    assert(0);
  }

  return err;
}

int
handle_ccs(dtls_context_t *ctx, dtls_peer_t *peer, 
	   uint8 *record_header, uint8 *data, size_t data_length)
{
  int err;

  /* A CCS message is handled after a KeyExchange message was
   * received from the client. When security parameters have been
   * updated successfully and a ChangeCipherSpec message was sent
   * by ourself, the security context is switched and the record
   * sequence number is reset. */
  
  if (peer->state != DTLS_STATE_WAIT_CLIENTCHANGECIPHERSPEC
      || !check_ccs(ctx, peer, record_header, data, data_length)) {
    /* signal error? */
    warn("expected ChangeCipherSpec during handshake\n");
    return -1;

  }

  err = calculate_key_block(ctx, OTHER_CONFIG(peer), &peer->session,
			    OTHER_CONFIG(peer)->client_random,
			    OTHER_CONFIG(peer)->server_random);
  if (err < 0) {
    return err;
  }

  if (init_cipher(OTHER_CONFIG(peer))) {
    return -1;
  }

  /* send change cipher spec message and switch to new configuration */
  if (dtls_send_ccs(ctx, peer) < 0) {
    warn("cannot send CCS message");
    return -1;
  } 
  
  SWITCH_CONFIG(peer);
  inc_uint(uint16, peer->epoch);
  memset(peer->rseq, 0, sizeof(peer->rseq));
  
  peer->state = DTLS_STATE_WAIT_FINISHED;

  dtls_debug_keyblock(CURRENT_CONFIG(peer));

  return 0;
}  

/** 
 * Handles incoming Alert messages. This function returns \c 1 if the
 * connection should be closed and the peer is to be invalidated.
 */
int
handle_alert(dtls_context_t *ctx, dtls_peer_t *peer, 
	     uint8 *record_header, uint8 *data, size_t data_length) {
  int free_peer = -1;		/* indicates whether to free peer */

  if (data_length < 2)
    return -1;

  info("** Alert: level %d, description %d\n", data[0], data[1]);

  /* The peer object is invalidated for FATAL alerts and close
   * notifies. This is done in two steps.: First, remove the object
   * from our list of peers. After that, the event handler callback is
   * invoked with the still existing peer object. Finally, the storage
   * used by peer is released.
   */
  if (data[0] == DTLS_ALERT_LEVEL_FATAL || data[1] == DTLS_ALERT_CLOSE_NOTIFY) {
    dsrv_log(LOG_ALERT, "%d invalidate peer\n", data[1]);
    
#ifndef WITH_CONTIKI
    HASH_DEL_PEER(ctx->peers, peer);
#else /* WITH_CONTIKI */
    list_remove(ctx->peers, peer);

#ifndef NDEBUG
    PRINTF("removed peer [");
    PRINT6ADDR(&peer->session.addr);
    PRINTF("]:%d\n", uip_ntohs(peer->session.port));
#endif
#endif /* WITH_CONTIKI */

    free_peer = 0;

  }

  (void)CALL(ctx, event, &peer->session, 
	     (dtls_alert_level_t)data[0], (unsigned short)data[1]);
  switch (data[1]) {
  case DTLS_ALERT_CLOSE_NOTIFY:
    /* If state is DTLS_STATE_CLOSING, we have already sent a
     * close_notify so, do not send that again. */
    if (peer->state != DTLS_STATE_CLOSING) {
      peer->state = DTLS_STATE_CLOSING;
      dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_CLOSE_NOTIFY);
    } else
      peer->state = DTLS_STATE_CLOSED;
    break;
  default:
    ;
  }
  
  if (free_peer) {
    dtls_stop_retransmission(ctx, peer);
    dtls_free_peer(peer);
  }

  return free_peer;
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
  uint8 *data; 			/* (decrypted) payload */
  size_t data_length;		/* length of decrypted payload 
				   (without MAC and padding) */
  int err;

  peer = dtls_get_peer(ctx, session);

  if (!peer) {
    debug("dtls_handle_message: PEER NOT FOUND\n");
    dtls_dsrv_log_addr(LOG_DEBUG, "peer addr", session);
  } else {
    debug("dtls_handle_message: FOUND PEER\n");
  }

  if (!peer) {			

    /* get first record from client message */
    rlen = is_record(msg, msglen);
    assert(rlen <= msglen);

    if (!rlen) {
#ifndef NDEBUG
      if (msglen > 3) 
	debug("dropped invalid message %02x%02x%02x%02x\n", msg[0], msg[1], msg[2], msg[3]);
      else
	debug("dropped invalid message (less than four bytes)\n");
#endif
      return -1;
    }

    /* is_record() ensures that msg contains at least a record header */
    data = msg + DTLS_RH_LENGTH;
    data_length = rlen - DTLS_RH_LENGTH;

    /* When no DTLS state exists for this peer, we only allow a
       Client Hello message with 
        
       a) a valid cookie, or 
       b) no cookie.

       Anything else will be rejected. Fragementation is not allowed
       here as it would require peer state as well.
    */

    if (dtls_verify_peer(ctx, NULL, session, msg, data, data_length) <= 0) {
      warn("cannot verify peer\n");
      return -1;
    }
    
    /* msg contains a Client Hello with a valid cookie, so we can
       safely create the server state machine and continue with
       the handshake. */

    peer = dtls_new_peer(ctx, session);
    if (!peer) {
      dsrv_log(LOG_ALERT, "cannot create peer");
      /* FIXME: signal internal error */
      return -1;
    }

    /* Initialize record sequence number to 1 for new peers. The first
     * record with sequence number 0 is a stateless Hello Verify Request.
     */
    peer->rseq[5] = 1;

    /* First negotiation step: check for PSK
     *
     * Note that we already have checked that msg is a Handshake
     * message containing a ClientHello. dtls_get_cipher() therefore
     * does not check again.
     */
    err = dtls_update_parameters(ctx, peer, msg + DTLS_RH_LENGTH,
				 rlen - DTLS_RH_LENGTH);
    if (err < 0) {

      warn("error updating security parameters\n");
      /* FIXME: send handshake failure Alert */
      dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, 
		 DTLS_ALERT_HANDSHAKE_FAILURE);
      dtls_free_peer(peer);
      return err;
    }

#ifndef WITH_CONTIKI
    HASH_ADD_PEER(ctx->peers, session, peer);
#else /* WITH_CONTIKI */
    list_add(ctx->peers, peer);
#endif /* WITH_CONTIKI */
    
    /* update finish MAC */
    update_hs_hash(peer, msg + DTLS_RH_LENGTH, rlen - DTLS_RH_LENGTH); 
 
    if (!dtls_send_server_hello_msgs(ctx, peer)) {
      if (OTHER_CONFIG(peer)->cipher == TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 &&
	  ctx && ctx->h && ctx->h->verify_ecdsa_key)
        peer->state = DTLS_STATE_WAIT_CLIENTCERTIFICATE;
      else
        peer->state = DTLS_STATE_WAIT_CLIENTKEYEXCHANGE;
    }
    
    /* after sending the ServerHelloDone, we expect the 
     * ClientKeyExchange (possibly containing the PSK id),
     * followed by a ChangeCipherSpec and an encrypted Finished.
     */

    msg += rlen;
    msglen -= rlen;
  } else {
    debug("found peer\n");
  }

  /* At this point peer contains a state machine to handle the
     received message. */

  assert(peer);

  /* FIXME: check sequence number of record and drop message if the
   * number is not exactly the last number that we have responded to + 1. 
   * Otherwise, stop retransmissions for this specific peer and 
   * continue processing. */
  dtls_stop_retransmission(ctx, peer);

  while ((rlen = is_record(msg,msglen))) {

    debug("got packet %d (%d bytes)\n", msg[0], rlen);
    /* skip packet if it is from a different epoch */
    if (memcmp(DTLS_RECORD_HEADER(msg)->epoch, 
	       peer->epoch, sizeof(uint16)) != 0)
      goto next;

    if (!decrypt_verify(peer, msg, rlen, &data, &data_length)) {
      info("decrypt_verify() failed\n");
      goto next;
    }

    dtls_dsrv_hexdump_log(LOG_DEBUG, "receive header", msg,
			  sizeof(dtls_record_header_t), 1);
    dtls_dsrv_hexdump_log(LOG_DEBUG, "receive unencrypted", data, data_length, 1);

    /* Handle received record according to the first byte of the
     * message, i.e. the subprotocol. We currently do not support
     * combining multiple fragments of one type into a single
     * record. */

    switch (msg[0]) {

    case DTLS_CT_CHANGE_CIPHER_SPEC:
      err = handle_ccs(ctx, peer, msg, data, data_length);
      if (err < 0) {
        return err;
      }
      break;

    case DTLS_CT_ALERT:
      err = handle_alert(ctx, peer, msg, data, data_length);
      if (err < 0) {
	/* handle alert has invalidated peer */
	peer = NULL;
	return err;
      }

    case DTLS_CT_HANDSHAKE:
      err = handle_handshake(ctx, peer, msg, data, data_length);
      if (err < 0) {
        return err;
      }
      if (peer->state == DTLS_STATE_CONNECTED) {
	/* stop retransmissions */
	dtls_stop_retransmission(ctx, peer);
	CALL(ctx, event, &peer->session, 0, DTLS_EVENT_CONNECTED);
      }
      break;

    case DTLS_CT_APPLICATION_DATA:
      info("** application data:\n");
      CALL(ctx, read, &peer->session, data, data_length);
      break;
    default:
      info("dropped unknown message of type %d\n",msg[0]);
    }

  next:
    /* advance msg by length of ciphertext */
    msg += rlen;
    msglen -= rlen;
  }

  return 0;
}

dtls_context_t *
dtls_new_context(void *app_data) {
  dtls_context_t *c;

  prng_init(clock_time()); /* FIXME: need something better to init PRNG here */

  c = &the_dtls_context;

  memset(c, 0, sizeof(dtls_context_t));
  c->app = app_data;
  
  LIST_STRUCT_INIT(c, sendqueue);

#ifdef WITH_CONTIKI
  LIST_STRUCT_INIT(c, peers);
  /* LIST_STRUCT_INIT(c, key_store); */
  
  process_start(&dtls_retransmit_process, (char *)c);
  PROCESS_CONTEXT_BEGIN(&dtls_retransmit_process);
  /* the retransmit timer must be initialized to some large value */
  etimer_set(&c->retransmit_timer, 0xFFFF);
  PROCESS_CONTEXT_END(&coap_retransmit_process);
#endif /* WITH_CONTIKI */

  if (prng(c->cookie_secret, DTLS_COOKIE_SECRET_LENGTH))
    c->cookie_secret_age = clock_time();
  else 
    goto error;
  
  return c;

 error:
  dsrv_log(LOG_ALERT, "cannot create DTLS context");
  if (c)
    dtls_free_context(c);
  return NULL;
}

void dtls_free_context(dtls_context_t *ctx) {
  dtls_peer_t *p;
  
#ifndef WITH_CONTIKI
  dtls_peer_t *tmp;

  if (ctx->peers) {
    HASH_ITER(hh, ctx->peers, p, tmp) {
      dtls_free_peer(p);
    }
  }
#else /* WITH_CONTIKI */
  int i;

  p = (dtls_peer_t *)peer_storage.mem;
  for (i = 0; i < peer_storage.num; ++i, ++p) {
    if (peer_storage.count[i])
      dtls_free_peer(p);
  }
#endif /* WITH_CONTIKI */
}

int
dtls_connect(dtls_context_t *ctx, const session_t *dst) {
  dtls_peer_t *peer;
  int res;

  peer = dtls_get_peer(ctx, dst);
  
  if (peer) {
    debug("found peer, try to re-connect\n");
    /* FIXME: send HelloRequest if we are server, 
       ClientHello with good cookie if client */
    return 0;
  }

  peer = dtls_new_peer(ctx, dst);

  if (!peer) {
    dsrv_log(LOG_CRIT, "cannot create new peer\n");
    return -1;
  }
    
  /* set peer role to server: */
  OTHER_CONFIG(peer)->role = DTLS_SERVER;
  CURRENT_CONFIG(peer)->role = DTLS_SERVER;

#ifndef WITH_CONTIKI
  HASH_ADD_PEER(ctx->peers, session, peer);
#else /* WITH_CONTIKI */
  list_add(ctx->peers, peer);
#endif /* WITH_CONTIKI */

  /* send ClientHello with empty Cookie */
  res = dtls_send_client_hello(ctx, peer, NULL, 0);
  if (res < 0)
    warn("cannot send ClientHello\n");
  else 
    peer->state = DTLS_STATE_CLIENTHELLO;

  return res;
}

void
dtls_retransmit(dtls_context_t *context, netq_t *node) {
  if (!context || !node)
    return;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if (node->retransmit_cnt < DTLS_DEFAULT_MAX_RETRANSMIT) {
      unsigned char sendbuf[DTLS_MAX_BUF];
      size_t len = sizeof(sendbuf);

      node->retransmit_cnt++;
      node->t += (node->timeout << node->retransmit_cnt);
      netq_insert_node((netq_t **)context->sendqueue, node);
      
      debug("** retransmit packet\n");
      
      if (dtls_prepare_record(node->peer, DTLS_CT_HANDSHAKE, 
			      (uint8 **)&(node->data), &(node->length), 1,
			      sendbuf, &len) > 0) {

	dtls_dsrv_hexdump_log(LOG_DEBUG, "retransmit header", sendbuf,
			      sizeof(dtls_record_header_t), 1);
	dtls_dsrv_hexdump_log(LOG_DEBUG, "retransmit unencrypted", node->data,
			      node->length, 1);

	(void)CALL(context, write, &node->peer->session, sendbuf, len);
      }
      return;
  }

  /* no more retransmissions, remove node from system */
  
  debug("** removed transaction\n");

  /* And finally delete the node */
  netq_node_free(node);
}

void
dtls_stop_retransmission(dtls_context_t *context, dtls_peer_t *peer) {
  void *node;
  node = list_head((list_t)context->sendqueue); 

  while (node) {
    if (dtls_session_equals(&((netq_t *)node)->peer->session,
			    &peer->session)) {
      void *tmp = node;
      node = list_item_next(node);
      list_remove((list_t)context->sendqueue, tmp);
      netq_node_free((netq_t *)tmp);
    } else
      node = list_item_next(node);    
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

  debug("Started DTLS retransmit process\r\n");

  while(1) {
    PROCESS_YIELD();
    if (ev == PROCESS_EVENT_TIMER) {
      if (etimer_expired(&the_dtls_context.retransmit_timer)) {
	
	node = list_head(the_dtls_context.sendqueue);
	
	now = clock_time();
	while (node && node->t <= now) {
	  dtls_retransmit(&the_dtls_context, list_pop(the_dtls_context.sendqueue));
	  node = list_head(the_dtls_context.sendqueue);
	}

	/* need to set timer to some value even if no nextpdu is available */
	etimer_set(&the_dtls_context.retransmit_timer, 
		   node ? node->t - now : 0xFFFF);
      } 
    }
  }
  
  PROCESS_END();
}
#endif /* WITH_CONTIKI */
