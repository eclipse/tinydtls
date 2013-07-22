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

#include "config.h"
#include "dtls_time.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
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
#define DTLS_HV_LENGTH sizeof(dtls_hello_verify_t)
#define DTLS_SH_LENGTH (2 + 32 + 1 + 2 + 1)
#define DTLS_CKX_LENGTH 1
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
#define IS_SERVERHELLODONE(M,L) \
      ((L) >= DTLS_HS_LENGTH && (M)[0] == DTLS_HT_SERVER_HELLO_DONE)
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

uint8 _clear[DTLS_MAX_BUF]; /* target buffer message decryption */
uint8 _buf[DTLS_MAX_BUF]; /* target buffer for several crypto operations */

#ifndef NDEBUG
void hexdump(const unsigned char *packet, int length);
void dump(unsigned char *buf, size_t len);
#endif

/* some constants for the PRF */
#define PRF_LABEL(Label) prf_label_##Label
#define PRF_LABEL_SIZE(Label) (sizeof(PRF_LABEL(Label)) - 1)

static const unsigned char prf_label_master[] = "master secret";
static const unsigned char prf_label_key[] = "key expansion";
static const unsigned char prf_label_client[] = "client";
static const unsigned char prf_label_server[] = "server";
static const unsigned char prf_label_finished[] = " finished";

extern void netq_init();
extern void crypto_init();
extern void peer_init();

dtls_context_t the_dtls_context;

void
dtls_init() {
  dtls_clock_init();
  netq_init();
  crypto_init();
  peer_init();
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
dtls_get_peer(const dtls_context_t *ctx, const session_t *session) {
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

void
dtls_add_peer(dtls_context_t *ctx, dtls_peer_t *peer) {
#ifndef WITH_CONTIKI
  HASH_ADD_PEER(ctx->peers, session, peer);
#else /* WITH_CONTIKI */
  list_add(ctx->peers, peer);
#endif /* WITH_CONTIKI */
}

int
dtls_write(struct dtls_context_t *ctx, 
	   session_t *dst, uint8 *buf, size_t len) {
  
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
      return dtls_send(ctx, peer, DTLS_CT_APPLICATION_DATA, buf, len);
    }
  }
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

  dtls_hmac_update(&hmac_context, msg + DTLS_HS_LENGTH, e);
  
  /* skip cookie bytes and length byte */
  e += *(uint8 *)(msg + DTLS_HS_LENGTH + e) & 0xff;
  e += sizeof(uint8);

  dtls_hmac_update(&hmac_context, 
		   msg + DTLS_HS_LENGTH + e,
		   dtls_get_fragment_length(DTLS_HANDSHAKE_HEADER(msg)) - e);

  len = dtls_hmac_finalize(&hmac_context, buf);

  if (len < *clen) {
    memset(cookie + len, 0, *clen - len);
    *clen = len;
  }
  
  memcpy(cookie, buf, *clen);
  return 1;
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
		 uint8 *data, size_t data_length) {

  int len = DTLS_COOKIE_LENGTH;
  uint8 *cookie, *p;
#undef mycookie
#define mycookie (ctx->sendbuf + HV_HDR_LENGTH)

  /* check if we can access at least all fields from the handshake header */
  if (record[0] == DTLS_CT_HANDSHAKE
      && data_length >= DTLS_HS_LENGTH 
      && data[0] == DTLS_HT_CLIENT_HELLO) {

    /* Store cookie where we can reuse it for the HelloVerify request. */
    if (dtls_create_cookie(ctx, session, data, data_length,
			   mycookie, &len) < 0)
      return -1;
/* #ifndef NDEBUG */
/*     debug("create cookie: "); */
/*     dump(mycookie, len); */
/*     printf("\n"); */
/* #endif */
    assert(len == DTLS_COOKIE_LENGTH);
    
    /* Perform cookie check. */
    len = dtls_get_cookie(data, data_length, &cookie);

/* #ifndef NDEBUG */
/*     debug("compare with cookie: "); */
/*     dump(cookie, len); */
/*     printf("\n"); */
/* #endif */

    /* check if cookies match */
    if (len == DTLS_COOKIE_LENGTH && memcmp(cookie, mycookie, len) == 0) {
    debug("found matching cookie\n");
      return 1;      
    }
    if (len > 0) {
      debug("invalid cookie");
#ifndef NDEBUG
      dump(cookie, len);
      printf("\n");
#endif
    }
    /* ClientHello did not contain any valid cookie, hence we send a
     * HelloVerify request. */

    p = dtls_set_handshake_header(DTLS_HT_HELLO_VERIFY_REQUEST,
				  peer, DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH,
				  0, DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH, 
				  ctx->sendbuf + DTLS_RH_LENGTH);

    dtls_int_to_uint16(p, DTLS_VERSION);
    p += sizeof(uint16);

    dtls_int_to_uint8(p, DTLS_COOKIE_LENGTH);
    p += sizeof(uint8);

    assert(p == mycookie);
    
    p += DTLS_COOKIE_LENGTH;

    if (!peer) {
      /* It's an initial ClientHello, so we set the record header
       * manually and send the HelloVerify request using the
       * registered write callback. */

      dtls_set_record_header(DTLS_CT_HANDSHAKE, NULL, ctx->sendbuf);
      /* set packet length */
      dtls_int_to_uint16(ctx->sendbuf + 11, 
			 p - (ctx->sendbuf + DTLS_RH_LENGTH));

      (void)CALL(ctx, write, session, ctx->sendbuf, p - ctx->sendbuf);
    } else {
      if (peer->epoch) {
	debug("renegotiation, therefore we accept it anyway:");
	return 1;
      }

      if (dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		    ctx->sendbuf + DTLS_RH_LENGTH, 
		    p - (ctx->sendbuf + DTLS_RH_LENGTH)) < 0) {
	warn("cannot send HelloVerify request\n");
	return -1;
      }
  }

    return 0; /* HelloVerify is sent, now we cannot do anything but wait */
  }

  return -1;			/* not a ClientHello, signal error */
#undef mycookie
}

/** only one compression method is currently defined */
uint8 compression_methods[] = { 
  TLS_COMP_NULL 
};

/**
 * Returns @c 1 if @p code is a cipher suite other than @c
 * TLS_NULL_WITH_NULL_NULL that we recognize.
 *
 * @param code The cipher suite identifier to check
 * @return @c 1 iff @p code is recognized,
 */ 
static inline int
known_cipher(dtls_cipher_t code) {
  return code == TLS_PSK_WITH_AES_128_CCM_8;
}

int
calculate_key_block(dtls_context_t *ctx, 
		    dtls_security_parameters_t *config,
		    const dtls_key_t *key,
		    unsigned char client_random[32],
		    unsigned char server_random[32]) {
  unsigned char *pre_master_secret;
  size_t pre_master_len = 0;
  pre_master_secret = config->key_block;

  assert(key);
  switch (key->type) {
  case DTLS_KEY_PSK: {
  /* Temporarily use the key_block storage space for the pre master secret. */
    pre_master_len = dtls_pre_master_secret(key->key.psk.key, key->key.psk.key_length, 
					  pre_master_secret);
    
    break;
  }
  default:
    debug("calculate_key_block: unknown key type\n");
    return 0;
  }

/* #ifndef NDEBUG */
/*   { */
/*     int i; */

/*     printf("client_random:"); */
/*     for (i = 0; i < 32; ++i) */
/*       printf(" %02x", client_random[i]); */
/*     printf("\n"); */

/*     printf("server_random:"); */
/*     for (i = 0; i < 32; ++i) */
/*       printf(" %02x", server_random[i]); */
/*     printf("\n"); */

/*     printf("psk: (%lu bytes):", key->key.psk.key_length); */
/*     hexdump(key->key.psk.key, key->key.psk.key_length); */
/*     printf("\n"); */

/*     printf("pre_master_secret: (%lu bytes):", pre_master_len); */
/*     for (i = 0; i < pre_master_len; ++i) */
/*       printf(" %02x", pre_master_secret[i]); */
/*     printf("\n"); */
/*   } */
/* #endif /\* NDEBUG *\/ */

  dtls_prf(pre_master_secret, pre_master_len,
	   PRF_LABEL(master), PRF_LABEL_SIZE(master),
	   client_random, 32,
	   server_random, 32,
	   config->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH);

/* #ifndef NDEBUG */
/*   { */
/*     int i; */
/*     printf("master_secret (%d bytes):", DTLS_MASTER_SECRET_LENGTH); */
/*     for (i = 0; i < DTLS_MASTER_SECRET_LENGTH; ++i) */
/*       printf(" %02x", config->master_secret[i]); */
/*     printf("\n"); */
/*   } */
/* #endif /\* NDEBUG *\/ */

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

/* #ifndef NDEBUG */
/*   { */
/*       printf("key_block (%d bytes):\n", dtls_kb_size(config)); */
/*       printf("  client_MAC_secret:\t");   */
/*       dump(dtls_kb_client_mac_secret(config),  */
/* 	   dtls_kb_mac_secret_size(config)); */
/*       printf("\n"); */

/*       printf("  server_MAC_secret:\t");   */
/*       dump(dtls_kb_server_mac_secret(config),  */
/* 	   dtls_kb_mac_secret_size(config)); */
/*       printf("\n"); */

/*       printf("  client_write_key:\t");   */
/*       dump(dtls_kb_client_write_key(config),  */
/* 	   dtls_kb_key_size(config)); */
/*       printf("\n"); */

/*       printf("  server_write_key:\t");   */
/*       dump(dtls_kb_server_write_key(config),  */
/* 	   dtls_kb_key_size(config)); */
/*       printf("\n"); */

/*       printf("  client_IV:\t\t");   */
/*       dump(dtls_kb_client_iv(config),  */
/* 	   dtls_kb_iv_size(config)); */
/*       printf("\n"); */
      
/*       printf("  server_IV:\t\t");   */
/*       dump(dtls_kb_server_iv(config),  */
/* 	   dtls_kb_iv_size(config)); */
/*       printf("\n"); */
      

/*   } */
/* #endif */
  return 1;
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

    return 1;
  }

  data += sizeof(uint16);
  data_length -= sizeof(uint16) + i;

  ok = 0;
  while (i && !ok) {
    config->cipher = dtls_uint16_to_int(data);
    ok = known_cipher(config->cipher);
    i -= sizeof(uint16);
    data += sizeof(uint16);
  }

  /* skip remaining ciphers */
  data += i;

  if (!ok) {
    /* reset config cipher to a well-defined value */
    config->cipher = TLS_NULL_WITH_NULL_NULL;
    return 0;
  }

  if (data_length < sizeof(uint8)) { 
    /* no compression specified, take the current compression method */
    config->compression = CURRENT_CONFIG(peer)->compression;
    return 1;
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
  
  return ok;
 error:
  warn("ClientHello too short (%d bytes)\n", data_length);
  return 0;
}

static inline int
check_client_keyexchange(dtls_context_t *ctx, 
			 dtls_peer_t *peer,
			 uint8 *data, size_t length) {
  return length >= DTLS_CKX_LENGTH && data[0] == DTLS_HT_CLIENT_KEY_EXCHANGE;
}

static int
check_ccs(dtls_context_t *ctx, 
	  dtls_peer_t *peer,
	  uint8 *record, uint8 *data, size_t data_length) {

  if (DTLS_RECORD_HEADER(record)->content_type != DTLS_CT_CHANGE_CIPHER_SPEC
      || data_length < 1 || data[0] != 1)
    return 0;

  /* set crypto context for TLS_PSK_WITH_AES_128_CCM_8 */
  /* client */
  dtls_cipher_free(OTHER_CONFIG(peer)->read_cipher);

  assert(OTHER_CONFIG(peer)->cipher != TLS_NULL_WITH_NULL_NULL);
  OTHER_CONFIG(peer)->read_cipher = 
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
		    dtls_kb_client_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!OTHER_CONFIG(peer)->read_cipher) {
    warn("cannot create read cipher\n");
    return 0;
  }

  dtls_cipher_set_iv(OTHER_CONFIG(peer)->read_cipher,
		     dtls_kb_client_iv(OTHER_CONFIG(peer)),
		     dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* server */
  dtls_cipher_free(OTHER_CONFIG(peer)->write_cipher);
  
  OTHER_CONFIG(peer)->write_cipher = 
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
		    dtls_kb_server_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!OTHER_CONFIG(peer)->write_cipher) {
    warn("cannot create write cipher\n");
    return 0;
  }

  dtls_cipher_set_iv(OTHER_CONFIG(peer)->write_cipher,
		     dtls_kb_server_iv(OTHER_CONFIG(peer)),
		     dtls_kb_iv_size(OTHER_CONFIG(peer)));

  return 1;
}

#ifndef NDEBUG
extern size_t dsrv_print_addr(const session_t *, unsigned char *, size_t);
#endif

static inline void
update_hs_hash(dtls_peer_t *peer, uint8 *data, size_t length) {
/* #ifndef NDEBUG */
/*   printf("add MAC data: "); */
/*   dump(data, length); */
/*   printf("\n"); */
/* #endif */
  dtls_hash_update(&peer->hs_state.hs_hash, data, length);
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
    return 0;
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
  
/* #ifndef NDEBUG */
/*   printf("d:\t"); dump(data + DTLS_HS_LENGTH, sizeof(b.verify_data)); printf("\n"); */
/*   printf("v:\t"); dump(b.verify_data, sizeof(b.verify_data)); printf("\n"); */
/* #endif */
  return 
    memcmp(data + DTLS_HS_LENGTH, b.verify_data, sizeof(b.verify_data)) == 0;
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
		    uint8 *data, size_t data_length,
		    uint8 *sendbuf, size_t *rlen) {
  uint8 *p;
  int res;
  
  /* check the minimum that we need for packets that are not encrypted */
  if (*rlen < DTLS_RH_LENGTH + data_length) {
    debug("dtls_prepare_record: send buffer too small\n");
    return -1;
  }

  p = dtls_set_record_header(type, peer, sendbuf);

  if (CURRENT_CONFIG(peer)->cipher == TLS_NULL_WITH_NULL_NULL) {
    /* no cipher suite */
    memcpy(p, data, data_length);
    res = data_length;
  } else { /* TLS_PSK_WITH_AES_128_CCM_8 */   
    dtls_cipher_context_t *cipher_context;

    /** 
     * length of additional_data for the AEAD cipher which consists of
     * seq_num(2+6) + type(1) + version(2) + length(2)
     */
#define A_DATA_LEN 13
#define A_DATA N
    unsigned char N[max(DTLS_CCM_BLOCKSIZE, A_DATA_LEN)];
    
    if (*rlen < sizeof(dtls_record_header_t) + data_length + 8) {
      warn("dtls_prepare_record(): send buffer too small\n");
      return -1;
    }

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
    memcpy(p + 8, data, data_length);

    memset(N, 0, DTLS_CCM_BLOCKSIZE);
    memcpy(N, dtls_kb_local_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));
    memcpy(N + dtls_kb_iv_size(CURRENT_CONFIG(peer)), p, 8); /* epoch + seq_num */

    cipher_context = CURRENT_CONFIG(peer)->write_cipher;

    if (!cipher_context) {
      warn("no write_cipher available!\n");
      return -1;
    }
/* #ifndef NDEBUG */
/*     printf("nonce:\t"); */
/*     dump(N, DTLS_CCM_BLOCKSIZE); */
/*     printf("\nkey:\t"); */
/*     dump(dtls_kb_local_write_key(CURRENT_CONFIG(peer)),  */
/* 	 dtls_kb_key_size(CURRENT_CONFIG(peer))); */
/*     printf("\n"); */
/* #endif */
    dtls_cipher_set_iv(cipher_context, N, DTLS_CCM_BLOCKSIZE);
    
    /* re-use N to create additional data according to RFC 5246, Section 6.2.3.3:
     * 
     * additional_data = seq_num + TLSCompressed.type +
     *                   TLSCompressed.version + TLSCompressed.length;
     */
    memcpy(A_DATA, &DTLS_RECORD_HEADER(sendbuf)->epoch, 8); /* epoch and seq_num */
    memcpy(A_DATA + 8,  &DTLS_RECORD_HEADER(sendbuf)->content_type, 3); /* type and version */
    dtls_int_to_uint16(A_DATA + 11, data_length); /* length */
    
    res = dtls_encrypt(cipher_context, p + 8, data_length, p + 8,
		       A_DATA, A_DATA_LEN);

    if (res < 0)
      return -1;

/* #ifndef NDEBUG */
/*     dump(p, res + 8); */
/*     printf("\n"); */
/* #endif */
    res += 8;			/* increment res by size of nonce_explicit */
  }

  /* fix length of fragment in sendbuf */
  dtls_int_to_uint16(sendbuf + 11, res);
  
  *rlen = DTLS_RH_LENGTH + res;
  return 1;
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

  res = dtls_prepare_record(peer, type, buf, buflen, sendbuf, &len);

  if (res < 0)
    return res;

  /* if (peer && MUST_HASH(peer, type, buf, buflen)) */
  /*   update_hs_hash(peer, buf, buflen); */
  
/* #ifndef NDEBUG */
/*   debug("send %d bytes\n", buflen); */
/*   hexdump(sendbuf, sizeof(dtls_record_header_t)); */
/*   printf("\n"); */
/*   hexdump(buf, buflen); */
/*   printf("\n"); */
/* #endif */

  if (type == DTLS_CT_HANDSHAKE && buf[0] != DTLS_HT_HELLO_VERIFY_REQUEST) {
    /* copy handshake messages other than HelloVerify into retransmit buffer */
    netq_t *n = netq_node_new();
    if (n) {
      dtls_tick_t now;
      dtls_ticks(&now);
      n->t = now + 2 * CLOCK_SECOND;
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
#else /* WITH_CONTIKI */
	debug("copied to sendqueue\n");
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
    res = dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_CLOSE);
    /* indicate tear down */
    peer->state = DTLS_STATE_CLOSING;
  }
  return res;
}

int
dtls_send_server_hello(dtls_context_t *ctx, dtls_peer_t *peer) {

  static uint8 buf[DTLS_MAX_BUF];
  uint8 *p = buf, *q = ctx->sendbuf;
  size_t qlen = sizeof(ctx->sendbuf);
  int res;
  const dtls_key_t *key;
  dtls_tick_t now;

  /* Ensure that the largest message to create fits in our source
   * buffer. (The size of the destination buffer is checked by the
   * encoding function, so we do not need to guess.) */
  assert(sizeof(buf) >=
	 DTLS_RH_LENGTH + DTLS_HS_LENGTH + DTLS_SH_LENGTH + 20);

  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
    debug("dtls_send_server_hello(): no key for session available\n");
    return -1;
  }

  /* Handshake header */
  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO, 
				peer,
				DTLS_SH_LENGTH, 
				0, DTLS_SH_LENGTH,
				buf);

  /* ServerHello */
  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* Set server random: First 4 bytes are the server's Unix timestamp,
   * followed by 28 bytes of generate random data. */
  dtls_ticks(&now);
  dtls_int_to_uint32(p, now / CLOCK_SECOND);
  prng(p + 4, 28);

  if (!calculate_key_block(ctx, OTHER_CONFIG(peer), key, 
			   OTHER_CONFIG(peer)->client_random, p))
    return -1;

  p += 32;

  *p++ = 0;			/* no session id */

  if (OTHER_CONFIG(peer)->cipher != TLS_NULL_WITH_NULL_NULL) {
    /* selected cipher suite */
    dtls_int_to_uint16(p, OTHER_CONFIG(peer)->cipher);
    p += sizeof(uint16);

    /* selected compression method */
    if (OTHER_CONFIG(peer)->compression >= 0)
      *p++ = compression_methods[OTHER_CONFIG(peer)->compression];

    /* FIXME: if key->psk.id != NULL we need the server key exchange */

    /* update the finish hash 
       (FIXME: better put this in generic record_send function) */
    update_hs_hash(peer, buf, p - buf);
  }

  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE, 
			    buf, p - buf,
			    q, &qlen);
  if (res < 0) {
    debug("dtls_server_hello: cannot prepare ServerHello record\n");
    return res;
  }

  q += qlen;
  qlen = sizeof(ctx->sendbuf) - qlen;

  /* ServerHelloDone 
   *
   * Start message construction at beginning of buffer. */
  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO_DONE, 
				peer,
				0, /* ServerHelloDone has no extra fields */
				0, 0, /* ServerHelloDone has no extra fields */
				buf);

  /* update the finish hash 
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, buf, p - buf);

  res = dtls_prepare_record(peer, DTLS_CT_HANDSHAKE, 
			    buf, p - buf,
			    q, &qlen);
  if (res < 0) {
    debug("dtls_server_hello: cannot prepare ServerHelloDone record\n");
    return res;
  }

  return CALL(ctx, write, &peer->session,  
		  ctx->sendbuf, (q + qlen) - ctx->sendbuf);
}

static inline int 
dtls_send_ccs(dtls_context_t *ctx, dtls_peer_t *peer) {
  ctx->sendbuf[0] = 1;
  return dtls_send(ctx, peer, DTLS_CT_CHANGE_CIPHER_SPEC, ctx->sendbuf, 1);
}

    
int 
dtls_send_kx(dtls_context_t *ctx, dtls_peer_t *peer, int is_client) {
  const dtls_key_t *key;
  uint8 *p = ctx->sendbuf;
  size_t size;
  int ht = is_client 
    ? DTLS_HT_CLIENT_KEY_EXCHANGE 
    : DTLS_HT_SERVER_KEY_EXCHANGE;
  unsigned char *id = NULL;
  size_t id_len = 0;

  if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0) {
    dsrv_log(LOG_CRIT, "no key to send in kx\n");
    return -2;
  }

  assert(key);

  switch (key->type) {
  case DTLS_KEY_PSK: {
    id_len = key->key.psk.id_length;
    id = key->key.psk.id;
    break;
  }
  default:
    dsrv_log(LOG_CRIT, "key type not supported\n");
    return -3;
  }
  
  size = id_len + sizeof(uint16);
  p = dtls_set_handshake_header(ht, peer, size, 0, size, p);

  dtls_int_to_uint16(p, id_len);
  memcpy(p + sizeof(uint16), id, id_len);

  p += size;

  update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);
  return dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		   ctx->sendbuf, p - ctx->sendbuf);
}

#define msg_overhead(Peer,Length) (DTLS_RH_LENGTH +	\
  ((Length + dtls_kb_iv_size(CURRENT_CONFIG(Peer)) + \
    dtls_kb_digest_size(CURRENT_CONFIG(Peer))) /     \
   DTLS_BLK_LENGTH + 1) * DTLS_BLK_LENGTH)

int
dtls_send_server_finished(dtls_context_t *ctx, dtls_peer_t *peer) {

  int length;
  uint8 buf[DTLS_HMAC_MAX];
  uint8 *p = ctx->sendbuf;

  /* FIXME: adjust message overhead calculation */
  assert(msg_overhead(peer, DTLS_HS_LENGTH + DTLS_FIN_LENGTH) 
	 < sizeof(ctx->sendbuf));

  p = dtls_set_handshake_header(DTLS_HT_FINISHED, 
                                peer, DTLS_FIN_LENGTH, 0, DTLS_FIN_LENGTH, p);
  
  length = finalize_hs_hash(peer, buf);

  dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   PRF_LABEL(server), PRF_LABEL_SIZE(server), 
	   PRF_LABEL(finished), PRF_LABEL_SIZE(finished), 
	   buf, length,
	   p, DTLS_FIN_LENGTH);

/* #ifndef NDEBUG */
/*   printf("server finished MAC:\t"); */
/*   dump(p, DTLS_FIN_LENGTH); */
/*   printf("\n"); */
/* #endif */

  p += DTLS_FIN_LENGTH;

  return dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		   ctx->sendbuf, p - ctx->sendbuf);
}

static int
check_server_hello(dtls_context_t *ctx, 
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length) {
  dtls_hello_verify_t *hv;
  uint8 *p = ctx->sendbuf;
  size_t size;
  int res;
  const dtls_key_t *key;

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

    /* FIXME: check PSK hint */
    if (CALL(ctx, get_key, &peer->session, NULL, 0, &key) < 0
	|| !calculate_key_block(ctx, OTHER_CONFIG(peer), key, 
				OTHER_CONFIG(peer)->client_random, data)) {
      goto error;
    }
    /* store server random data */

    /* memcpy(OTHER_CONFIG(peer)->server_random, data, */
    /* 	   sizeof(OTHER_CONFIG(peer)->server_random)); */
    data += sizeof(OTHER_CONFIG(peer)->client_random);
    data_length -= sizeof(OTHER_CONFIG(peer)->client_random);

    SKIP_VAR_FIELD(data, data_length, uint8); /* skip session id */
    
    /* Check cipher suite. As we offer all we have, it is sufficient
     * to check if the cipher suite selected by the server is in our
     * list of known cipher suites. Subsets are not supported. */
    OTHER_CONFIG(peer)->cipher = dtls_uint16_to_int(data);
    if (!known_cipher(OTHER_CONFIG(peer)->cipher)) {
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

    return 1;
  }

  if (!IS_HELLOVERIFY(data, data_length)) {
    debug("no HelloVerify\n");
    return 0;
  }

  hv = (dtls_hello_verify_t *)(data + DTLS_HS_LENGTH);

  /* FIXME: dtls_send_client_hello(ctx,peer,cookie) */
  size = DTLS_CH_LENGTH + 8 + dtls_uint8_to_int(&hv->cookie_length);

  p = dtls_set_handshake_header(DTLS_HT_CLIENT_HELLO, peer, 
				size, 0, size, p);

  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* we must use the same Client Random as for the previous request */
  memcpy(p, OTHER_CONFIG(peer)->client_random, 
	 sizeof(OTHER_CONFIG(peer)->client_random));
  p += sizeof(OTHER_CONFIG(peer)->client_random);

  /* session id (length 0) */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, dtls_uint8_to_int(&hv->cookie_length));
  p += sizeof(uint8);
  memcpy(p, hv->cookie, dtls_uint8_to_int(&hv->cookie_length));
  p += dtls_uint8_to_int(&hv->cookie_length);

  /* add known cipher(s) */
  dtls_int_to_uint16(p, 2);
  p += sizeof(uint16);
  
  dtls_int_to_uint16(p, TLS_PSK_WITH_AES_128_CCM_8);
  p += sizeof(uint16);
  
  /* compression method */
  dtls_int_to_uint8(p, 1);  
  p += sizeof(uint8);

  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);

  res = dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, ctx->sendbuf, 
		  p - ctx->sendbuf);
  if (res < 0)
    warn("cannot send ClientHello\n");

 error: 
  return 0;
}

static int
check_server_hellodone(dtls_context_t *ctx, 
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length) {

  /* calculate master key, send CCS */
  if (!IS_SERVERHELLODONE(data, data_length))
    return 0;
  
  update_hs_hash(peer, data, data_length);

  /* set crypto context for TLS_PSK_WITH_AES_128_CCM_8 */
  /* client */
  dtls_cipher_free(OTHER_CONFIG(peer)->read_cipher);

  assert(OTHER_CONFIG(peer)->cipher != TLS_NULL_WITH_NULL_NULL);
  OTHER_CONFIG(peer)->read_cipher = 
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
		    dtls_kb_server_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!OTHER_CONFIG(peer)->read_cipher) {
    warn("cannot create read cipher\n");
    return 0;
  }

  dtls_cipher_set_iv(OTHER_CONFIG(peer)->read_cipher,
		     dtls_kb_server_iv(OTHER_CONFIG(peer)),
		     dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* server */
  dtls_cipher_free(OTHER_CONFIG(peer)->write_cipher);
  
  OTHER_CONFIG(peer)->write_cipher = 
    dtls_cipher_new(OTHER_CONFIG(peer)->cipher,
		    dtls_kb_client_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));
  
  if (!OTHER_CONFIG(peer)->write_cipher) {
    dtls_cipher_free(OTHER_CONFIG(peer)->read_cipher);
    warn("cannot create write cipher\n");
    return 0;
  }
  
  dtls_cipher_set_iv(OTHER_CONFIG(peer)->write_cipher,
		     dtls_kb_client_iv(OTHER_CONFIG(peer)),
		     dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* send ClientKeyExchange */
  if (dtls_send_kx(ctx, peer, 1) < 0) {
    debug("cannot send KeyExchange message\n");
    return 0;
  }

  /* and switch cipher suite */
  if (dtls_send_ccs(ctx, peer) < 0) {
    debug("cannot send CCS message\n");
    return 0;
  }

  SWITCH_CONFIG(peer);
  inc_uint(uint16, peer->epoch);
  memset(peer->rseq, 0, sizeof(peer->rseq));
/* #ifndef NDEBUG */
/*   { */
/*       printf("key_block:\n"); */
/*       printf("  client_MAC_secret:\t");   */
/*       dump(dtls_kb_client_mac_secret(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */

/*       printf("  server_MAC_secret:\t");   */
/*       dump(dtls_kb_server_mac_secret(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */

/*       printf("  client_write_key:\t");   */
/*       dump(dtls_kb_client_write_key(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_key_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */

/*       printf("  server_write_key:\t");   */
/*       dump(dtls_kb_server_write_key(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_key_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */

/*       printf("  client_IV:\t\t");   */
/*       dump(dtls_kb_client_iv(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_iv_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */
      
/*       printf("  server_IV:\t\t");   */
/*       dump(dtls_kb_server_iv(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_iv_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */
      

/*   } */
/* #endif */

  /* Client Finished */
  {
    debug ("send Finished\n");
    int length;
    uint8 buf[DTLS_HMAC_MAX];
    uint8 *p = ctx->sendbuf;

    unsigned char statebuf[DTLS_HASH_CTX_SIZE];

    /* FIXME: adjust message overhead calculation */
    assert(msg_overhead(peer, DTLS_HS_LENGTH + DTLS_FIN_LENGTH) 
	   < sizeof(ctx->sendbuf));

    p = dtls_set_handshake_header(DTLS_HT_FINISHED, 
				  peer, DTLS_FIN_LENGTH, 
				  0, DTLS_FIN_LENGTH, p);
  
    /* temporarily store hash status for roll-back after finalize */
    memcpy(statebuf, &peer->hs_state.hs_hash, DTLS_HASH_CTX_SIZE);

    length = finalize_hs_hash(peer, buf);

    /* restore hash status */
    memcpy(&peer->hs_state.hs_hash, statebuf, DTLS_HASH_CTX_SIZE);

    dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	     DTLS_MASTER_SECRET_LENGTH,
	     PRF_LABEL(client), PRF_LABEL_SIZE(client),
	     PRF_LABEL(finished), PRF_LABEL_SIZE(finished),
	     buf, length,
	     p, DTLS_FIN_LENGTH);
  
    p += DTLS_FIN_LENGTH;

    update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);
    if (dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		  ctx->sendbuf, p - ctx->sendbuf) < 0) {
      dsrv_log(LOG_ALERT, "cannot send Finished message\n");
      return 0;
    }
  }
  return 1;
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
      
/* #ifndef NDEBUG */
/*     printf("nonce:\t"); */
/*     dump(N, DTLS_CCM_BLOCKSIZE); */
/*     printf("\nkey:\t"); */
/*     dump(dtls_kb_remote_write_key(CURRENT_CONFIG(peer)),  */
/* 	 dtls_kb_key_size(CURRENT_CONFIG(peer))); */
/*     printf("\nciphertext:\n"); */
/*     dump(*cleartext, *clen); */
/*     printf("\n"); */
/* #endif */

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
/* #ifndef NDEBUG */
/*       printf("decrypt_verify(): found %ld bytes cleartext\n", len); */
/* #endif */
      *clen = len;
    }
/* #ifndef NDEBUG */
/*     printf("\ncleartext:\n"); */
/*     dump(*cleartext, *clen); */
/*     printf("\n"); */
/* #endif */
  }

  return ok;
}


int
handle_handshake(dtls_context_t *ctx, dtls_peer_t *peer, 
		 uint8 *record_header, uint8 *data, size_t data_length) {

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
    if (check_server_hello(ctx, peer, data, data_length)) {
      peer->state = DTLS_STATE_WAIT_SERVERHELLODONE;
    /* update_hs_hash(peer, data, data_length); */
    }

    break;

  case DTLS_STATE_WAIT_SERVERHELLODONE:
    /* expect a ServerHelloDone */

    debug("DTLS_STATE_WAIT_SERVERHELLODONE\n");

    if (check_server_hellodone(ctx, peer, data, data_length)) {
      peer->state = DTLS_STATE_WAIT_SERVERFINISHED;
      /* update_hs_hash(peer, data, data_length); */
    }

    break;

  case DTLS_STATE_WAIT_SERVERFINISHED:
    /* expect a Finished message from server */

    debug("DTLS_STATE_WAIT_SERVERFINISHED\n");
    if (check_finished(ctx, peer, record_header, data, data_length)) {
      debug("finished!\n");
      peer->state = DTLS_STATE_CONNECTED;
    }

    break;

  /************************************************************************
   * Server states
   ************************************************************************/

  case DTLS_STATE_SERVERHELLO:
    /* here we expect a ClientHello */
    /* handle ClientHello, update msg and msglen and goto next if not finished */

    debug("DTLS_STATE_SERVERHELLO\n");
    if (!check_client_keyexchange(ctx, peer, data, data_length)) {
      warn("check_client_keyexchange failed (%d, %d)\n", data_length, data[0]);
      return 0;			/* drop it, whatever it is */
    }
    
    update_hs_hash(peer, data, data_length);
    peer->state = DTLS_STATE_KEYEXCHANGE;
    break;

  case DTLS_STATE_WAIT_FINISHED:
    debug("DTLS_STATE_WAIT_FINISHED\n");
    if (check_finished(ctx, peer, record_header, data, data_length)) {
      debug("finished!\n");
	
      /* send ServerFinished */
      update_hs_hash(peer, data, data_length);

      if (dtls_send_server_finished(ctx, peer) > 0) {
	peer->state = DTLS_STATE_CONNECTED;
      } else {
	warn("sending server Finished failed\n");
      }
    } else {
      /* send alert */
    }
    break;
      
  case DTLS_STATE_CONNECTED:
    /* At this point, we have a good relationship with this peer. This
     * state is left for re-negotiation of key material. */
    
    debug("DTLS_STATE_CONNECTED\n");

    /* renegotiation */
    if (dtls_verify_peer(ctx, peer, &peer->session, 
			 record_header, data, data_length) > 0) {

      clear_hs_hash(peer);

      if (!dtls_update_parameters(ctx, peer, data, data_length)) {
	
	warn("error updating security parameters\n");
	dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_WARNING, 
		   DTLS_ALERT_NO_RENEGOTIATION);
	return 0;
      }

      /* update finish MAC */
      update_hs_hash(peer, data, data_length); 

      if (dtls_send_server_hello(ctx, peer) > 0)
	peer->state = DTLS_STATE_SERVERHELLO;
    
      /* after sending the ServerHelloDone, we expect the 
       * ClientKeyExchange (possibly containing the PSK id),
       * followed by a ChangeCipherSpec and an encrypted Finished.
       */
    }

    break;
    
  case DTLS_STATE_INIT:	      /* these states should not occur here */
  case DTLS_STATE_KEYEXCHANGE:
  default:
    dsrv_log(LOG_CRIT, "unhandled state %d\n", peer->state);
    assert(0);
  }

  return 1;
}

int
handle_ccs(dtls_context_t *ctx, dtls_peer_t *peer, 
	   uint8 *record_header, uint8 *data, size_t data_length) {

  /* A CCS message is handled after a KeyExchange message was
   * received from the client. When security parameters have been
   * updated successfully and a ChangeCipherSpec message was sent
   * by ourself, the security context is switched and the record
   * sequence number is reset. */
  
  if (peer->state != DTLS_STATE_KEYEXCHANGE
      || !check_ccs(ctx, peer, record_header, data, data_length)) {
    /* signal error? */
    warn("expected ChangeCipherSpec during handshake\n");
    return 0;

  }

  /* send change cipher spec message and switch to new configuration */
  if (dtls_send_ccs(ctx, peer) < 0) {
    warn("cannot send CCS message");
    return 0;
  } 
  
  SWITCH_CONFIG(peer);
  inc_uint(uint16, peer->epoch);
  memset(peer->rseq, 0, sizeof(peer->rseq));
  
  peer->state = DTLS_STATE_WAIT_FINISHED;

/* #ifndef NDEBUG */
/*   { */
/*       printf("key_block:\n"); */
/*       printf("  client_MAC_secret:\t");   */
/*       dump(dtls_kb_client_mac_secret(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */

/*       printf("  server_MAC_secret:\t");   */
/*       dump(dtls_kb_server_mac_secret(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */

/*       printf("  client_write_key:\t");   */
/*       dump(dtls_kb_client_write_key(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_key_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */

/*       printf("  server_write_key:\t");   */
/*       dump(dtls_kb_server_write_key(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_key_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */

/*       printf("  client_IV:\t\t");   */
/*       dump(dtls_kb_client_iv(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_iv_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */
      
/*       printf("  server_IV:\t\t");   */
/*       dump(dtls_kb_server_iv(CURRENT_CONFIG(peer)),  */
/* 	   dtls_kb_iv_size(CURRENT_CONFIG(peer))); */
/*       printf("\n"); */
      

/*   } */
/* #endif */

  return 1;
}  

/** 
 * Handles incoming Alert messages. This function returns \c 1 if the
 * connection should be closed and the peer is to be invalidated.
 */
int
handle_alert(dtls_context_t *ctx, dtls_peer_t *peer, 
	     uint8 *record_header, uint8 *data, size_t data_length) {
  int free_peer = 0;		/* indicates whether to free peer */

  if (data_length < 2)
    return 0;

  info("** Alert: level %d, description %d\n", data[0], data[1]);

  /* The peer object is invalidated for FATAL alerts and close
   * notifies. This is done in two steps.: First, remove the object
   * from our list of peers. After that, the event handler callback is
   * invoked with the still existing peer object. Finally, the storage
   * used by peer is released.
   */
  if (data[0] == DTLS_ALERT_LEVEL_FATAL || data[1] == DTLS_ALERT_CLOSE) {
    dsrv_log(LOG_ALERT, "%d invalidate peer\n", data[1]);
    
#ifndef WITH_CONTIKI
    HASH_DEL_PEER(ctx->peers, peer);
#else /* WITH_CONTIKI */
    list_remove(ctx->peers, peer);

/* #ifndef NDEBUG */
/*     PRINTF("removed peer ["); */
/*     PRINT6ADDR(&peer->session.addr); */
/*     PRINTF("]:%d\n", uip_ntohs(peer->session.port)); */
/* #endif */
#endif /* WITH_CONTIKI */

    free_peer = 1;

  }

  (void)CALL(ctx, event, &peer->session, 
	     (dtls_alert_level_t)data[0], (unsigned short)data[1]);
  switch (data[1]) {
  case DTLS_ALERT_CLOSE:
    /* If state is DTLS_STATE_CLOSING, we have already sent a
     * close_notify so, do not send that again. */
    if (peer->state != DTLS_STATE_CLOSING) {
      peer->state = DTLS_STATE_CLOSING;
      dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, DTLS_ALERT_CLOSE);
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

  /* check if we have DTLS state for addr/port/ifindex */
  peer = dtls_get_peer(ctx, session);

#ifndef NDEBUG
  if (peer) {
    unsigned char addrbuf[72];

    dsrv_print_addr(session, addrbuf, sizeof(addrbuf));
    debug("found peer %s\n", addrbuf);
  }
#endif /* NDEBUG */

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
      return 0;
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

    peer = dtls_new_peer(session);
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
    if (!dtls_update_parameters(ctx, peer, 
			msg + DTLS_RH_LENGTH, rlen - DTLS_RH_LENGTH)) {

      warn("error updating security parameters\n");
      /* FIXME: send handshake failure Alert */
      dtls_alert(ctx, peer, DTLS_ALERT_LEVEL_FATAL, 
		 DTLS_ALERT_HANDSHAKE_FAILURE);
      dtls_free_peer(peer);
      return -1;
    }

#ifndef WITH_CONTIKI
    HASH_ADD_PEER(ctx->peers, session, peer);
#else /* WITH_CONTIKI */
    list_add(ctx->peers, peer);
#endif /* WITH_CONTIKI */
    
    /* update finish MAC */
    update_hs_hash(peer, msg + DTLS_RH_LENGTH, rlen - DTLS_RH_LENGTH); 
 
    if (dtls_send_server_hello(ctx, peer) > 0)
      peer->state = DTLS_STATE_SERVERHELLO;
    
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

/* #ifndef NDEBUG */
/*     hexdump(msg, sizeof(dtls_record_header_t)); */
/*     printf("\n"); */
/*     hexdump(data, data_length); */
/*     printf("\n"); */
/* #endif */

    /* Handle received record according to the first byte of the
     * message, i.e. the subprotocol. We currently do not support
     * combining multiple fragments of one type into a single
     * record. */

    switch (msg[0]) {

    case DTLS_CT_CHANGE_CIPHER_SPEC:
      handle_ccs(ctx, peer, msg, data, data_length);
      break;

    case DTLS_CT_ALERT:
      if (handle_alert(ctx, peer, msg, data, data_length)) {
	/* handle alert has invalidated peer */
	peer = NULL;
	return 0;
      }

    case DTLS_CT_HANDSHAKE:
      handle_handshake(ctx, peer, msg, data, data_length);
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
  dtls_tick_t now;
#ifndef WITH_CONTIKI
  FILE *urandom = fopen("/dev/urandom", "r");
  unsigned char buf[sizeof(unsigned long)];
#endif /* WITH_CONTIKI */

  dtls_ticks(&now);
#ifdef WITH_CONTIKI
  /* FIXME: need something better to init PRNG here */
  prng_init(now);
#else /* WITH_CONTIKI */
  if (!urandom) {
    dsrv_log(LOG_EMERG, "cannot initialize PRNG\n");
    return NULL;
  }

  if (fread(buf, 1, sizeof(buf), urandom) != sizeof(buf)) {
    dsrv_log(LOG_EMERG, "cannot initialize PRNG\n");
    return NULL;
  }

  fclose(urandom);
  prng_init((unsigned long)*buf);
#endif /* WITH_CONTIKI */

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
    c->cookie_secret_age = now;
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
dtls_connect_peer(dtls_context_t *ctx, dtls_peer_t *peer) {
  uint8 *p = ctx->sendbuf;
  size_t size;
  int res;
  dtls_tick_t now;

  assert(peer);
  if (!peer)
    return -1;

  /* check if the same peer is already in our list */
  if (peer == dtls_get_peer(ctx, &peer->session)) {
    debug("found peer, try to re-connect\n");
    /* FIXME: send HelloRequest if we are server, 
       ClientHello with good cookie if client */
    return 0;
  }
    
  /* set peer role to server: */
  OTHER_CONFIG(peer)->role = DTLS_SERVER;
  CURRENT_CONFIG(peer)->role = DTLS_SERVER;

  dtls_add_peer(ctx, peer);

  /* send ClientHello with some Cookie */

  /* add to size:
   *   1. length of session id (including length field)
   *   2. length of cookie (including length field)
   *   3. cypher suites
   *   4. compression methods 
   */
  size = DTLS_CH_LENGTH + 8;

  /* force sending 0 as handshake message sequence number by setting
   * peer to NULL */
  p = dtls_set_handshake_header(DTLS_HT_CLIENT_HELLO, NULL, 
				size, 0, size, p);

  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  dtls_ticks(&now);
  /* Set client random: First 4 bytes are the client's Unix timestamp,
   * followed by 28 bytes of generate random data. */
  dtls_int_to_uint32(&OTHER_CONFIG(peer)->client_random, 
		     now / DTLS_TICKS_PER_SECOND);
  prng(OTHER_CONFIG(peer)->client_random + sizeof(uint32),
       sizeof(OTHER_CONFIG(peer)->client_random) - sizeof(uint32));
  memcpy(p, OTHER_CONFIG(peer)->client_random, 
	 sizeof(OTHER_CONFIG(peer)->client_random));
  p += 32;

  /* session id (length 0) */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  /* add supported cipher suite */
  dtls_int_to_uint16(p, 2);
  p += sizeof(uint16);
  
  dtls_int_to_uint16(p, TLS_PSK_WITH_AES_128_CCM_8);
  p += sizeof(uint16);
  
  /* compression method */
  dtls_int_to_uint8(p, 1);  
  p += sizeof(uint8);

  dtls_int_to_uint8(p, TLS_COMP_NULL);
  p += sizeof(uint8);

  res = dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, ctx->sendbuf, 
		  p - ctx->sendbuf);
  if (res < 0)
    warn("cannot send ClientHello\n");
  else 
    peer->state = DTLS_STATE_CLIENTHELLO;

  return res;
}

int
dtls_connect(dtls_context_t *ctx, const session_t *dst) {
  dtls_peer_t *peer;

  peer = dtls_get_peer(ctx, dst);
  
  if (!peer)
    peer = dtls_new_peer(dst);

  if (!peer) {
    dsrv_log(LOG_CRIT, "cannot create new peer\n");
    return -1;
  }

  return dtls_connect_peer(ctx, peer);
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
			      node->data, node->length, 
			      sendbuf, &len) > 0) {
	
#ifndef NDEBUG
	if (dtls_get_log_level() >= LOG_DEBUG) {
	  debug("retransmit %d bytes\n", len);
	  hexdump(sendbuf, sizeof(dtls_record_header_t));
	  printf("\n");
	  hexdump(node->data, node->length);
	  printf("\n");
	}
#endif
	
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

void
dtls_check_retransmit(dtls_context_t *context, clock_time_t *next) {
  dtls_tick_t now;
  netq_t *node = netq_head((netq_t **)context->sendqueue);

  dtls_ticks(&now);
  while (node && node->t <= now) {
    netq_pop_first((netq_t **)context->sendqueue);
    dtls_retransmit(context, node);
    node = netq_head((netq_t **)context->sendqueue);
  }

  if (next && node)
    *next = node->t;
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

#ifndef NDEBUG
/** dumps packets in usual hexdump format */
void hexdump(const unsigned char *packet, int length) {
  int n = 0;

  while (length--) { 
    if (n % 16 == 0)
      printf("%08X ",n);

    printf("%02X ", *packet++);
    
    n++;
    if (n % 8 == 0) {
      if (n % 16 == 0)
	printf("\n");
      else
	printf(" ");
    }
  }
}

/** dump as narrow string of hex digits */
void dump(unsigned char *buf, size_t len) {
  while (len--) 
    printf("%02x", *buf++);
}
#endif

