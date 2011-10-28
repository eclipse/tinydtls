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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "debug.h"
#include "numeric.h"
#include "dtls.h"

#ifdef WITH_MD5
#  include "md5/md5.h"
#endif

#ifdef WITH_SHA1
#  include "sha1/sha.h"
#endif

#if defined(WITH_SHA256) || defined(WITH_SHA384) || defined(WITH_SHA512)
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

#define HASH_FIND_PEER(head,sess,out)		\
  HASH_FIND(hh,head,sess,sizeof(session_t),out)
#define HASH_ADD_PEER(head,sess,add)		\
  HASH_ADD(hh,head,sess,sizeof(session_t),add)
#define HASH_DEL_PEER(head,delptr)		\
  HASH_DELETE(hh,head,delptr)

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

#define CURRENT_CONFIG(Peer) (&(Peer)->security_params[(Peer)->config])
#define OTHER_CONFIG(Peer) (&(Peer)->security_params[!((Peer)->config & 0x01)])

#define SWITCH_CONFIG(Peer) ((Peer)->config = !((Peer)->config & 0x01))

uint8 _clear[DTLS_MAX_BUF]; /* target buffer message decryption */
uint8 _buf[DTLS_MAX_BUF]; /* target buffer for several crypto operations */

#ifndef NDEBUG
void hexdump(const unsigned char *packet, int length);
void dump(unsigned char *buf, size_t len);
#endif

/* Calls cb_write() with given arguments if defined, otherwise an
 * error message is logged and the result is -1. This is just an
 * internal helper.
 */
#define CB_WRITE(Context, Session, Buf, Len)				\
  ((Context)->cb_write							\
   ? (Context)->cb_write((Context), (Session), (Buf), (Len))		\
   : (dsrv_log(LOG_CRIT, "no send function registered"), -1))

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

dtls_peer_t *
dtls_get_peer(struct dtls_context_t *ctx, session_t *session) {
  dtls_peer_t *peer = NULL;
  HASH_FIND_PEER(ctx->peers, session, peer);
  return peer;
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
  debug("found cookie field (len: %d)\n", *msg & 0xff);
  return *msg & 0xff;

 error:
  return -1;
}

int
dtls_create_cookie(dtls_context_t *ctx, 
		   session_t *session,
		   uint8 *msg, int msglen,
		   uint8 *cookie, int *clen) {

  dtls_hmac_context_t hmac_context;
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

  dtls_hmac_init(&hmac_context, 
		 ctx->cookie_secret, DTLS_COOKIE_SECRET_LENGTH, 
#ifdef WITH_SHA256
		 HASH_SHA256
#elif WITH_SHA1
		 HASH_SHA1
#elif WITH_MD5
		 HASH_MD5
#endif
		 );

  dtls_hmac_update(&hmac_context, 
		   (unsigned char *)&session->raddr, 
		   sizeof(session->raddr));

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

  if (msglen > DTLS_RH_LENGTH	/* FIXME allow empty records? */
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
    inc_uint(uint16, peer->mseq);
  
    /* and copy the result to buf */
    memcpy(buf, &peer->mseq, sizeof(uint16));
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
#ifndef NDEBUG
    debug("create cookie: ");
    dump(mycookie, len);
    printf("\n");
#endif
    assert(len == DTLS_COOKIE_LENGTH);
    
    /* Perform cookie check. */
    len = dtls_get_cookie(data, data_length, &cookie);

    /* check if cookies match */
    if (len == DTLS_COOKIE_LENGTH && memcmp(cookie, mycookie, len) == 0) {
    debug("found matching cookie\n");
      return 1;      
    }
#ifndef NDEBUG
    if (len > 0) {
      debug("invalid cookie:");
      dump(cookie, len);
      printf("\n");
    }
#endif
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

      CB_WRITE(ctx, session, ctx->sendbuf, p - ctx->sendbuf);
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

  debug("dtls_update_parameters: msglen is %d\n", data_length);

  /* skip the handshake header and client version information */
  data += DTLS_HS_LENGTH + sizeof(uint16);
  data_length -= DTLS_HS_LENGTH + sizeof(uint16);

  /* store client random in config */
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

    if (CURRENT_CONFIG(peer)->cipher < 0)
      goto error;

    config->cipher = CURRENT_CONFIG(peer)->cipher;
    config->compression = CURRENT_CONFIG(peer)->compression;

    return 1;
  }

  data += sizeof(uint16);
  data_length -= sizeof(uint16) + i;

  ok = 0;
  while (i && !ok) {
    for (j = 0; dtls_uint16_to_int(ciphers[j].code) != 0; ++j)
      if (memcmp(data, &ciphers[j].code, sizeof(uint16)) == 0) {
	config->cipher = j;
	ok = 1;
      }
    i -= sizeof(uint16);
    data += sizeof(uint16);
  }

  /* skip remaining ciphers */
  data += i;

  if (!ok)
    return 0;

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
check_css(dtls_context_t *ctx, 
	  dtls_peer_t *peer,
	  uint8 *record, uint8 *data, size_t data_length) {

  unsigned char pre_master_secret[60];
  size_t pre_master_len = 0;
  dtls_cipher_context_t **cipher_context;

  if (DTLS_RECORD_HEADER(record)->content_type != DTLS_CT_CHANGE_CIPHER_SPEC
      || data_length < 1 || data[0] != 1)
    return 0;
  
  /* FIXME: explicitly store length of psk */
  pre_master_len = 
    dtls_pre_master_secret(ctx->psk, ctx->psk_length, pre_master_secret);

  dtls_prf(pre_master_secret, pre_master_len,
	   (unsigned char *)"master secret", 13,
	   OTHER_CONFIG(peer)->client_random, 32,
	   OTHER_CONFIG(peer)->server_random, 32,
	   OTHER_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH);

  /* create key_block from master_secret
   * key_block = PRF(master_secret,
                    "key expansion" + server_random + client_random) */

  dtls_prf(OTHER_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   (unsigned char *)"key expansion", 13,
	   OTHER_CONFIG(peer)->server_random, 32,
	   OTHER_CONFIG(peer)->client_random, 32,
	   OTHER_CONFIG(peer)->key_block, 
	   dtls_kb_size(OTHER_CONFIG(peer)));

  /* set crypto context for AES_128_CBC */
  /* client */
  cipher_context = &OTHER_CONFIG(peer)->read_cipher;
  if (*cipher_context)
    free(OTHER_CONFIG(peer)->read_cipher);

  assert(OTHER_CONFIG(peer)->cipher != -1);
  *cipher_context = 
    dtls_new_cipher(&ciphers[OTHER_CONFIG(peer)->cipher],
		    dtls_kb_client_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!*cipher_context) {
    warn("cannot create read cipher\n");
    return 0;
  }

  dtls_init_cipher(*cipher_context,
		   dtls_kb_client_iv(OTHER_CONFIG(peer)),
		   dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* server */
  cipher_context = &OTHER_CONFIG(peer)->write_cipher;
  if (*cipher_context)
    free(OTHER_CONFIG(peer)->write_cipher);

  *cipher_context = 
    dtls_new_cipher(&ciphers[OTHER_CONFIG(peer)->cipher],
		    dtls_kb_server_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!*cipher_context) {
    warn("cannot create write cipher\n");
    return 0;
  }

  dtls_init_cipher(*cipher_context,
		   dtls_kb_server_iv(OTHER_CONFIG(peer)),
		   dtls_kb_iv_size(OTHER_CONFIG(peer)));
  return 1;
}


dtls_peer_t *
dtls_new_peer(dtls_context_t *ctx, 
	      session_t *session) {
  dtls_peer_t *peer;

  peer = (dtls_peer_t *)malloc(sizeof(dtls_peer_t));
  if (peer) {
    memset(peer, 0, sizeof(dtls_peer_t));
    memcpy(&peer->session, session, sizeof(session_t));

    /* initially allow the NULL cipher */
    CURRENT_CONFIG(peer)->cipher = -1;

    /* initialize the handshake hash wrt. the hard-coded DTLS version */
#if DTLS_VERSION == 0xfeff
    debug("DTLSv11: initialize HASH_MD5 (%d) and HASH_SHA1 (%d)\n", HASH_MD5, HASH_SHA1);
    /* TLS 1.0: PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
                                           P_SHA-1(S2, label + seed); */
    peer->hs_hash[0] = dtls_new_hash(HASH_MD5);
    peer->hs_hash[1] = dtls_new_hash(HASH_SHA1);

    peer->hs_hash[0]->init(peer->hs_hash[0]->data);
    peer->hs_hash[1]->init(peer->hs_hash[1]->data);
#elif DTLS_VERSION == 0xfefd
    debug("DTLSv12: initialize HASH_SHA256 (%d)\n", HASH_SHA256);
    /* TLS 1.2:  PRF(secret, label, seed) = P_<hash>(secret, label + seed) */
    /* FIXME: we use the default SHA256 here, might need to support other 
              hash functions as well */
    peer->hs_hash[0] = dtls_new_hash(HASH_SHA256);
    peer->hs_hash[0]->init(peer->hs_hash[0]->data);
#else
#error "unknown DTLS_VERSION"
#endif
  }
  
  return peer;
}

static inline void
update_hs_hash(dtls_peer_t *peer, uint8 *data, size_t length) {
  int i;

  assert(peer->hs_hash[0]);

#ifndef NDEBUG
  printf("add MAC data: ");
  dump(data, length);
  printf("\n");
#endif
  for (i = 0; i < sizeof(peer->hs_hash) / sizeof(dtls_hash_t *); ++i)
    peer->hs_hash[i]->update(peer->hs_hash[i]->data, data, length);
}

static inline size_t
finalize_hs_hash(dtls_peer_t *peer, uint8 *buf) {
#ifdef FINISH_DIGEST_LEN
#undef FINISH_DIGEST_LEN
#endif

#if DTLS_VERSION == 0xfeff
#define FINISH_DIGEST_LEN (16 + SHA1_DIGEST_LENGTH)
#else
#define FINISH_DIGEST_LEN SHA256_DIGEST_LENGTH
#endif

  assert(peer->hs_hash[0]);
  
  peer->hs_hash[0]->finalize(buf, peer->hs_hash[0]->data);
#if DTLS_VERSION == 0xfeff
  peer->hs_hash[1]->finalize(buf + 16, peer->hs_hash[1]->data);
#endif

  return FINISH_DIGEST_LEN;
#undef FINISH_DIGEST_LEN
}

static inline void
clear_hs_hash(dtls_peer_t *peer) {
  int i;

  for (i = 0; i < sizeof(peer->hs_hash) / sizeof(dtls_hash_t *); ++i)
    peer->hs_hash[i]->init(peer->hs_hash[i]->data);
}

/** Releases the storage occupied by peer. */
void
dtls_free_peer(dtls_peer_t *peer) {
  int i;
  for (i = 0; i < sizeof(peer->hs_hash) / sizeof(dtls_hash_t *); ++i)
    free(peer->hs_hash[i]);
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
  size_t digest_length;
  unsigned char verify_data[DTLS_FIN_LENGTH];
  unsigned char buf[DTLS_HMAC_MAX];

#if DTLS_VERSION == 0xfeff
  unsigned char statebuf[sizeof(md5_state_t) + sizeof(SHA_CTX)];
#elif DTLS_VERSION == 0xfefd
  unsigned char statebuf[sizeof(SHA256_CTX)];
#endif

  debug("check Finish message\n");
  if (record[0] != DTLS_CT_HANDSHAKE || !IS_FINISHED(data, data_length)) {
    debug("failed\n");
    return 0;
  }

  /* temporarily store hash status for roll-back after finalize */
#if DTLS_VERSION == 0xfeff
  memcpy(statebuf, peer->hs_hash[0]->data, sizeof(md5_state_t));
  memcpy(statebuf + sizeof(md5_state_t), 
	 peer->hs_hash[1]->data, 
	 sizeof(SHA_CTX));
#elif DTLS_VERSION == 0xfefd
  memcpy(statebuf, peer->hs_hash[0]->data, sizeof(statebuf));
#endif

  digest_length = finalize_hs_hash(peer, buf);
  /* clear_hash(); */

  /* restore hash status */
#if DTLS_VERSION == 0xfeff
  memcpy(peer->hs_hash[0]->data, statebuf, sizeof(md5_state_t));
  memcpy(peer->hs_hash[1]->data, 
	 statebuf + sizeof(md5_state_t), 
	 sizeof(SHA_CTX));
#elif DTLS_VERSION == 0xfefd
  memcpy(peer->hs_hash[0]->data, statebuf, sizeof(statebuf));
#endif

  {
    unsigned char finishedmsg[15] = { 
      'c','l','i','e','n','t',' ','f','i','n','i','s','h','e','d' 
    };

    if (CURRENT_CONFIG(peer)->role == DTLS_SERVER)
      memcpy(finishedmsg, "server", 6);

    dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	     DTLS_MASTER_SECRET_LENGTH,
	     finishedmsg,
	     sizeof(finishedmsg),
	     buf, digest_length,
	     NULL, 0,
	     verify_data, sizeof(verify_data));
  }

  return memcmp(data + DTLS_HS_LENGTH, verify_data, sizeof(verify_data)) == 0;
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

  switch (CURRENT_CONFIG(peer)->cipher) {
  case -1:			/* no cipher suite */
    memcpy(p, data, data_length);
    res = data_length;
    break;

#ifdef TLS_PSK_WITH_AES_128_CBC_SHA
  case AES128:
    {				/* add MAC */
      dtls_hmac_context_t hmac_ctx;

      dtls_int_to_uint16(sendbuf + 11, data_length);

      debug("prepare_record(): use mac algorithm %d\n", 
	    dtls_kb_mac_algorithm(CURRENT_CONFIG(peer)));
      dtls_hmac_init(&hmac_ctx, 
		     dtls_kb_local_mac_secret(CURRENT_CONFIG(peer)),
		     dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)),
		     dtls_kb_mac_algorithm(CURRENT_CONFIG(peer)));

      dtls_mac(&hmac_ctx, sendbuf, data, data_length, data + data_length);
      data_length += dtls_kb_digest_size(CURRENT_CONFIG(peer));
      
      /* check for block-encrypted and MAC-protected records: */
      if (*rlen < DTLS_RH_LENGTH + data_length 
	  + 2 * dtls_kb_iv_size(CURRENT_CONFIG(peer)) + 1) {
	debug("dtls_prepare_record: send buffer too small\n");
	return -2;
      }

      res = dtls_encrypt(CURRENT_CONFIG(peer)->write_cipher, 
			 data, data_length, p);
      if (res < 0) {
	debug("dtls_prepare_record: encryption failed\n");
	return res;
      }
    }
    break;
#endif /* TLS_PSK_WITH_AES_128_CBC_SHA */
  default:
    warn("unknown cipher, no data sent\n");
    return -1;
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
  
#ifndef NDEBUG
  debug("send %d bytes\n", buflen);
  hexdump(sendbuf, sizeof(dtls_record_header_t));
  printf("\n");
  hexdump(buf, buflen);
  printf("\n");
#endif

  res = CB_WRITE(ctx, &peer->session, sendbuf, len);

  /* Guess number of bytes application data actually sent:
   * dtls_prepare_record() tells us in len the number of bytes to
   * send, res will contain the bytes actually sent. */
  return res <= 0 ? res : buflen - (len - res);
}

int
dtls_send_server_hello(dtls_context_t *ctx, dtls_peer_t *peer) {

  uint8 buf[DTLS_MAX_BUF];
  uint8 *p = buf, *q = ctx->sendbuf;
  size_t qlen = sizeof(ctx->sendbuf);
  int res;

  /* Ensure that the largest message to create fits in our source
   * buffer. (The size of the destination buffer is checked by the
   * encoding function, so we do not need to guess.) */
  assert(sizeof(buf) >=
	 DTLS_RH_LENGTH + DTLS_HS_LENGTH + DTLS_SH_LENGTH + 20);

  /* Handshake header */
  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO, 
				peer,
				DTLS_SH_LENGTH, 
				0, DTLS_SH_LENGTH,
				buf);
  /* ServerHello */
  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* Set server random: First generate 32 bytes of random data and then 
   * overwrite the leading 4 bytes with the timestamp. */
  prng(OTHER_CONFIG(peer)->server_random, 
       sizeof(OTHER_CONFIG(peer)->server_random));
  dtls_int_to_uint32(&OTHER_CONFIG(peer)->server_random, time(NULL));

  /* random gmt and server random bytes */
  memcpy(p, &OTHER_CONFIG(peer)->server_random, 
	 sizeof(OTHER_CONFIG(peer)->server_random));
  p += 32;

  *p++ = 0;			/* no session id */


  if (OTHER_CONFIG(peer)->cipher >= 0) {
    /* selected cipher suite */
    memcpy(p, ciphers[OTHER_CONFIG(peer)->cipher].code, sizeof(uint16));
    p += sizeof(uint16);

    /* selected compression method */
    if (OTHER_CONFIG(peer)->compression >= 0)
      *p++ = compression_methods[OTHER_CONFIG(peer)->compression];

    /* no PSK hint, therefore, we do not need the server key exchange */

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

  return CB_WRITE(ctx, &peer->session,  
		  ctx->sendbuf, (q + qlen) - ctx->sendbuf);
}

static inline int 
dtls_send_css(dtls_context_t *ctx, dtls_peer_t *peer) {
  ctx->sendbuf[0] = 1;
  return dtls_send(ctx, peer, DTLS_CT_CHANGE_CIPHER_SPEC, ctx->sendbuf, 1);
}

    
int 
dtls_send_kx(dtls_context_t *ctx, dtls_peer_t *peer, int is_client) {
  uint8 *p = ctx->sendbuf;
  size_t size = ctx->psk_id_length + sizeof(uint16);
  int ht = is_client 
    ? DTLS_HT_CLIENT_KEY_EXCHANGE 
    : DTLS_HT_SERVER_KEY_EXCHANGE;

  p = dtls_set_handshake_header(ht, peer, size, 0, size, p);

  dtls_int_to_uint16(p, ctx->psk_id_length);
  memcpy(p + sizeof(uint16), ctx->psk_id, ctx->psk_id_length);
  p += size;

  update_hs_hash(peer, ctx->sendbuf, p - ctx->sendbuf);
  return dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, 
		   ctx->sendbuf, p - ctx->sendbuf);
}

#define msg_overhead(Peer,Length) (DTLS_RH_LENGTH +	\
  ((Length + dtls_kb_iv_size(CURRENT_CONFIG(Peer)) + \
    dtls_kb_digest_size(CURRENT_CONFIG(Peer))) /     \
    (ciphers[CURRENT_CONFIG(Peer)->cipher].blk_length) + 1) * \
    ciphers[CURRENT_CONFIG(Peer)->cipher].blk_length)

int
dtls_send_server_finished(dtls_context_t *ctx, dtls_peer_t *peer) {

  int length;
  uint8 buf[DTLS_HMAC_MAX];
  uint8 *p = ctx->sendbuf;

  assert(msg_overhead(peer, DTLS_HS_LENGTH + DTLS_FIN_LENGTH) 
	 < sizeof(ctx->sendbuf));

  p = dtls_set_handshake_header(DTLS_HT_FINISHED, 
                                peer, DTLS_FIN_LENGTH, 0, DTLS_FIN_LENGTH, p);
  
  length = finalize_hs_hash(peer, buf);

  dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   (unsigned char *)"server finished", 15,
	   buf, length,
	   NULL, 0,
	   p, DTLS_FIN_LENGTH);

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
    data += sizeof(OTHER_CONFIG(peer)->client_random);
    data_length -= sizeof(OTHER_CONFIG(peer)->client_random);

    SKIP_VAR_FIELD(data, data_length, uint8); /* skip session id */
    
    /* Check cipher suite. As we offer all we have, it is sufficient
     * to check if the cipher suite selected by the server is in our
     * list of known cipher suites. Subsets are not supported. */
    {
      int c, j = 0, cipher = dtls_uint16_to_int(data);
      do {
	c = dtls_uint16_to_int(ciphers[j].code); 
	if (!c) {
	  dsrv_log(LOG_ALERT, "unsupported cipher 0x%02x 0x%02x\n", 
		   data[0], data[1]);
	  goto error;
	}
      } while (c != cipher);
      data += sizeof(uint16);
      data_length -= sizeof(uint16);
    }

    /* Check if NULL compression was selected. We do not know any other. */
    if (dtls_uint8_to_int(data) != 0x00) {
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

  /* FIXME: add everything from ciphers[] */
  dtls_int_to_uint16(p, 2);
  p += sizeof(uint16);
  
  memcpy(p, ciphers[0].code, sizeof(uint16));
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
  
  unsigned char pre_master_secret[60];
  size_t pre_master_len = 0;
  dtls_cipher_context_t **cipher_context;

  /* calculate master key, send CSS */
  if (!IS_SERVERHELLODONE(data, data_length))
    return 0;
  
  update_hs_hash(peer, data, data_length);

  /* FIXME: explicitly store length of psk */
  pre_master_len = 
    dtls_pre_master_secret(ctx->psk, ctx->psk_length, pre_master_secret);

  dtls_prf(pre_master_secret, pre_master_len,
	   (unsigned char *)"master secret", 13,
	   OTHER_CONFIG(peer)->client_random, 32,
	   OTHER_CONFIG(peer)->server_random, 32,
	   OTHER_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH);

  /* create key_block from master_secret
   * key_block = PRF(master_secret,
                    "key expansion" + server_random + client_random) */

  dtls_prf(OTHER_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   (unsigned char *)"key expansion", 13,
	   OTHER_CONFIG(peer)->server_random, 32,
	   OTHER_CONFIG(peer)->client_random, 32,
	   OTHER_CONFIG(peer)->key_block, 
	   dtls_kb_size(OTHER_CONFIG(peer)));

  /* set crypto context for AES_128_CBC */
  /* client */
  cipher_context = &OTHER_CONFIG(peer)->read_cipher;
  if (*cipher_context)
    free(OTHER_CONFIG(peer)->read_cipher);

  assert(OTHER_CONFIG(peer)->cipher != -1);
  *cipher_context = 
    dtls_new_cipher(&ciphers[OTHER_CONFIG(peer)->cipher],
		    dtls_kb_server_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!*cipher_context) {
    warn("cannot create read cipher\n");
    return 0;
  }

  dtls_init_cipher(*cipher_context,
		   dtls_kb_server_iv(OTHER_CONFIG(peer)),
		   dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* server */
  cipher_context = &OTHER_CONFIG(peer)->write_cipher;
  if (*cipher_context)
    free(OTHER_CONFIG(peer)->write_cipher);

  *cipher_context = 
    dtls_new_cipher(&ciphers[OTHER_CONFIG(peer)->cipher],
		    dtls_kb_client_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!*cipher_context) {
    warn("cannot create write cipher\n");
    return 0;
  }

  dtls_init_cipher(*cipher_context,
		   dtls_kb_client_iv(OTHER_CONFIG(peer)),
		   dtls_kb_iv_size(OTHER_CONFIG(peer)));

  /* send ClientKeyExchange */
  if (dtls_send_kx(ctx, peer, 1) < 0) {
    debug("cannot send KeyExchange message\n");
    return 0;
  }

  /* and switch cipher suite */
  if (dtls_send_css(ctx, peer) < 0) {
    debug("cannot send CSS message\n");
    return 0;
  }

  SWITCH_CONFIG(peer);
  inc_uint(uint16, peer->epoch);
  memset(peer->rseq, 0, sizeof(peer->rseq));
#ifndef NDEBUG
  {
      printf("key_block:\n");
      printf("  client_MAC_secret:\t");  
      dump(dtls_kb_client_mac_secret(CURRENT_CONFIG(peer)), 
	   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  server_MAC_secret:\t");  
      dump(dtls_kb_server_mac_secret(CURRENT_CONFIG(peer)), 
	   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  client_write_key:\t");  
      dump(dtls_kb_client_write_key(CURRENT_CONFIG(peer)), 
	   dtls_kb_key_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  server_write_key:\t");  
      dump(dtls_kb_server_write_key(CURRENT_CONFIG(peer)), 
	   dtls_kb_key_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  client_IV:\t\t");  
      dump(dtls_kb_client_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));
      printf("\n");
      
      printf("  server_IV:\t\t");  
      dump(dtls_kb_server_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));
      printf("\n");
      

  }
#endif

  /* Client Finished */
  {
    debug ("send Finished\n");
    int length;
    uint8 buf[DTLS_HMAC_MAX];
    uint8 *p = ctx->sendbuf;

#if DTLS_VERSION == 0xfeff
    unsigned char statebuf[sizeof(md5_state_t) + sizeof(SHA_CTX)];
#elif DTLS_VERSION == 0xfefd
    unsigned char statebuf[sizeof(SHA256_CTX)];
#endif

    assert(msg_overhead(peer, DTLS_HS_LENGTH + DTLS_FIN_LENGTH) 
	   < sizeof(ctx->sendbuf));

    p = dtls_set_handshake_header(DTLS_HT_FINISHED, 
				  peer, DTLS_FIN_LENGTH, 
				  0, DTLS_FIN_LENGTH, p);
  
  /* temporarily store hash status for roll-back after finalize */
#if DTLS_VERSION == 0xfeff
  memcpy(statebuf, peer->hs_hash[0]->data, sizeof(md5_state_t));
  memcpy(statebuf + sizeof(md5_state_t), 
	 peer->hs_hash[1]->data, 
	 sizeof(SHA_CTX));
#elif DTLS_VERSION == 0xfefd
  memcpy(statebuf, peer->hs_hash[0]->data, sizeof(statebuf));
#endif

  length = finalize_hs_hash(peer, buf);

  /* restore hash status */
#if DTLS_VERSION == 0xfeff
  memcpy(peer->hs_hash[0]->data, statebuf, sizeof(md5_state_t));
  memcpy(peer->hs_hash[1]->data, 
	 statebuf + sizeof(md5_state_t), 
	 sizeof(SHA_CTX));
#elif DTLS_VERSION == 0xfefd
  memcpy(peer->hs_hash[0]->data, statebuf, sizeof(statebuf));
#endif

    dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	     DTLS_MASTER_SECRET_LENGTH,
	     (unsigned char *)"client finished", 15,
	     buf, length,
	     NULL, 0,
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
  int res, ok = 0;
  
  *cleartext = (uint8 *)packet + sizeof(dtls_record_header_t);
  *clen = length - sizeof(dtls_record_header_t);

  switch (CURRENT_CONFIG(peer)->cipher) {
  case -1:			/* no cipher suite selected */
    ok = 1;
    break;

#ifdef TLS_PSK_WITH_AES_128_CBC_SHA
  case AES128:
      
    res = dtls_decrypt(CURRENT_CONFIG(peer)->read_cipher, 
		       *cleartext, *clen, *cleartext);

    
    if (res < dtls_kb_digest_size(CURRENT_CONFIG(peer))) {
      warn("decryption failed!\n");
    } else {			/* verify MAC */

      /* We include the HMAC verification here, so we can strip the
       * digest easily after successful verification. */

      unsigned char mac[DTLS_HMAC_MAX];
      dtls_hmac_context_t hmac_ctx;
      
      debug("decrypt_verify(): use mac algorithm %d\n", 
	    dtls_kb_mac_algorithm(CURRENT_CONFIG(peer)));
      dtls_hmac_init(&hmac_ctx, 
		     dtls_kb_remote_mac_secret(CURRENT_CONFIG(peer)),
		     dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)),
		     dtls_kb_mac_algorithm(CURRENT_CONFIG(peer)));

      res -= dtls_kb_digest_size(CURRENT_CONFIG(peer));

      dtls_mac(&hmac_ctx, packet, *cleartext, res, mac);
      
      if (memcmp(mac, *cleartext + res, 
		 dtls_kb_digest_size(CURRENT_CONFIG(peer))) == 0) {
	*clen = res;
	ok = 1;
      }
    }
    break;
#endif /* TLS_PSK_WITH_AES_128_CBC_SHA */

  default:
    warn("unknown cipher!\n");
    /* fall through and fail */
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

    /* renogotiation */
    if (dtls_verify_peer(ctx, peer, &peer->session, 
			 record_header, data, data_length) > 0) {

      clear_hs_hash(peer);

      if (!dtls_update_parameters(ctx, peer, data, data_length)) {
	
	warn("error updating security parameters\n");
	/* FIXME: send Alert */
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
handle_css(dtls_context_t *ctx, dtls_peer_t *peer, 
	   uint8 *record_header, uint8 *data, size_t data_length) {

  /* A CSS message is handled after a KeyExchange message was
   * received from the client. When security parameters have been
   * updated successfully and a ChangeCipherSpec message was sent
   * by ourself, the security context is switched and the record
   * sequence number is reset. */
  
  if (peer->state != DTLS_STATE_KEYEXCHANGE
      || !check_css(ctx, peer, record_header, data, data_length)) {
    /* signal error? */
    warn("expected ChangeCipherSpec during handshake\n");
    return 0;

  }

  /* send change cipher spec message and switch to new configuration */
  if (dtls_send_css(ctx, peer) < 0) {
    warn("cannot send CSS message");
    return 0;
  } 
  
  SWITCH_CONFIG(peer);
  inc_uint(uint16, peer->epoch);
  memset(peer->rseq, 0, sizeof(peer->rseq));
  
  peer->state = DTLS_STATE_WAIT_FINISHED;

#ifndef NDEBUG
  {
      printf("key_block:\n");
      printf("  client_MAC_secret:\t");  
      dump(dtls_kb_client_mac_secret(CURRENT_CONFIG(peer)), 
	   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  server_MAC_secret:\t");  
      dump(dtls_kb_server_mac_secret(CURRENT_CONFIG(peer)), 
	   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  client_write_key:\t");  
      dump(dtls_kb_client_write_key(CURRENT_CONFIG(peer)), 
	   dtls_kb_key_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  server_write_key:\t");  
      dump(dtls_kb_server_write_key(CURRENT_CONFIG(peer)), 
	   dtls_kb_key_size(CURRENT_CONFIG(peer)));
      printf("\n");

      printf("  client_IV:\t\t");  
      dump(dtls_kb_client_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));
      printf("\n");
      
      printf("  server_IV:\t\t");  
      dump(dtls_kb_server_iv(CURRENT_CONFIG(peer)), 
	   dtls_kb_iv_size(CURRENT_CONFIG(peer)));
      printf("\n");
      

  }
#endif

  return 1;
}  

#define DTLS_ALERT_CLOSE 0

/** 
 * Handles incoming Alert messages. This function returns \c 1 if the
 * connection should be closed and the peer is to be invalidated.
 */
int
handle_alert(dtls_context_t *ctx, dtls_peer_t *peer, 
	     uint8 *record_header, uint8 *data, size_t data_length) {
  if (data_length < 2)
    return 0;

  info("** Alert: level %d, description %d\n", data[0], data[1]);

  switch (data[1]) {
  case DTLS_ALERT_CLOSE:
    memcpy(ctx->sendbuf, data, 2);
    dtls_send(ctx, peer, DTLS_CT_ALERT, ctx->sendbuf, 2);
    return 1;
  default:
    ;
  }
  
  return 1;
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

  /* check if we have DTLS state for raddr/ifindex */
  HASH_FIND_PEER(ctx->peers, session, peer);

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
    if (!dtls_update_parameters(ctx, peer, 
			msg + DTLS_RH_LENGTH, rlen - DTLS_RH_LENGTH)) {

      warn("error updating security parameters\n");
      /* FIXME: send handshake failure Alert */
      dtls_free_peer(peer);
      return -1;
    }

    HASH_ADD_PEER(ctx->peers, session, peer);
    
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

#ifndef NDEBUG
    hexdump(msg, sizeof(dtls_record_header_t));
    printf("\n");
    hexdump(data, data_length);
    printf("\n");
#endif

    /* Handle received record according to the first byte of the
     * message, i.e. the subprotocol. We currently do not support
     * combining multiple fragments of one type into a single
     * record. */

    switch (msg[0]) {

    case DTLS_CT_CHANGE_CIPHER_SPEC:
      handle_css(ctx, peer, msg, data, data_length);
      break;

    case DTLS_CT_ALERT:
      if (handle_alert(ctx, peer, msg, data, data_length)) {

	/* invalidate peer */
	HASH_DEL_PEER(ctx->peers, peer);
	dtls_free_peer(peer);

	return 0;
      }
      break;

    case DTLS_CT_HANDSHAKE:
      handle_handshake(ctx, peer, msg, data, data_length);
      break;

    case DTLS_CT_APPLICATION_DATA:
      info("** application data:\n");
      if (ctx->cb_read) 
	ctx->cb_read(ctx, &peer->session, data, data_length);
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

  c = (dtls_context_t *)malloc(sizeof(dtls_context_t));
  if (!c)
    goto error;

  memset(c, 0, sizeof(dtls_context_t));
  c->app = app_data;
  
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

int
dtls_set_psk(dtls_context_t *ctx, unsigned char *psk, size_t length,
	     unsigned char *psk_identity, size_t id_length) {
  if (ctx->psk)
    free(ctx->psk);

  ctx->psk = (unsigned char *)malloc(length);
  if (!ctx->psk) 
    goto error;

  ctx->psk_length = length;
  memcpy(ctx->psk, psk, ctx->psk_length);

  if (ctx->psk_id)
    free(ctx->psk_id);

  ctx->psk_id = (unsigned char *)malloc(id_length);
  if (!ctx->psk_id)
    goto error;
  
  ctx->psk_id_length = id_length;
  memcpy(ctx->psk_id, psk_identity, ctx->psk_id_length);
  return 1;

error:				/* clean up in case of error */
  free(ctx->psk);
  ctx->psk = NULL;
  ctx->psk_length = 0;

  free(ctx->psk_id);
  ctx->psk_id = NULL;
  ctx->psk_id_length = 0;
  
  return 0;
}

void dtls_free_context(dtls_context_t *ctx) {
  dtls_peer_t *peer, *tmp;
  
  if (ctx->peers) {
    HASH_ITER(hh, ctx->peers, peer, tmp) {
      /*peer_free(peer);*/
      free(peer);
    }
  }

  free(ctx->psk);
  free(ctx);    
}

int
dtls_connect(dtls_context_t *ctx, session_t *dst) {
  dtls_peer_t *peer;
  uint8 *p = ctx->sendbuf;
  size_t size;
  int j, res;

  /* check if we have DTLS state for raddr/ifindex */
  HASH_FIND_PEER(ctx->peers, dst, peer);
  if (peer) {
    debug("found peer, try to re-connect\n");
    /* FIXME: send HelloRequest if we are server, 
       ClientHello with good cookie if client */
    return 0;
  }

  peer = dtls_new_peer(ctx, dst);

  /* set peer role to server: */
  OTHER_CONFIG(peer)->role = 1;
  CURRENT_CONFIG(peer)->role = 1;

  HASH_ADD_PEER(ctx->peers, session, peer);

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
  prng(OTHER_CONFIG(peer)->client_random, 
       sizeof(OTHER_CONFIG(peer)->client_random));
  dtls_int_to_uint32(&OTHER_CONFIG(peer)->client_random, clock_time());
  memcpy(p, OTHER_CONFIG(peer)->client_random, 
	 sizeof(OTHER_CONFIG(peer)->client_random));
  p += 32;

  /* session id (length 0) */
  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  /* FIXME: add everything from ciphers[] */
  dtls_int_to_uint16(p, 2);
  p += sizeof(uint16);
  
  memcpy(p, ciphers[j].code, sizeof(uint16));
  p += sizeof(uint16);
  
  /* compression method */
  dtls_int_to_uint8(p, 1);  
  p += sizeof(uint8);

  dtls_int_to_uint8(p, 0);
  p += sizeof(uint8);

  res = dtls_send(ctx, peer, DTLS_CT_HANDSHAKE, ctx->sendbuf, 
		  p - ctx->sendbuf);
  if (res < 0)
    warn("cannot send ClientHello\n");
  else 
    peer->state = DTLS_STATE_CLIENTHELLO;

  return res;
}

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

