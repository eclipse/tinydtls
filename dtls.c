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
#include <time.h>
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

#define IS_HANDSHAKE(M,L) \
      ((L) >= DTLS_RH_LENGTH + DTLS_HS_LENGTH && (M)[0] == DTLS_CT_HANDSHAKE)
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

int 
dtls_get_cookie(uint8 *hello_msg, int msglen, uint8 **cookie) {
  /* To access the cookie, we have to determine the session id's
   * length and skip the whole thing. */
  if (msglen < DTLS_CH_LENGTH + sizeof(uint8)
      || dtls_uint16_to_int(hello_msg) != DTLS_VERSION)
    return -1;

  msglen -= DTLS_CH_LENGTH;
  hello_msg += DTLS_CH_LENGTH;

  SKIP_VAR_FIELD(hello_msg, msglen, uint8); /* skip session id */

  if (msglen < (*hello_msg & 0xff) + sizeof(uint8))
    return -1;
  
  *cookie = hello_msg + sizeof(uint8);
  debug("found cookie field (len: %d)\n", *hello_msg & 0xff);
  return *hello_msg & 0xff;

 error:
  return -1;
}

int
dtls_create_cookie(dtls_context_t *ctx, 
		   session_t *session,
		   uint8 *msg, int msglen,
		   uint8 *cookie, int *clen) {

  dtls_hmac_context_t hmac_context;
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
		 HASH_SHA256);

  dtls_hmac_update(&hmac_context, 
		   (unsigned char *)&session->raddr, 
		   sizeof(session->raddr));

  /* feed in the beginning of the Client Hello up to and including the
     session id */
  e = sizeof(dtls_client_hello_t);
  e += (*(msg + HS_HDR_LENGTH + e) & 0xff) + sizeof(uint8);

  dtls_hmac_update(&hmac_context, msg + HS_HDR_LENGTH, e);
  
  /* skip cookie bytes and length byte */
  e += *(uint8 *)(msg + HS_HDR_LENGTH + e) & 0xff;
  e += sizeof(uint8);

  dtls_hmac_update(&hmac_context, 
		   msg + HS_HDR_LENGTH + e, 
		   dtls_get_fragment_length(HANDSHAKE(msg)) - e);

  len = dtls_hmac_finalize(&hmac_context, _buf);

  if (len < *clen) {
    memset(cookie + len, 0, *clen - len);
    *clen = len;
  }
  
  memcpy(cookie, _buf, *clen);
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

static inline int 
is_client_hello(uint8 *msg, int msglen) {
  return  (msglen > HS_HDR_LENGTH)
    && DTLS_RECORD_HEADER(msg)->content_type == DTLS_CT_HANDSHAKE
    && HANDSHAKE(msg)->msg_type == DTLS_HT_CLIENT_HELLO;
}

static inline int 
is_change_cipher_spec(uint8 *msg, int msglen) {
  return DTLS_RECORD_HEADER(msg)->content_type == DTLS_CT_CHANGE_CIPHER_SPEC
    && dtls_uint16_to_int(DTLS_RECORD_HEADER(msg)->length) == 1
    && *(msg + DTLS_RH_LENGTH) == 0x01;
}

int
dtls_verify_peer(dtls_context_t *ctx, 
		    session_t *session,
		    uint8 *msg, int msglen) {

  int len, clen = DTLS_COOKIE_LENGTH;
  uint8 *cookie;

  static uint8 buf[HV_HDR_LENGTH+DTLS_COOKIE_LENGTH] = { 
    /* Record header */
    DTLS_CT_HANDSHAKE,		/* handshake message */
    HIGH(DTLS_VERSION),		/* DTLS version (1.0) */
    LOW(DTLS_VERSION), 		
    0, 0,			/* epoch */
    0, 0, 0, 0, 0, 0,		/* sequence number */
    HIGH(DTLS_HS_LENGTH + DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH),
    LOW(DTLS_HS_LENGTH + DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH),

    /* Handshake header */
    DTLS_HT_HELLO_VERIFY_REQUEST, /* handshake type: hello verify */
    0, 0, LOW(DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH), /* length of Hello verfy */
    0, 0,			/* message sequence */
    0, 0, 0,			/* fragment offset */
    0, 0, LOW(DTLS_HV_LENGTH + DTLS_COOKIE_LENGTH), /* fragment length */

    /* Hello Verify request */
    HIGH(DTLS_VERSION),		/* DTLS version (1.0) */
    LOW(DTLS_VERSION), 		
    DTLS_COOKIE_LENGTH			/* cookie length */
    /* 32 bytes cookie */
  };

  /* check if we can access at least all fields from the handshake header */
  if (is_client_hello(msg, msglen)) {
    
    /* Perform rough cookie check. */
    len = dtls_get_cookie((uint8 *)CLIENTHELLO(msg), 
			  msglen - HS_HDR_LENGTH,
			  &cookie);

    if (len == 0) {		/* no cookie */
      if (dtls_create_cookie(ctx, session, msg, msglen, 
			     buf + HV_HDR_LENGTH, &clen) < 0)
	return -1;
      assert(clen == DTLS_COOKIE_LENGTH);
      
      /* send Hello Verify request using registered callback */
      ctx->cb_write(ctx,
		    &session->raddr.sa, session->rlen, session->ifindex,
		    buf, sizeof(buf));
      
      return 0;			/* cannot do anything but wait */
      
    } else {			/* found a cookie, check it */
      if (len != DTLS_COOKIE_LENGTH 
	  || dtls_create_cookie(ctx, session, msg, msglen, 
				buf + HV_HDR_LENGTH, &clen) < 0) 
	return -1;		/* discard */
      assert(clen == DTLS_COOKIE_LENGTH);
    
      /* compare if both values match */
      if (memcmp(cookie, buf + HV_HDR_LENGTH, clen) == 0)
	return 1;

      debug("accepted cookie\n");
    }
  }

  return -1;
}

/** only one compression method is currently defined */
uint8 compression_methods[] = { 
  TLS_COMP_NULL 
};

int
dtls_update_parameters(dtls_context_t *ctx, 
		       session_t *session,
		       uint8 *msg, size_t msglen,
		       dtls_security_parameters_t *config) {
  int i, j;
  int ok;

  assert(msglen > HS_HDR_LENGTH + DTLS_CH_LENGTH);

  debug("dtls_update_parameters: msglen is %d\n", msglen);

  /* skip the handshake header and client version information */
  msg += HS_HDR_LENGTH + sizeof(uint16);
  msglen -= HS_HDR_LENGTH + sizeof(uint16);

  /* store client random in config */
  memcpy(config->client_random, msg, sizeof(config->client_random));
  msg += sizeof(config->client_random);
  msglen -= sizeof(config->client_random);

  /* Caution: SKIP_VAR_FIELD may jump to error: */
  SKIP_VAR_FIELD(msg, msglen, uint8);	/* skip session id */
  SKIP_VAR_FIELD(msg, msglen, uint8);	/* skip cookie */

  i = dtls_uint16_to_int(msg);
  if (msglen < i + sizeof(uint16))
    goto error;

  msg += sizeof(uint16);
  msglen -= sizeof(uint16) + i;

  ok = 0;
  while (i && !ok) {
    for (j = 0; dtls_uint16_to_int(ciphers[j].code) != 0; ++j)
      if (memcmp(msg, &ciphers[j].code, sizeof(uint16)) == 0) {
	config->cipher = j;
	ok = 1;
      }
    i -= sizeof(uint16);
    msg += sizeof(uint16);
  }

  /* skip remaining ciphers */
  msg += i;

  if (!ok)
    return 0;

  if (msglen < sizeof(uint8))
    goto error;
  
  i = dtls_uint8_to_int(msg);
  if (msglen < i + sizeof(uint8))
    goto error;

  msg += sizeof(uint8);
  msglen -= sizeof(uint8) + i;

  ok = 0;
  while (i && !ok) {
    for (j = 0; j < sizeof(compression_methods) / sizeof(uint8); ++j)
      if (dtls_uint8_to_int(msg) == compression_methods[j]) {
	config->compression = compression_methods[j];
	ok = 1;
      }
    i -= sizeof(uint8);
    msg += sizeof(uint8);    
  }
  
  return ok;
 error:
  warn("ClientHello too short (%d bytes)\n", msglen);
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
	  uint8 *record, size_t  rlen,
	  uint8 *data, size_t data_length) {

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
  cipher_context = &OTHER_CONFIG(peer)->read_cipher;
  if (*cipher_context)
    free(OTHER_CONFIG(peer)->read_cipher);

  assert(OTHER_CONFIG(peer)->cipher != -1);
  *cipher_context = 
    dtls_new_cipher(&ciphers[OTHER_CONFIG(peer)->cipher],
		    dtls_kb_client_write_key(OTHER_CONFIG(peer)),
		    dtls_kb_key_size(OTHER_CONFIG(peer)));

  if (!*cipher_context) {
    warn("cannot create cipher\n");
    return 0;
  }

  dtls_init_cipher(*cipher_context,
		   dtls_kb_client_iv(OTHER_CONFIG(peer)),
		   dtls_kb_iv_size(OTHER_CONFIG(peer)));
  return 1;
}

/**
 * Initializes \p buf as record header. The caller must ensure that \p
 * buf is capable of holding at least \c sizeof(dtls_record_header_t)
 * bytes. Increments sequence number counter of \p peer.
 * \return pointer to the next byte after the written header
 */ 
static inline uint8 *
dtls_set_record_header(uint8 type, dtls_peer_t *peer, uint8 *buf) {
  
  DTLS_RECORD_HEADER(buf)->content_type = type;
  ++buf;

  /* increment record sequence counter by 1 */
  inc_uint(uint48, peer->rseq);

  dtls_int_to_uint16(buf, DTLS_VERSION);
  buf += sizeof(uint16);

  memcpy(buf, &peer->epoch, sizeof(uint16) + sizeof(uint48));
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
  
  DTLS_HANDSHAKE_HEADER(buf)->msg_type = type;
  ++buf;

  dtls_int_to_uint24(buf, length);
  buf += sizeof(uint24);

  /* increment handshake message sequence counter by 1 */
  inc_uint(uint16, peer->mseq);
  
  /* and copy the result to buf */
  memcpy(buf, &peer->mseq, sizeof(uint16));
  buf += sizeof(uint16);
  
  dtls_int_to_uint24(buf, frag_offset);
  buf += sizeof(uint24);

  dtls_int_to_uint24(buf, frag_length);
  buf += sizeof(uint24);
  
  return buf;
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
    /* TLS 1.0: PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
                                           P_SHA-1(S2, label + seed); */
    peer->hs_hash[0] = dtls_new_hash(HASH_MD5);
    peer->hs_hash[1] = dtls_new_hash(HASH_SHA1);

    peer->hs_hash[0]->init(peer->hs_hash[0]->data);
    peer->hs_hash[1]->init(peer->hs_hash[1]->data);
#elif DTLS_VERSION == 0xfefd
    /* TLS 1.2:  PRF(secret, label, seed) = P_<hash>(secret, label + seed) */
    /* FIXME: we use the default SHA256 here, might need to support other 
              hash functions as well */
    peer->hs_hash[0] = dtls_new_hash(HASH_SHA256);
    peer->hs_hash[0]->init(peer->hs_hash[0]->data);
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
#define FINISH_DIGEST_LEN SHA2_DIGEST_LENGTH
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
    free(peer->hs_hash[i]);
  memset(peer->hs_hash, 0, sizeof(peer->hs_hash));
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
check_client_finished(dtls_context_t *ctx, 
		      dtls_peer_t *peer,
		      uint8 *record, size_t rlen,
		      uint8 *foodata, size_t data_length) {
  size_t digest_length;
  unsigned char verify_data[DTLS_FIN_LENGTH];

#if DTLS_VERSION == 0xfeff
  unsigned char statebuf[sizeof(md5_state_t) + sizeof(SHA_CTX)];
#elif DTLS_VERSION == 0xfefd
  unsigned char statebuf[sizeof(SHA256_CTX)];
#endif

  debug("checking for client Finish\n");
  if (!IS_HANDSHAKE(record, rlen) || !IS_FINISHED(foodata, data_length)) {
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
  memcpy(statebuf, hs_peer->hash[0]->data, sizeof(statebuf));
#endif

  digest_length = finalize_hs_hash(peer, _buf);
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

  dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   (unsigned char *)"client finished", 15,
	   _buf, digest_length,
	   NULL, 0,
	   verify_data, sizeof(verify_data));

  return memcmp(foodata + DTLS_HS_LENGTH, verify_data, sizeof(verify_data)) == 0;
}

int
dtls_server_hello(dtls_context_t *ctx, 
		  dtls_peer_t *peer,
		  uint8 *buf, int buflen) {

  uint8 *p = buf, *q;

#ifndef NDEBUG
  if (buflen < (DTLS_RH_LENGTH + DTLS_HS_LENGTH) * 2 + DTLS_SH_LENGTH) {
    dsrv_log(LOG_CRIT, "dtls_server_hello: buffer too small\n");
#endif
    return -1;
  }

  p = dtls_set_record_header(DTLS_CT_HANDSHAKE, peer, p);

  /* set packet length */
  dtls_int_to_uint16(p - sizeof(uint16), DTLS_HS_LENGTH + DTLS_SH_LENGTH);

  /* save start of handshake message for calling update_hs_hash() */
  q = p;

  /* Handshake header */
  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO, 
				peer,
				DTLS_SH_LENGTH, 
				0, DTLS_SH_LENGTH,
				p);

  /* ServerHello */
  dtls_int_to_uint16(p, DTLS_VERSION);
  p += sizeof(uint16);

  /* FIXME: set server random */
  dtls_int_to_uint32(&OTHER_CONFIG(peer)->server_random, time(NULL));
  OTHER_CONFIG(peer)->server_random[4] = 0xAB; /* random... */
  OTHER_CONFIG(peer)->server_random[31] = 0x13;

  /* random gmt and server random bytes */
  memcpy(p, &OTHER_CONFIG(peer)->server_random, 32);
  p += 32;

  *p++ = 0;			/* no session id */

  /* selected cipher suite */
  memcpy(p, ciphers[OTHER_CONFIG(peer)->cipher].code, sizeof(uint16));
  p += sizeof(uint16);

  /* selected compression method */
  *p++ = compression_methods[OTHER_CONFIG(peer)->compression];

  /* no PSK hint, therefore, we do not need the server key exchange */

  /* update the finish hash 
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, q, p - q);

  /* add the ServerHelloDone to avoid multiple records in flight */
  p = dtls_set_record_header(DTLS_CT_HANDSHAKE, peer, p);
  
  /* set packet length */
  dtls_int_to_uint16(p - sizeof(uint16), DTLS_HS_LENGTH);

  /* save start of handshake message for calling update_hs_hash() */
  q = p;

  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO_DONE, 
				peer,
				0, /* ServerHelloDone has no extra fields */
				0, 0, /* ServerHelloDone has no extra fields */
				p);

  /* update the finish hash 
     (FIXME: better put this in generic record_send function) */
  update_hs_hash(peer, q, p - q);

  return ctx->cb_write(ctx,
		       &peer->session.raddr.sa, peer->session.rlen, 
		       peer->session.ifindex,
		       buf, p - buf);
}

int
dtls_server_finished(dtls_context_t *ctx, 
	      dtls_peer_t *peer,
	      uint8 *buf, int buflen) {

  size_t digest_length;
  uint8 *p = buf, *q;

#ifndef NDEBUG
  if (buflen < DTLS_RH_LENGTH + DTLS_HS_LENGTH + DTLS_FIN_LENGTH) {
    dsrv_log(LOG_CRIT, "dtls_finished: buffer too small\n");
#endif
    return -1;
  }

  p = dtls_set_record_header(DTLS_CT_HANDSHAKE, peer, p);

  /* set packet length */
  dtls_int_to_uint16(p - sizeof(uint16), DTLS_HS_LENGTH + DTLS_FIN_LENGTH);

  /* add IV */
  prng(p, ciphers[CURRENT_CONFIG(peer)->cipher].blk_length);
  p += ciphers[CURRENT_CONFIG(peer)->cipher].blk_length;

  /* Handshake header */
  q = p;
  p = dtls_set_handshake_header(DTLS_HT_FINISHED, 
				peer,
				DTLS_FIN_LENGTH, 
				0, DTLS_FIN_LENGTH,
				p);

  digest_length = finalize_hs_hash(peer, _buf);

  dtls_prf(CURRENT_CONFIG(peer)->master_secret, 
	   DTLS_MASTER_SECRET_LENGTH,
	   (unsigned char *)"server finished", 15,
	   _buf, digest_length,
	   NULL, 0,
	   p, DTLS_FIN_LENGTH);

  p += DTLS_FIN_LENGTH;

  {
    dtls_hmac_context_t hmac_ctx;

  /* add MAC */
    dtls_hmac_init(&hmac_ctx, 
		   dtls_kb_client_mac_secret(CURRENT_CONFIG(peer)),
		   dtls_kb_mac_secret_size(CURRENT_CONFIG(peer)),
		   dtls_kb_mac_algorithm(CURRENT_CONFIG(peer)));
    dtls_mac(&hmac_ctx, 
	     buf, 		/* the pre-filled record header */
	     q, p - q,
	     p);
  }

  /* encrypt (adds padding) */
  /*  FIXME: something like this: 
      dtls_cbc_encrypt(CURRENT_CONFIG(peer),
		   buf, p - buf,
		   result, DTLS_MAX_BUF);
  */

  return ctx->cb_write(ctx,
		       &peer->session.raddr.sa, peer->session.rlen, 
		       peer->session.ifindex,
		       buf, p - buf);
}

int
decrypt_verify(dtls_peer_t *peer,
	       uint8 *packet, size_t length,
	       uint8 **cleartext, size_t *clen) {
  int res;
  
  *cleartext = NULL;
  *clen = 0;

  switch (CURRENT_CONFIG(peer)->cipher) {
  case -1:			/* no cipher suite selected */
    *cleartext = packet + sizeof(dtls_record_header_t);
    *clen = dtls_uint16_to_int(((dtls_record_header_t *)packet)->length);
    return 1;
  case 0:			/* TLS_PSK_WITH_AES128_CBC_SHA */
    if (length > sizeof(_buf))
      return 0;

    res = dtls_decrypt(CURRENT_CONFIG(peer)->read_cipher, packet, length);
    if (res < 0) {
      warn("decryption failed!\n");
    } else {
      *cleartext = packet;
      *clen = res;
    }
    break;
  default:
    warn("unknown cipher!\n");
    /* fall through and let dtls_verify() fail */
  }

  return dtls_verify(CURRENT_CONFIG(peer), packet, length, *cleartext, *clen);
}

/** 
 * Handles incoming data as DTLS message from given peer.
 */
int
dtls_handle_message(dtls_context_t *ctx, 
		    session_t *session,
		    uint8 *msg, int msglen) {
  dtls_peer_t *peer = NULL;
  uint8 buf[DTLS_MAX_BUF];
  unsigned int rlen;		/* record length */
  uint8 *data; 			/* (decrypted) payload */
  size_t data_length;		/* length of decrypted payload 
				   (without MAC and padding) */

  /* check if we can send everything in one message */
#if DTLS_MAX_BUF < 88
#error "DTLS_MAX_BUF too small!"
#endif

  /* TODO: check if we have DTLS state for raddr/ifindex */
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

    /* When no DTLS state exists for this peer, we only allow a
       Client Hello message with 
        
       a) a valid cookie, or 
       b) no cookie.

       Anything else will be rejected. Fragementation is not allowed
       here as it would require peer state as well.
    */

    if (dtls_verify_peer(ctx, session, msg, rlen) <= 0) {
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

    /* First negotiation step: check for PSK
     *
     * Note that we already have checked that msg is a Handshake
     * message containing a ClientHello. dtls_get_cipher() therefore
     * does not check again.
     */
    if (!dtls_update_parameters(ctx, session, msg, rlen, 
				OTHER_CONFIG(peer))) {

      warn("error updating security parameters\n");
      /* FIXME: send handshake failure Alert */
      dtls_free_peer(peer);
      return -1;
    }

    HASH_ADD_PEER(ctx->peers, session, peer);
    
    /* update finish MAC */
    update_hs_hash(peer, msg + DTLS_RH_LENGTH, rlen - DTLS_RH_LENGTH); 
 
    if (dtls_server_hello(ctx, peer, buf, sizeof(buf)) > 0)
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

    switch (peer->state) {

    case DTLS_STATE_INIT:
      /* this should not happen */
      assert(0);
      msglen = rlen = 0;
      break;

    case DTLS_STATE_SERVERHELLO:
      /* here we expect a ClientHello */
      /* handle ClientHello, update msg and msglen and goto next if not finished */

      debug("DTLS_STATE_SERVERHELLO\n");
      if (!check_client_keyexchange(ctx, peer, data, data_length)) {
	warn("check_client_keyexchange failed (%d, %d)\n", data_length, data[0]);
	return 0;		/* drop it, whatever it is */
      }

      update_hs_hash(peer, data, data_length);
      peer->state = DTLS_STATE_KEYEXCHANGE;
      break;

    case DTLS_STATE_KEYEXCHANGE:
      /* here we expect a ChangeCipherSpec message */

      debug("DTLS_STATE_KEYEXCHANGE\n");
      if (!check_css(ctx, peer, msg, rlen, data, data_length)) {
	/* signal error? */
	warn("expected ChangeCipherSpec during handshake\n");
	return 0;
      }

      SWITCH_CONFIG(peer);
      inc_uint(uint16, peer->epoch);

      peer->state = DTLS_STATE_WAIT_FINISHED; /* wait for finished message */
      break;

    case DTLS_STATE_WAIT_FINISHED:
      debug("DTLS_STATE_WAIT_FINISHED\n");
      if (check_client_finished(ctx, peer, msg, rlen, data, data_length)) {
	debug("finished!\n");
	
	/* send ServerFinished */
	update_hs_hash(peer, data, data_length);

	if (dtls_server_finished(ctx, peer, buf, sizeof(buf)) > 0) {
	  peer->state = DTLS_STATE_FINISHED;
	} else {
	  warn("sending server Finished failed\n");
	}
      } else {
	/* send alert */
      }
      break;
      
    case DTLS_STATE_FINISHED:
      /* handshake is finished */
      
      debug("TODO: check for finished\n");
      msglen = 0;
      break;

    default:
      dsrv_log(LOG_CRIT, "unhandled state %d\n", peer->state);
      assert(0);
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

  prng_init(app_data);

  c = (dtls_context_t *)malloc(sizeof(dtls_context_t));
  if (c) {
    memset(c, 0, sizeof(dtls_context_t));
    c->app = app_data;

    if (prng(c->cookie_secret, DTLS_COOKIE_SECRET_LENGTH))
      time(&c->cookie_secret_age);
    else 
      dsrv_log(LOG_ALERT, "cannot initalize cookie secret");
  }
  
  return c;
}

int
dtls_set_psk(dtls_context_t *ctx, unsigned char *psk, size_t length) {
  if (ctx->psk)
    free(ctx->psk);

  ctx->psk = (unsigned char *)malloc(length);
  if (!ctx->psk) {
    ctx->psk_length = 0;
    return 0;
  }

  ctx->psk_length = length;
  memcpy(ctx->psk, psk, ctx->psk_length);
  return 1;
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

