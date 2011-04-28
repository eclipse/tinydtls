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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include "debug.h"
#include "numeric.h"
#include "dtls.h"

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

/* The length check here should work because dtls_*_to_int() works on
 * unsigned char. Otherwise, broken messages could cause severe
 * trouble.
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

  HMAC_CTX hmac_context;
  unsigned int len, e;
  static unsigned char buf[EVP_MAX_MD_SIZE];

  /* create cookie with HMAC-SHA256 over:
   * - SECRET
   * - session parameters (only IP address?)
   * - client version 
   * - random gmt and bytes
   * - session id
   * - cipher_suites 
   * - compression method
   */
  
  HMAC_Init(&hmac_context, ctx->cookie_secret, DTLS_COOKIE_SECRET_LENGTH, 
	    EVP_sha256());

  /* use only IP address? */
  HMAC_Update(&hmac_context, (unsigned char *)&session->raddr, 
	      sizeof(session->raddr));

  /* feed in the beginning of the Client Hello up to and including the
     session id */
  e = sizeof(dtls_client_hello_t);
  e += (*(msg + HS_HDR_LENGTH + e) & 0xff) + sizeof(uint8);

  HMAC_Update(&hmac_context, msg + HS_HDR_LENGTH, e);
  
  /* skip cookie bytes and length byte */
  e += *(uint8 *)(msg + HS_HDR_LENGTH + e) & 0xff;
  e += sizeof(uint8);

  HMAC_Update(&hmac_context, msg + HS_HDR_LENGTH + e, 
	      dtls_get_fragment_length(HANDSHAKE(msg)) - e);

  HMAC_Final(&hmac_context, buf, &len);
  HMAC_cleanup(&hmac_context);

  if (len < *clen) {
    memset(cookie, 0, *clen);
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

static int
is_finished(dtls_context_t *ctx, 
	    dtls_peer_t *peer,
	    uint8 *msg, int msglen) {
  return 1;
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
		       uint8 *msg, int msglen,
		       dtls_security_parameters_t *config) {
  int i, j;
  int ok;

  assert(msglen > HS_HDR_LENGTH + DTLS_CH_LENGTH);

  /* FIXME: store client random in *config */

  msg += HS_HDR_LENGTH + DTLS_CH_LENGTH;
  msglen -= HS_HDR_LENGTH + DTLS_CH_LENGTH;

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
  warn("ClientHello too short\n");
  return 0;
}

int
dtls_check_client_keyexchange(dtls_context_t *ctx, 
			      dtls_peer_t *peer,
			      uint8 *msg, int msglen) {
  return msglen >= DTLS_RH_LENGTH + DTLS_CKX_LENGTH
    && *(msg + DTLS_RH_LENGTH) == DTLS_HT_CLIENT_KEY_EXCHANGE;
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
  }
  
  return peer;
}

/** Releases the storage occupied by peer. */
void
dtls_free_peer(dtls_peer_t *peer) {
}

int
dtls_server_hello(dtls_context_t *ctx, 
		  dtls_peer_t *peer,
		  uint8 *buf, int buflen) {

  uint8 *p = buf;

#ifndef NDEBUG
  if (buflen < (DTLS_RH_LENGTH + DTLS_HS_LENGTH) * 2 + DTLS_SH_LENGTH) {
    dsrv_log(LOG_CRIT, "dtls_server_hello: buffer too small\n");
#endif
    return -1;
  }

  p = dtls_set_record_header(DTLS_CT_HANDSHAKE, peer, p);

  /* set packet length */
  dtls_int_to_uint16(p - sizeof(uint16), DTLS_HS_LENGTH + DTLS_SH_LENGTH);

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
  memcpy(p, &OTHER_CONFIG(peer)->cipher, sizeof(uint16));
  p += sizeof(uint16);

  /* selected compression method */
  *p++ = compression_methods[OTHER_CONFIG(peer)->compression];

  /* no PSK hint, therefore, we do not need the server key exchange */

  /* add the ServerHelloDone to avoid multiple records in flight */
  p = dtls_set_record_header(DTLS_CT_HANDSHAKE, peer, p);
  
  /* set packet length */
  dtls_int_to_uint16(p - sizeof(uint16), DTLS_HS_LENGTH);

  p = dtls_set_handshake_header(DTLS_HT_SERVER_HELLO_DONE, 
				peer,
				0, /* ServerHelloDone has no extra fields */
				0, 0, /* ServerHelloDone has no extra fields */
				p);

  return ctx->cb_write(ctx,
		       &peer->session.raddr.sa, peer->session.rlen, 
		       peer->session.ifindex,
		       buf, p - buf);
}

int
dtls_finished(dtls_context_t *ctx, 
	      dtls_peer_t *peer,
	      uint8 *buf, int buflen) {

  uint8 *p = buf;

#ifndef NDEBUG
  if (buflen < DTLS_RH_LENGTH + DTLS_HS_LENGTH + DTLS_FIN_LENGTH) {
    dsrv_log(LOG_CRIT, "dtls_finished: buffer too small\n");
#endif
    return -1;
  }

  p = dtls_set_record_header(DTLS_CT_HANDSHAKE, peer, p);

  /* set packet length */
  dtls_int_to_uint16(p - sizeof(uint16), DTLS_HS_LENGTH + DTLS_FIN_LENGTH);

  /* Handshake header */
  p = dtls_set_handshake_header(DTLS_HT_FINISHED, 
				peer,
				DTLS_FIN_LENGTH, 
				0, DTLS_FIN_LENGTH,
				p);

  /* Finished */
  /* create premaster_secret from ctx->psk according to RFC 4279 
     tmplen = premaster_secret(tmp, ctx->psk) */
  /* prf(tmp, tmplen, "server finished", 15, peer->premaster_secret, p); */
  /* p += FIXME; */

  return ctx->cb_write(ctx,
		       &peer->session.raddr.sa, peer->session.rlen, 
		       peer->session.ifindex,
		       buf, p - buf);
}

unsigned int
check_and_decrypt(dtls_context_t *ctx, 
		  dtls_peer_t *peer, 
		  uint8 *msg, int msglen) {
  unsigned int rlen = is_record(msg, msglen);
  if (!rlen)
    return 0;

  /* decrypt! */

 

  return rlen;
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
  unsigned int rlen, clen; /* record length and cleartext record length */

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

  while (msglen > 0) {

    rlen = check_and_decrypt(ctx, peer, msg, msglen);
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

    assert(peer);
    switch (peer->state) {

    case DTLS_STATE_INIT:
      /* this should not happen */
      assert(0);
      msglen = 0;
      break;

    case DTLS_STATE_SERVERHELLO:
      /* here we expect a ClientHello */
      /* handle ClientHello, update msg and msglen and goto again if not finished */

      if (!dtls_check_client_keyexchange(ctx, peer, msg, rlen))
	return 0;		/* drop it, whatever it is */

      peer->state = DTLS_STATE_KEYEXCHANGE;
      break;

    case DTLS_STATE_KEYEXCHANGE:
      /* here we expect a ChangeCipherSpec message */
      /* SWITH_CONFIG(peer) */

      if (is_change_cipher_spec(msg, rlen)) {
	SWITCH_CONFIG(peer);
	peer->state = DTLS_STATE_WAIT_FINISHED; /* wait for finished message */
      } else {
	/* signal error? */
	warn("expected ChangeCipherSpec during handshake\n");
	return 0;
      }      
      break;

    case DTLS_STATE_WAIT_FINISHED:
      if (is_finished(ctx, peer, msg, rlen)) {
	debug("finished!\n");
	/* if (dtls_finished(ctx, peer, buf, sizeof(buf)) > 0) */
	  peer->state = DTLS_STATE_FINISHED;
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

    /* advande msg by length of ciphertext */
    rlen = dtls_uint16_to_int(DTLS_RECORD_HEADER(msg)->length);
    msg += rlen;
    msglen -= rlen;
  }

  return 0;
}

dtls_context_t *
dtls_new_context(void *app_data) {
  dtls_context_t *c;

  c = (dtls_context_t *)malloc(sizeof(dtls_context_t));
  if (c) {
    memset(c, 0, sizeof(dtls_context_t));
    c->app = app_data;

    if (RAND_bytes(c->cookie_secret, DTLS_COOKIE_SECRET_LENGTH))
      time(&c->cookie_secret_age);
    else 
      dsrv_log(LOG_ALERT, "cannot initalize cookie secret: %s",
	       ERR_error_string(ERR_get_error(), NULL));

    c->psk = (unsigned char *)malloc(9);
    if (c->psk)
      memcpy(c->psk, "secretPSK", 9);
  }

  return c;
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

#ifdef DTLS_TEST

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

int write_func(struct dtls_context_t *ctx, 
	       struct sockaddr *dst, socklen_t dstlen, int ifindex, 
	       uint8 *buf, int len) {
  int fd = *(int *)dtls_get_app_data(ctx);

  return sendto(fd, buf, len, 0, dst, dstlen);
}

int
dtls_handle_read(struct dtls_context_t *ctx) {
  int fd;
  session_t session;
#define MAX_READ_BUF 2000
  static uint8 buf[MAX_READ_BUF];
  int len;

  fd = *(int *)dtls_get_app_data(ctx);
  
  if (!fd)
    return -1;

  session.rlen = sizeof(session.raddr);
  len = recvfrom(fd, buf, MAX_READ_BUF, 0, 
		 &session.raddr.sa, &session.rlen);
  
  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dsrv_log(LOG_DEBUG, "got %d bytes from port %d\n", len, 
	     ntohs(session.raddr.sin6.sin6_port));
  }

  return dtls_handle_message(ctx, &session, buf, len);
}    

int 
main(int argc, char **argv) {
  dtls_context_t *the_context = NULL;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, result;
  int on = 1;
  struct sockaddr_in6 listen_addr = { AF_INET6, htons(20220), 0, IN6ADDR_ANY_INIT, 0 };

  set_log_level(LOG_DEBUG);

  /* init socket and set it to non-blocking */
  fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

  if (fd < 0) {
    dsrv_log(LOG_ALERT, "socket: %s\n", strerror(errno));
    return 0;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dsrv_log(LOG_ALERT, "setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }
#if 0
  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    dsrv_log(LOG_ALERT, "fcntl: %s\n", strerror(errno));
    goto error;
  }
#endif
  on = 1;
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
    dsrv_log(LOG_ALERT, "setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
  }

  if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
    dsrv_log(LOG_ALERT, "bind: %s\n", strerror(errno));
    goto error;
  }

  the_context = dtls_new_context(&fd);
  dtls_set_cb(the_context, write_func, write);

  while (1) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fd, &rfds);
    /* FD_SET(fd, &wfds); */
    
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    result = select( fd+1, &rfds, &wfds, 0, &timeout);
    
    if (result < 0) {		/* error */
      if (errno != EINTR)
	perror("select");
    } else if (result == 0) {	/* timeout */
    } else {			/* ok */
      if (FD_ISSET(fd, &wfds))
	;
      else if (FD_ISSET(fd, &rfds)) {
	dtls_handle_read(the_context);
      }
    }
  }
  
 error:
  dtls_free_context(the_context);
  exit(0);
}
#endif
