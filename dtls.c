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
#include "dtls.h"

#define dtls_int_to_uint16(Field,Value) do {			\
    *(unsigned char*)(Field) = ((Value) >> 8) & 0xff;		\
    *(((unsigned char*)(Field))+1) = ((Value) & 0xff);		\
  } while(0)

#define dtls_int_to_uint24(Field,Value) do {			\
    *(unsigned char*)(Field) = ((Value) >> 16) & 0xff;		\
    dtls_int_to_uint16((((unsigned char*)(Field))+1),Value);	\
  } while(0)

#define dtls_set_version(H,V) dtls_int_to_uint16(&(H)->version, (V))
#define dtls_set_content_type(H,V) ((H)->content_type = (V) & 0xff)
#define dtls_set_length(H,V)  ((H)->length = (V))

#define dtls_uint16_to_int(Field) \
  (((*(unsigned char*)(Field)) << 8) | (*(((unsigned char*)(Field))+1)))

#define dtls_uint24_to_int(Field)		\
  (((*(((unsigned char*)(Field)))) << 16)	\
   | ((*(((unsigned char*)(Field))+1)) << 8)	\
   | ((*(((unsigned char*)(Field))+2))))
  
#define dtls_uint48_to_ulong(Field)		\
  (((*(unsigned char*)(Field)) << 40)		\
   | ((*(((unsigned char*)(Field))+1)) << 32)	\
   | ((*(((unsigned char*)(Field))+2)) << 24)	\
   | ((*(((unsigned char*)(Field))+3)) << 16)	\
   | ((*(((unsigned char*)(Field))+4)) << 8)	\
   | ((*(((unsigned char*)(Field))+5))))

#define dtls_get_content_type(H) ((H)->content_type & 0xff)
#define dtls_get_version(H) dtls_uint16_to_int(&(H)->version)
#define dtls_get_epoch(H) dtls_uint16_to_int(&(H)->epoch)
#define dtls_get_sequence_number(H) dtls_uint48_to_ulong(&(H)->sequence_number)
#define dtls_get_fragment_length(H) dtls_uint24_to_int(&(H)->fragment_length)

#define HASH_FIND_PEER(head,sess,out)		\
  HASH_FIND(hh,head,sess,sizeof(session_t),out)

#define DTLS_RH_LENGTH sizeof(dtls_record_header_t)
#define DTLS_HS_LENGTH sizeof(dtls_handshake_header_t)
#define DTLS_CH_LENGTH sizeof(dtls_client_hello_t) /* no variable length fields! */
#define DTLS_HV_LENGTH sizeof(dtls_hello_verify_t)

#define HS_HDR_LENGTH  DTLS_RH_LENGTH + DTLS_HS_LENGTH
#define HV_HDR_LENGTH  HS_HDR_LENGTH + DTLS_HV_LENGTH

#define HIGH(V) (((V) >> 8) & 0xff)
#define LOW(V)  ((V) & 0xff)

#define RECORD(M) ((dtls_record_header_t *)(M))
#define HANDSHAKE(M) ((dtls_handshake_header_t *)((M) + DTLS_RH_LENGTH))
#define CLIENTHELLO(M) ((dtls_client_hello_t *)((M) + HS_HDR_LENGTH))

int 
dtls_get_cookie(uint8 *hello_msg, int msglen, uint8 **cookie) {
  debug("in dtls_get_cookie\n");

  /* To access the cookie, we have to determine the session id's
   * length and skip the whole thing. */
  if (msglen < DTLS_CH_LENGTH)
    return -1;

  if (dtls_get_version((dtls_client_hello_t *)hello_msg) != DTLS_VERSION)
    return -1;			/* wrong version */

  hello_msg += DTLS_CH_LENGTH 
    + ((dtls_client_hello_t *)hello_msg)->session_id_length;

  *cookie = hello_msg + sizeof(uint8);
  debug("found cookie field (len: %d)\n", *hello_msg & 0xff);
  return *hello_msg & 0xff;
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
  e = sizeof(dtls_client_hello_t) + CLIENTHELLO(msg)->session_id_length;

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

int
dtls_verify_peer(dtls_context_t *ctx, 
		    session_t *session,
		    uint8 *msg, int msglen) {

  int len, clen = DTLS_COOKIE_LENGTH;
  uint8 *cookie;
  int i;
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
  if (msglen < HS_HDR_LENGTH)
    return 0;

  /* Perform rough cookie check. */
  if (RECORD(msg)->content_type == DTLS_CT_HANDSHAKE
      && HANDSHAKE(msg)->msg_type == DTLS_HT_CLIENT_HELLO) {
    
    len = dtls_get_cookie((uint8 *)CLIENTHELLO(msg), 
			  msglen - HS_HDR_LENGTH,
			  &cookie);

    if (len == 0) {		/* no cookie */
      /* FIXME: send Hello Verify request */
      
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
      debug("compare cookies:\n");
      for (i=0; i < clen; i++) 
	printf("%02x", *(char *)(buf + HV_HDR_LENGTH + i) & 0xff);
      printf("\n");
      for (i=0; i < clen; i++) 
	printf("%02x", *(char *)(cookie + i) & 0xff);
      printf("\n");

      if (memcmp(cookie, buf + HV_HDR_LENGTH, clen) == 0)
	return 1;
    }
  }

  /* discard message in any other case */
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

  /* TODO: check if we have DTLS state for raddr/ifindex */
  HASH_FIND_PEER(ctx->peers, session, peer);

  if (!peer) {			

    /* When no DTLS state exists for this peer, we only allow a
       Client Hello message with 
        
       a) a valid cookie, or 
       b) no cookie.

       Anything else will be rejected. Fragementation is not allowed
       here as it would require peer state as well.
    */
    
    if (!dtls_verify_peer(ctx, session, msg, msglen)) {
      debug("cannot verify peer\n");
      return -1;
    }

    /* msg contains a Client Hello with a valid cookie, so we can
       safely create the server state machine and continue with
       the handshake. */

    /* FIXME: create peer status */
    debug("verified peer\n");
  } else {
    debug("found peer\n");
  }

  /* At this point peer contains a state machine to handle the
     received message. */

  /* FIXME: handle message with peer status */

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
handle_read(struct dtls_context_t *ctx) {
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
	handle_read(the_context);
      }
    }
  }
  
 error:
  dtls_free_context(the_context);
  exit(0);
}
#endif
