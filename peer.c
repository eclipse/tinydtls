/* dsrv -- utility functions for servers that use datagram sockets
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

#include "debug.h"
#include "dsrv.h"
#include "peer.h"

void 
peer_set_state(peer_t *peer, peer_state_t state) {
  if (!peer || peer->state == state)
    return;

  if (peer->state == PEER_ST_PENDING)
    dsrv_get_context()->num_pending--;
  else if (state == PEER_ST_PENDING)
    dsrv_get_context()->num_pending++;
  
  peer->state = state;
}

void
peer_free(peer_t *peer) {
  if (peer) {
#ifdef WITH_DTLS
    if (peer->ssl) SSL_free(peer->ssl);
    if (peer->nbio) BIO_free(peer->nbio);
#endif
    free(peer);
  }
}

peer_t *
peer_new(struct sockaddr *raddr, int raddrlen, int ifindex) {
  peer_t *peer = (peer_t *)malloc(sizeof(peer_t));
#ifdef WITH_DTLS
  BIO *ibio;
#endif

  if (peer) {

    memset(peer, 0, sizeof(peer_t));

    peer_set_state(peer, PEER_ST_PENDING);
    memcpy(&peer->session.raddr, raddr, raddrlen);
    peer->session.rlen = raddrlen;
    peer->session.ifindex = ifindex;
    make_hashkey(&peer->session);

#ifdef WITH_DTLS
    peer->ssl = SSL_new(dsrv_get_context()->sslctx);
    if (peer->ssl) {

      if ( ! BIO_new_bio_pair(&ibio, 0, &peer->nbio, 0) ) {
	dsrv_log(LOG_ALERT, "cannot create bio pair\n");
	peer_free(peer);
	return NULL;
      }

      SSL_set_bio(peer->ssl, ibio, ibio);
      SSL_set_options(peer->ssl, SSL_OP_COOKIE_EXCHANGE);
	
      SSL_set_accept_state(peer->ssl);

    } else {
      dsrv_log(LOG_ALERT, "cannot create SSL object!\n");
      peer_free(peer);
      return NULL;
    }
#endif
    
  } else {
    info("cannot create peer object!\n");
  }
  
  return peer;
}

size_t
peer_write(peer_t *peer, char *buf, int len) {
#ifdef WITH_DTLS
  return SSL_write(peer->ssl, buf, len);
#else
  if (dsrv_sendto(dsrv_get_context(), 
		  &peer->session.raddr.sa, peer->session.rlen, 
		  peer->session.ifindex, buf, len))
    return len;
  else 
    return -1;
#endif  
}
