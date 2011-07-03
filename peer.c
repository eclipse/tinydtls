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
    free(peer);
  }
}

peer_t *
peer_new(struct sockaddr *raddr, int raddrlen, int ifindex
#ifndef DSRV_NO_PROTOCOL_DEMUX
	 , protocol_t protocol
#endif
	 ) {
  peer_t *peer = (peer_t *)malloc(sizeof(peer_t));

  if (peer) {

    memset(peer, 0, sizeof(peer_t));

    peer_set_state(peer, PEER_ST_PENDING);
    memcpy(&peer->session.raddr, raddr, raddrlen);
    peer->session.rlen = raddrlen;
    peer->session.ifindex = ifindex;
    make_hashkey(&peer->session);

#ifndef DSRV_NO_PROTOCOL_DEMUX
    peer->protocol = protocol;
#endif

#ifndef DSRV_NO_DTLS
#ifndef DSRV_NO_PROTOCOL_DEMUX
    if (protocol == DTLS) {
#endif /* DSRV_NO_PROTOCOL_DEMUX */
#ifndef DSRV_NO_PROTOCOL_DEMUX
    }
#endif /* DSRV_NO_PROTOCOL_DEMUX */
#endif /* DSRV_NO_DTLS */
    
  } else {
    info("cannot create peer object!\n");
  }
  
  return peer;
}

size_t
peer_write(peer_t *peer, char *buf, int len) {
  /* The following ifdef-garbage means: If we have DTLS support and
   * allow protocol multiplexing (i.e. usually intermixing
   * clear/crypto and possibly STUN), then we have to check if the
   * peer speaks DTLS. If we only have DTLS, we always send
   * crypted. Otherwise, if we have no DTLS or if the multiplexed
   * protocol isn't DTLS, we send in clear.
   */

#ifndef DSRV_NO_DTLS
#  ifndef DSRV_NO_PROTOCOL_DEMUX
  if (peer->protocol == DTLS)
#  endif /* DSRV_NO_PROTOCOL_DEMUX */
  ;
#endif /* DSRV_NO_DTLS */

#if defined(DSRV_NO_DTLS) || !defined(DSRV_NO_PROTOCOL_DEMUX)
  if (dsrv_sendto(dsrv_get_context(), 
		  &peer->session.raddr.sa, peer->session.rlen, 
		  peer->session.ifindex, buf, len))
    return len;
  else 
    return -1;
#endif  /* defined(DSRV_NO_DTLS) || !defined(DSRV_NO_PROTOCOL_DEMUX) */
}
