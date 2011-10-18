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

/** \file
 * \brief Definition of session peer.
 * 
 * Peers are stored in a hash table indexed by the remote transport
 * address and the local interface index. We use UTHash as hash
 * table implementation, see 
 * <a href="http://uthash.sourceforge.net">UThash</a>.
 */
#ifndef _PEER_H_
#define _PEER_H_

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "uthash.h"

#ifndef DSRV_NO_PROTOCOL_DEMUX
/** 
 * Used by demux function to indicate if special treatment is required
 * on incoming or outgoing traffic. */
typedef enum { DISCARD=0, RAW, DTLS } protocol_t;
#endif

typedef enum { 
  PEER_ST_ESTABLISHED, PEER_ST_PENDING, PEER_ST_CLOSED 
 } peer_state_t;

#ifndef session_t
typedef struct {
  socklen_t rlen;		/**< actual length of raddr */
  union {
    struct sockaddr sa;		/**< the generic API structure */
#if 0
    struct sockaddr_storage ss;	/**< internal representation */
#endif
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
  } raddr;			/**< remote address */
  int ifindex;			/**< local interface */
} __session_t;
#define session_t __session_t
#endif

typedef struct {
  peer_state_t state;
  session_t session;
#ifndef DSRV_NO_PROTOCOL_DEMUX
  protocol_t protocol;		/**< what protocol do we talk? */
#endif
  UT_hash_handle hh;	     /**< the hash handle (used internally) */
} peer_t;

/** Returns the current state from given peer. */
#define peer_get_state(P) ((P)->state)

/**
 * Sets the state of peer to state. Some state changes may result in
 * changes of the global context (e.g. when the object's state is
 * changed to PEER_ST_PENDING). */
void peer_set_state(peer_t *peer, peer_state_t state);

/** 
 * Creates a new peer for the session specified by remote address
 * raddr of len raddrlen and the local interface index ifindex. 
 *
 * \param raddr    The remote peer's transport address.
 * \param rlen     The length of \p raddr.
 * \param ifindex  The index of the local interface where the initial
 *                 packet has arrived.
 * \param protocol Whether or not the peer talks DTLS (not available with
 *                 \c DSRV_NO_PROTOCOL_DEMUX).
 * \return The new peer object or \c NULL if creation failed.
 */
peer_t *peer_new(struct sockaddr *raddr, int raddrlen, int ifindex
#ifndef DSRV_NO_PROTOCOL_DEMUX
		 , protocol_t protocol
#endif
		 );

/** Releases any storage occupied by given peer. */
void peer_free(peer_t *peer);

/** Sends len bytes from buf to given peer. */
size_t peer_write(peer_t *peer, char *buf, int len);

#endif /* _PEER_H_ */


