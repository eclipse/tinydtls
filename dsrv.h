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

#ifndef _DSRV_H_
#define _DSRV_H_

#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>

#ifdef WITH_DTLS
#include <openssl/ssl.h>
#endif

#include "uthash.h"	       /* see http://uthash.sourceforge.net */

#include "netq.h"
#include "peer.h"

#define DSRV_READ  0x01
#define DSRV_WRITE 0x02

#define MAX_PENDING      2	/* must be less than MAX_PEERS */
#define MAX_PEERS       10	/* MAX_PENDING of these might be pending  */

typedef struct dsrv_context_t {
  int fd;			/* single file descriptor for read/write */
  struct netq_t *rq, *wq;	/* read queue and write queue */
#ifdef WITH_DTLS
  SSL_CTX *sslctx;
#endif
  
  peer_t *peers;		/* table for peer structures */
  int num_pending;		/* number of pending peers */
  int num_peers;		/* total number of peers */

  int stop;			/* set != 0 to stop engine */

  void (*cb_timeout)(struct dsrv_context_t *);
  void (*cb_read)(struct dsrv_context_t *ctx, 
		  peer_t *peer, char *buf, int len);

} dsrv_context_t;

struct dsrv_context_t *
dsrv_new_context(struct sockaddr *laddr, size_t laddrlen,
		 int rqsize, int wqsize);

/** Returns the global context object. */ 
struct dsrv_context_t *dsrv_get_context();

/** Sets one of the available callbacks timeout, read. */
#define dsrv_set_cb(ctx,cb,CB) do { (ctx)->cb_##CB = cb; } while(0)

/* void dsrv_set_cb_timeout(struct dsrv_context_t *ctx, void (*)()); */
/* void dsrv_set_cb_read(struct dsrv_context_t *ctx, void (*)()); */

/** 
 * Releases the memory allocated for context C. The associated socket
 * must be closed manually. */
void dsrv_free_context(dsrv_context_t *ctx);

/* Closes the socket that is associated with context C. */ 
#define dsrv_close(C) do { close(C->fd); C->fd = -1; } while(0)

/* Retrieves the file descriptor for operation M (currently always ctx->fd). */
#define dsrv_get_fd(C,M) (C)->fd

/* Stops the server's execution loop (see dsrv_run()). */
#define dsrv_stop(C) do { (C)->stop = 1; } while(0)

/**
 * Prepare fd set for read or write (depending on mode and whether or
 * not data is ready to send). Returns fd+1 if set, 0 otherwise.
 */
int dsrv_prepare(dsrv_context_t *ctx, fd_set *fds, int mode);

/** 
 * Returns 1 if fd in fds is ready for the operation specified in
 * mode, 0 otherwise, */
int dsrv_check(dsrv_context_t *ctx, fd_set *fds, int mode);

/** Returns the timeout for the next select() operation. */
long dsrv_get_timeout(dsrv_context_t *ctx);

struct packet_t *dsrv_sendto(dsrv_context_t *ctx, struct sockaddr *raddr, 
			     socklen_t rlen, int ifindex,
			     char *buf, size_t len);

struct packet_t *dsrv_recvfrom(dsrv_context_t *ctx, struct sockaddr *raddr, 
			       socklen_t *rlen, int *ifindex,
			       char *buf, size_t *len);

/** Adds the given peer to the specified context. */
void dsrv_add_peer(struct dsrv_context_t *ctx, peer_t *peer); 

/** Adds the given peer from the specified context. */
void dsrv_delete_peer(struct dsrv_context_t *ctx, peer_t *peer);

/**
 * Returns the peer associated with the specified session or NULL if
 * not found. */
peer_t *dsrv_find_peer(struct dsrv_context_t *ctx, session_t *session);

/** 
 * Makes a hash key from the session object. Note that contents of s
 * will be changed to ensure a normalized version. */
void make_hashkey(session_t *s);

/**
 * Returns 1 if the remote party identified by addr is an acceptable
 * peer, 0 otherwise. By now, "acceptable" means that there are not
 * too many pending requests and the maximum number of sessions is not
 * reached.
 */
int dsrv_peer_allow(struct dsrv_context_t *ctx, 
		    const struct sockaddr *addr, int addrsize);

/** Clears all peer objects and frees any storage they allocate. */
void dsrv_free_peers(struct dsrv_context_t *ctx);

/** Start the event processing loop. */
void dsrv_run(struct dsrv_context_t *ctx);

#endif /* _DSRV_H_ */


