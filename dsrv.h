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

/**
 * \mainpage tinydtls -- a basic DTLS server template.
 * \author Olaf Bergmann, TZI Uni Bremen
 * 
 * This library provides a very simple datagram server with DTLS support.
 * It is designed to support session multiplexing in single-threaded 
 * applications and thus targets specifically on embedded systems.
 *
 * A previous release of this library was based on <a
 * href="http://www.openssl.org/">OpenSSL</a> to show issues with 
 * the Datagram BIO which is not suited very well for
 * DTLS as it reads too much data from the UDP socket once the initial
 * handshake is done (c.f.  <a
 * href="http://www.net-snmp.org/wiki/index.php/DTLS_Implementation_Notes">Net-SNMP
 * Wiki</a>).
 *
 * Additional literature: 
 * \li Nagendra Modadugu and Eric Rescorla: <em>The Design and Implementation of Datagram TLS</em>. In: Proc. NDSS, 2004. 
 * \li Eric Rescorla: <em>An Introduction to OpenSSL Programming, Part I of II</em>. Linux Journal, <a href="http://www.linuxjournal.com/article/4822">Article 4822 from 1 Sep 2001</a>.
 * \li Eric Rescorla: <em>An Introduction to OpenSSL Programming, Part II of II</em>. Linux Journal, <a href="http://www.linuxjournal.com/article/5487">Article 5487 from 9 Oct 2001</a>.
 * 
 * \section License
 * 
 * This software is under the <a
 * href="http://www.opensource.org/licenses/mit-license.php">MIT
 * License</a>. 
 *
 * \subsection uthash UTHash 
 * 
 * This library uses <a
 * href="http://uthash.sourceforge.net/">uthash</a> to manage its
 * peers. \b uthash uses the <b>BSD revised license</b>, see <a
 * href="http://uthash.sourceforge.net/license.html">http://uthash.sourceforge.net/license.html</a>. 
 * 
 * \subsection md5 L. Peter Deutsch's MD5 Implementation
 * 
 * The BSD-licensed MD5 implementation from Peter Deutsch claims to 
 * be free from any RSA IPR. You can find this implementation at
 * <a href="http://libmd5-rfc.sourceforge.net/"
 * >http://libmd5-rfc.sourceforge.net/</a>.
 * 
 * \subsection sha2 Aaron D. Gifford's SHA256 and SHA1 Implementations
 * 
 * This library also provides HMAC-SHA256 and HMAC-SHA1 with <a
 * href="http://www.opensource.org/licenses/bsd-license">BSD-licensed</a>
 * code from Aaron D. Gifford, see <a
 * href="http://www.aarongifford.com/">www.aarongifford.com</a>. 
 * 
 * \subsection aes Rijndael Implementation From OpenBSD 
 * 
 * The AES implementation is taken from rijndael.{c,h} contained in
 * the crypto sub-system of the OpenBSD operating system. It is 
 * copyright by Vincent Rijmen, Antoon Bosselaers and Paulo Barreto.
 * See 
 * <a href="http://www.openbsd.org/cgi-bin/cvsweb/src/sys/crypto/rijndael.c"
 * >rijndael.c</a> for <b>License info</b>.
 * 
 * \section develop Getting the Files
 *
 * You can get the sources either from the 
 * <a href="http://sourceforge.net/projects/tinydtls/files">downloads</a> 
 * section or through \c git from the 
 * <a href="http://sourceforge.net/projects/tinydtls/develop">project develop page</a>.
 * 
 * \section Configuration
 * 
 * Use \c configure to set up everything for a successful build. In addition
 * to the well-known GNU configure options, there are some specific switches
 * that affect what is included in the build:
 * 
 * \li \c --with-protocol-demux Add code for demuxing protocols, usually for
 *                      serving DTLS-crypted and clear-text requests over
 *                      the same UDP socket. (Enabled by default.)
 * \li \c --without-debug Switch off debug outputs used for development.
 * \li \c --with-dtls12 Build for DTLS 1.2. Note that this switches off support for DTLS 1.1. 
 * \li \c --without-md5 Disables use of MD5 (MD5 is required for DTLS 1.1).
 * \li \c --without-sha1 Disables use of SHA1 (SHA1 is required for DTLS 1.1).
 * \li \c --without-sha256 Disables use of SHA256 (SHA256 is required for DTLS 1.2).
 * 
 * \section Building
 * 
 * After configuring the software, just type
 * 
 * \code
 * make
 * \endcode
 * 
 * optionally followed by 
 * \code
 * make install
 * \endcode
 * 
 * \section Usage
 * 
 * An example how to use the bare DTLS code is contained in
 * @c tests/dtls-server.c. It starts a simple server that accepts
 * "connections" from remote peers and echos any data that it
 * receives, A simple client is also included in 
 * @c tests/dtls-client.c to show the client part.
 * Please refer to @ref dtls_susage for more information.
 *
 * \subsection testing Use OpenSSL for Testing
 * 
 * You can connect to the example echo server using <tt>openssl s_client</tt>:
 * \code
 * openssl s_client -dtls1 -servername $HOST -port $PORT  -cipher $CIPHER -psk $PSK
 * \endcode
 * 
 * \section join Get Involved
 *
 * To join this project, please contact the project administrators of this project, 
 * as shown on the 
 * <a href="http://sourceforge.net/projects/tinydtls/">project summary page</a>. 
 */

#ifndef _DSRV_H_
#define _DSRV_H_

#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>

#ifndef DSRV_NO_DTLS
#include "dtls.h"
#endif

#include "uthash.h"    

#include "netq.h"
#include "peer.h"

#define DSRV_READ  0x01	/**< Used in dsrv_get_fd() and dsrv_prepare(). */
#define DSRV_WRITE 0x02	/**< Used in dsrv_get_fd() and dsrv_prepare(). */

#ifndef MAX_PENDING
#define MAX_PENDING      20	/**< must be less than MAX_PEERS */
#endif

#ifndef MAX_PEERS
#define MAX_PEERS       100	/**< MAX_PENDING of these might be pending  */
#endif

#if MAX_PEERS < MAX_PENDING
#error "MAX_PEERS must not be less than MAX_PENDING"
#endif

typedef struct dsrv_context_t {
  int fd;			/**< single file descriptor for read/write */
  struct netq_t *rq, *wq;	/**< read queue and write queue */
#ifndef DSRV_NO_DTLS
  dtls_context_t *dtlsctx;	/**< the main context for DTLS operation */
#endif
  
  peer_t *peers;		/**< table for peer structures */
  int num_pending;		/**< number of pending peers */
  int num_peers;		/**< total number of peers */

  int stop;			/**< set != 0 to stop engine */

  void (*cb_timeout)(struct dsrv_context_t *);
  void (*cb_read)(struct dsrv_context_t *ctx, 
		  peer_t *peer, char *buf, int len);
#ifndef DSRV_NO_PROTOCOL_DEMUX
  protocol_t (*cb_demux)(struct sockaddr *raddr, socklen_t rlen,
			 int ifindex, char *buf, int len);
#endif
} dsrv_context_t;

/** 
 * Creates a new context object to manage the state of a datagram
 * server. This function allocates new storage for the dsrv_context_t
 * object that must be released with dsrv_free_context() when finished.
 * \param laddr     The local interface to listen on. This can be an
 *                  IPv4 or IPv6 address.
 * \param laddrlen  The actual length of the address object passed in
 *                  \p laddr.
 * \param rqsize    Size of the receive queue in bytes.
 * \param wqsize    Size of the send queue in bytes.
 * \return          A new dsrv_context_t object or \c NULL in case of
 *                  an error (e.g. when bind() to the local interface
 *                  failed). 
 *
 * \bug Some functions need the global server context but passing the
 * object as a parameter is not possible. As a workaround,
 * dsrv_new_context() creates a global variable \c the_context that
 * holds the latest instance of the server context (subsequent calls
 * to dsrv_new_context() will invalidate the previous object and
 * release its storage).
 */
struct dsrv_context_t *
dsrv_new_context(struct sockaddr *laddr, socklen_t laddrlen,
		 int rqsize, int wqsize);

/** Returns the global context object. */ 
struct dsrv_context_t *dsrv_get_context();

/** Sets one of the available callbacks timeout, read. */
#define dsrv_set_cb(ctx,cb,CB) do { (ctx)->cb_##CB = cb; } while(0)

/** 
 * Releases the memory allocated for context \c C and the 
 * registered peers. The associated socket will be closed. */
void dsrv_free_context(dsrv_context_t *ctx);

/** Closes the socket that is associated with context C. */ 
#define dsrv_close(C) do { close(C->fd); C->fd = -1; } while(0)

/** Retrieves the file descriptor for operation M (currently always
 *  ctx->fd). */
#define dsrv_get_fd(C,M) (C)->fd

/** Stops the server's execution loop (see dsrv_run()). */
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

/** 
 * Creates a new packet_t structure from the given parameters and adds
 * it to the server's send queue. The data will be copied to the send
 * queue. This function returns a pointer to the new packet_t object 
 * on success, \c NULL otherwise. The storage allocated for the new
 * packet is handled by the server object and must not be released by
 * the caller.
 *
 * \param ctx     The global server context.
 * \param raddr   The remote address.
 * \param rlen    The actual size of \p raddr.
 * \param ifindex The local interface to send the packet from.
 * \param buf     The payload data.
 * \param len     Length of \p buf. 
 * \return A pointer to the new packet on success, \c NULL otherwise.
 */
struct packet_t *dsrv_sendto(dsrv_context_t *ctx, struct sockaddr *raddr, 
			     socklen_t rlen, int ifindex,
			     char *buf, size_t len);

/** 
 * Gets the next packet from the internal receive queue. Packets are
 * appended to the receive queue in the order they have arrived. With
 * this function, applications can pull them off the queue, getting
 * the address information from the packets as well. This function
 * sets the variable parameters specified by the caller and returns a
 * pointer to the packet or \c NULL if the queue was empty. In that
 * case, the variable parameters' value is undefined. Note that the
 * object pointed to by the return value is valid only until the next
 * operation that writes to the receive queue.
 *
 * \param ctx      The global server context.
 * \param raddr    A variable that provides sufficient storage to 
 *                 hold the remote peer's address. May be set to 
 *                 \c NULL to suppress setting the address.
 * \param rlen     Must be initialized to the maximum storage that
 *                 is available for \p raddr. On return, the value
 *                 is set to the actual size of \p raddr.
 * \param ifindex  If set, the value will be updated to contain the
 *                 local interface where the packet was received.
 * \param buf      If set, the received payload data will be copied
 *                 to the given data buffer. At maximum \p *len bytes
 *                 will be copied.
 * \param len      Must be initialized to the maximum size of \p buf
 *                 or \c NULL when the payload data should not be 
 *                 copied. If set, the value pointed to by \p len will
 *                 be set to the actual number of bytes received.
 * \return         The first packet in the receive queue or \c NULL 
 *                 when there is no outstanding packet.
 */
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
 * Returns \c 1 if the remote party identified by \p addr is an
 * acceptable peer, \c 0 otherwise. By now, "acceptable" means that
 * there are not too many pending requests and the maximum number of
 * sessions is not reached.
 * \param ctx      The global dsrv context.
 * \param addr     The remote party's address.
 * \param addrsize Actual size of \p addr.
 * \return 1 if allowed, 0 otherwise.
 */
int dsrv_peer_allow(struct dsrv_context_t *ctx, 
		    const struct sockaddr *addr, int addrsize);

/** Clears all peer objects and frees any storage they allocate. */
void dsrv_free_peers(struct dsrv_context_t *ctx);

/** Start the event processing loop. */
void dsrv_run(struct dsrv_context_t *ctx);

#endif /* _DSRV_H_ */


