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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <assert.h>

#ifndef DSRV_NO_DTLS
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#include "dsrv.h"
#include "debug.h"

#define HASH_FIND_PEER(head,sess,out)		\
  HASH_FIND(hh,head,sess,sizeof(session_t),out)
#define HASH_ADD_PEER(head,sess,add)		\
  HASH_ADD(hh,head,sess,sizeof(session_t),add)
#define HASH_DEL_PEER(head,delptr)		\
  HASH_DELETE(hh,head,delptr)

static struct dsrv_context_t *the_context;

#ifndef NDEBUG
char *
debug_format_addr(struct sockaddr *addr, int addrlen) {
  static char addrbuf[INET6_ADDRSTRLEN+10];
  void *addrptr;
  char *p;

  switch (addr->sa_family) {
  case AF_INET:
    addrptr = &((struct sockaddr_in *)addr)->sin_addr;
    p = addrbuf;
    break;
  case AF_INET6:
    addrptr = &((struct sockaddr_in6 *)addr)->sin6_addr;
    addrbuf[0] = '[';
    p = addrbuf+1;
    break;
  default:
    snprintf(addrbuf, sizeof(addrbuf), "(unknown)");
    return addrbuf;
  }
  
  if (inet_ntop(addr->sa_family, addrptr, p, sizeof(addrbuf)-1)) {
    
    assert(strlen(addrbuf) <= INET6_ADDRSTRLEN+1);
    p += strlen(p);
    if (addr->sa_family == AF_INET6)
      *p++ = ']';

    *p++ = ':';
    
    snprintf(p, p-addrbuf, "%d", 
	     htons(((struct sockaddr_in *)addr)->sin_port));

  } else {
    perror("inet_ntop");
  }

  assert(strlen(addrbuf) <= sizeof(addrbuf));
  return addrbuf;
}
#endif

struct dsrv_context_t *
dsrv_get_context() {
  struct sockaddr_in listen_addr = { AF_INET, 0, { 0 } };

  /* Usually, the context is created manually with dsrv_new_context()
   * but we make it act like a singleton and create a dummy context.
   */

  if (!the_context) 
    dsrv_new_context((struct sockaddr *)&listen_addr, 
			 sizeof(listen_addr), 1500,1500);

  return the_context;
}

#ifndef DSRV_NO_DTLS
peer_t *
peer_find_from_ssl(const SSL *ssl) {
  peer_t *peer, *tmp;
 
  HASH_ITER(hh, dsrv_get_context()->peers, peer, tmp) {
    if (peer->ssl == ssl)
      return peer;
  }

  return NULL;
}

/* Handle state traversal. */
void
info_callback(const SSL *ssl, int where, int ret) {
  peer_t *peer;

  debug("STATE: 0x%x\n", SSL_state(ssl));
  if (where & SSL_CB_LOOP)  /* do not care for intermediary states */
    return;

  peer = peer_find_from_ssl(ssl);
#ifndef NDEBUG
  if (peer) {
    debug("info_callback: found peer %s\n",
	  debug_format_addr(&peer->session.raddr.sa, peer->session.rlen));
  }
#endif

  if (where & SSL_CB_ALERT) {	/* examine alert type */
    switch (*SSL_alert_type_string(ret)) {
    case 'F':
      /* move SSL object from pending to close */
      peer_set_state(peer, PEER_ST_CLOSED);
      break;
    case 'W': 
      if ((ret & 0xff) == SSL_AD_CLOSE_NOTIFY) {
	if (where == SSL_CB_WRITE_ALERT) 
	  debug("sent CLOSE_NOTIFY\n");
	else /* received CN */
	  debug("received CLOSE_NOTIFY\n");
      }
      break;
    default: 			/* handle unknown alert types */
#ifndef NDEBUG
      debug("not handled!\n");
#endif
      ;
    }
  }

  if (where & SSL_CB_HANDSHAKE_DONE) {
    debug("HANDSHAKE_DONE\n");

    /* move SSL object from pending to established */
    peer_set_state(peer, PEER_ST_ESTABLISHED);
  }
}

/* Callback function registered with dtls context to send datagrams. */
int 
dsrv_dtls_write(struct dtls_context_t *dtlsctx, 
		struct sockaddr *dst, socklen_t dstlen, int ifindex, 
		uint8 *buf, int len) {
  struct dsrv_context_t *ctx;

  ctx = (dsrv_context_t *)dtls_get_app_data(dtlsctx);
  assert(ctx);

  return dsrv_sendto(ctx, dst, dstlen, ifindex, (char *)buf, len) ? len : 0;
}
#endif

struct dsrv_context_t *
dsrv_new_context(struct sockaddr *laddr, socklen_t laddrlen,
		 int rqsize, int wqsize) {
  struct dsrv_context_t *c = NULL;
  int fd, flags, on;

  if (!laddr)
    return NULL;

  /* init socket and set it to non-blocking */
  fd = socket(laddr->sa_family, SOCK_DGRAM, 0);

  if (fd < 0) {
    dsrv_log(LOG_ALERT, "socket: %s\n", strerror(errno));
    return NULL;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dsrv_log(LOG_ALERT, "setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    dsrv_log(LOG_ALERT, "fcntl: %s\n", strerror(errno));
    goto error;
  }

  switch(laddr->sa_family) {
  case AF_INET6:
    on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
      dsrv_log(LOG_ALERT, "setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
    }
    break;
  case AF_INET:
    on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on) ) < 0) {
      dsrv_log(LOG_ALERT, "setsockopt IP_PKTINFO: %s\n", strerror(errno));
    }
    break;
  default: 
    ;				/* do nothing byy default */
  }

  if (bind(fd, laddr, laddrlen) < 0) {
    dsrv_log(LOG_ALERT, "bind: %s\n", strerror(errno));
    goto error;
  }

  /* At this point, the socket is initialized, so we can create the
   * context object to pass it around. */

  c = (struct dsrv_context_t *)malloc(sizeof(struct dsrv_context_t));
  if (c) {
    memset(c, 0, sizeof(struct dsrv_context_t));
    c->fd = fd;

    /* queues may be zero if not required */
    if (rqsize) {
      c->rq = nq_new(rqsize);
      if (!c->rq) 
	goto error;
    }

    if (wqsize) {
      c->wq = nq_new(wqsize);
      if (!c->wq) 
	goto error;
    }

  }

#ifndef DSRV_NO_DTLS
  SSL_load_error_strings();
  SSL_library_init();
  c->sslctx = SSL_CTX_new(DTLSv1_server_method());

  if (!c->sslctx) 
    goto error;

  SSL_CTX_set_verify(c->sslctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
  SSL_CTX_set_read_ahead(c->sslctx, 1); /* enable read-ahead */

  SSL_CTX_set_info_callback(c->sslctx, info_callback);

  c->dtlsctx = dtls_new_context(c);
  if (c->dtlsctx) 
    dtls_set_cb(c->dtlsctx, dsrv_dtls_write, write);
#endif

  if (the_context)
    dsrv_free_context(the_context);

  the_context = c;
  return c;

 error:
  close(fd);
  dsrv_free_context(c);
  return NULL;
}

void 
dsrv_free_context(dsrv_context_t *ctx) {
  if (ctx) {
    dsrv_free_peers(ctx);
    free(ctx->rq); 
    free(ctx->wq);
#ifndef DSRV_NO_DTLS
    dtls_free_context(ctx->dtlsctx);
    SSL_CTX_free(ctx->sslctx);
#endif
    dsrv_close(ctx);
    free(ctx); 
  }
}

int 
dsrv_pushq(struct netq_t *q, struct packet_t *p) {
  return q ? nq_push(q,p) : 0;
}

struct packet_t *
dsrv_popq(struct netq_t *q) {
  return q ? nq_pop(q) : NULL;
}

void
peer_check_write(dsrv_context_t *ctx, peer_t *peer) {
#ifndef DSRV_NO_DTLS
  static char buf[1000];
  int len;

  if (BIO_pending(peer->nbio)) {
    len = BIO_read(peer->nbio, buf, sizeof(buf));
    
    if (len < 0) {
      warn("cannot get pending data from BIO (%d)\n", len);
    } else {
      if (!dsrv_sendto(ctx, &peer->session.raddr.sa,
		       peer->session.rlen,
		       peer->session.ifindex,
		       buf, len))
	dsrv_log(LOG_CRIT, "cannot send data\n");
    }
  }
#endif
}

int
dsrv_prepare(dsrv_context_t *ctx, fd_set *fds, int mode) {
  peer_t *peer, *tmp;

  if (mode & DSRV_WRITE) { /* check if any peer has data to write */
    HASH_ITER(hh, ctx->peers, peer, tmp) {
      peer_check_write(ctx, peer);
    }
  }

  if ((mode & DSRV_READ)
      || ((mode & DSRV_WRITE) && ctx->wq && nq_pending(ctx->wq))) {
    FD_SET(ctx->fd, fds);
    return ctx->fd + 1;
  }

  return 0;
}

int
dsrv_check(dsrv_context_t *ctx, fd_set *fds, int mode) {
  /* TODO: flush ssl buffers before DSRV_READ (e.g.) */
  return FD_ISSET(ctx->fd, fds);
}

long 
dsrv_get_timeout(dsrv_context_t *ctx) {
  return 2000;			/* default timeout is two seconds */
}

struct packet_t *
dsrv_add_packet(dsrv_context_t *ctx, struct sockaddr *raddr, socklen_t rlen,
		int ifindex, char *buf, size_t len, int mode) {
  struct netq_t *nq;

  nq = mode & DSRV_WRITE ? ctx->wq : ctx->rq;
  if (nq) {
    return nq_new_packet(nq, raddr, rlen, ifindex, buf, len);
  } else  
    return NULL;
}

struct packet_t *
dsrv_sendto(dsrv_context_t *ctx, struct sockaddr *raddr, socklen_t rlen,
	   int ifindex, char *buf, size_t len) {
  return dsrv_add_packet(ctx, raddr, rlen, ifindex, buf, len, DSRV_WRITE);
}

#ifndef min
#  define min(A,B) ((A) <= (B) ? (A) : (B))
#endif

struct packet_t *
dsrv_recvfrom(dsrv_context_t *ctx, struct sockaddr *raddr, socklen_t *rlen,
	      int *ifindex, char *buf, size_t *blen) {
  struct packet_t *p;
  socklen_t len;

  if (!ctx->rq || !nq_pending(ctx->rq)) 
    return NULL;
  
  p = nq_pop(ctx->rq);
  assert(p);			/* see nq_pending() */

  if (raddr && rlen) {
    len = min(*rlen, p->rlen);
    memcpy(raddr, p->raddr, len);
    *rlen = len;
  } 

  if (ifindex)
    *ifindex = p->ifindex;

  if (buf && blen) {
    len = min(*blen, p->len);
    memcpy(buf, p->buf, len);
    *blen = len;    
  }

  return p;
}

void
make_hashkey(session_t *s) {
#if 1 /* this version is ugly but works */
  session_t s2;
  memset(&s2, 0, sizeof(session_t));
  s2.rlen = s->rlen;

  switch (s->raddr.ss.ss_family) {
  case AF_INET:
    s2.raddr.sin.sin_family = s->raddr.sin.sin_family;
    s2.raddr.sin.sin_port = s->raddr.sin.sin_port;
    s2.raddr.sin.sin_addr = s->raddr.sin.sin_addr;
    break;
  case AF_INET6:
    s2.raddr.sin6.sin6_family = s->raddr.sin6.sin6_family;
    s2.raddr.sin6.sin6_port = s->raddr.sin6.sin6_port;
    s2.raddr.sin6.sin6_addr = s->raddr.sin6.sin6_addr;
    break;
  default:
    return;
  }
  
  memcpy(s, &s2, sizeof(session_t));
#else /* FIXME: debug the v6 case */
  unsigned char *beg, *end;
  beg = end = (unsigned char *)&s->raddr + sizeof(s->raddr);

  switch (s->raddr.ss.ss_family) {
  case AF_INET:
    beg = (unsigned char *)&s->raddr.sin.sin_zero;
    break;
  case AF_INET6:
    s->raddr.sin6.sin6_flowinfo = 0;
    beg = (unsigned char *)&s->raddr.sin6.sin6_scope_id;
    break;
  default:
    ;				/* don't clear anything */
  }

  memset(beg, 0, end - beg);
#endif
}

int 
dsrv_peer_allow(struct dsrv_context_t *ctx, 
		const struct sockaddr *addr, int addrsize) {
  return ctx->num_pending < MAX_PENDING && ctx->num_peers < MAX_PEERS;
}

void
dsrv_add_peer(struct dsrv_context_t *ctx, peer_t *peer) {
  HASH_ADD_PEER(ctx->peers,session,peer);
  ctx->num_peers++;
}

void
dsrv_delete_peer(struct dsrv_context_t *ctx, peer_t *peer) {
  HASH_DEL_PEER(ctx->peers,peer);
  ctx->num_peers--;
}

peer_t *
dsrv_find_peer(struct dsrv_context_t *ctx, session_t *session) {
  peer_t *peer = NULL;
  
  HASH_FIND_PEER(ctx->peers, session, peer);
  return peer;
}

void
dsrv_free_peers(struct dsrv_context_t *ctx) {
  peer_t *peer, *tmp;
  
  HASH_ITER(hh, ctx->peers, peer, tmp) {
    dsrv_delete_peer(ctx, peer);
    peer_free(peer);
  }
}

void dump(char *buf, int len) {
  int i=0;

  while(i<len) {
    printf("%02x ", buf[i] & 0xff);

    ++i;
    if (i % 8 == 0) 
      printf("\n");
  }
  printf("\n");
}

void
handle_read(struct dsrv_context_t *ctx) {
  int len;
  static char buf[2000];
  session_t session;
  peer_t *peer = NULL;
  int fd = dsrv_get_fd(ctx, DSRV_READ);
#ifndef DSRV_NO_DTLS  
  int wlen, err, res;
#endif
#ifndef DSRV_NO_PROTOCOL_DEMUX
  protocol_t protocol;
#endif

  session.rlen = sizeof(struct sockaddr_storage);
  len = recvfrom(fd, buf, sizeof(buf), 0, 
		 &session.raddr.sa, &session.rlen);

  if (len < 0) {
    warn("recvfrom: %s\n", strerror(errno));
  } else {
#ifndef NDEBUG
    debug("read %d bytes from %s\n",len,
	  debug_format_addr(&session.raddr.sa, session.rlen));
#endif
    
    session.ifindex = 0;
    make_hashkey(&session);

    /* check if we know this peer */
    peer = dsrv_find_peer(ctx, &session);
    if (peer) {
#ifndef NDEBUG
      debug("found peer %s\n",
	    debug_format_addr(&session.raddr.sa, session.rlen));
#endif
    } else {			/* its a new peer */

      if (!dsrv_peer_allow(ctx, &session.raddr.sa, session.rlen)) {
	warn("new peer not allowed\n");
	return;
      }
#ifndef DSRV_NO_PROTOCOL_DEMUX
      if (ctx->cb_demux) {
	protocol = ctx->cb_demux(&session.raddr.sa, session.rlen, 
				 session.ifindex, buf, len);

	if (protocol == DISCARD) {
	  debug("DISCARD packet from %s\n", 
		debug_format_addr(&session.raddr.sa, session.rlen));
	  return;
	}
      } else {
#ifndef DSRV_NO_DTLS
	protocol = DTLS;
#else
	protocol = RAW;
#endif
      }
#endif

#ifndef DSRV_NO_DTLS
#ifndef DSRV_NO_PROTOCOL_DEMUX
      if (protocol == DTLS) {
#endif
	if (dtls_verify_peer(ctx->dtlsctx, &session, 
			     (uint8 *)buf, len) <= 0) {
	  fprintf(stderr,"peer not verified\n");
	  return;
	} else {
	  fprintf(stderr,"verify peer succeeded, update SSL status\n");
	}
#ifndef DSRV_NO_PROTOCOL_DEMUX
      }
#endif
#endif /* DSRV_NO_DTLS */

      peer = peer_new(&session.raddr.sa, session.rlen, session.ifindex
#ifndef DSRV_NO_PROTOCOL_DEMUX
		      , protocol
#endif
		      );

      if (peer) {
#ifndef NDEBUG
	debug("add new peer %s\n",
	      debug_format_addr(&session.raddr.sa, session.rlen));
#endif
	dsrv_add_peer(ctx, peer);
      }
    }
  }

#ifndef DSRV_NO_DTLS
#ifndef DSRV_NO_PROTOCOL_DEMUX
  if (peer->protocol == DTLS) {
#endif /* DSRV_NO_PROTOCOL_DEMUX */
    /* Handle data only if nothing is pending. */      
  
    if (BIO_flush(peer->nbio) != 1) {
      warn("flush failed, dropping data (%d)\n", BIO_should_retry(peer->nbio));
      return;
    }
    
    wlen = BIO_write(peer->nbio, buf, len);
    if (wlen < 0) {
      err = SSL_get_error(peer->ssl,wlen);	
      dsrv_log(LOG_CRIT, "BIO_write: %d: %s\n", err,
	       ERR_error_string(err, NULL));
      return;
    } 
    
    /* res = SSL_read(peer->ssl, dbuf, sizeof(dbuf)); */
    res = SSL_read(peer->ssl, buf, sizeof(buf));
    if (res < 0) {
      err = SSL_get_error(peer->ssl,res);    
      
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
	dsrv_log(LOG_CRIT,"E: SSL_read: %d %s\n", 
		 err, ERR_error_string(err, NULL));
      
      return;
    } else if (res == 0) {	/* connection might have been closed */
      if (SSL_get_shutdown(peer->ssl)) 
	peer_set_state(peer, PEER_ST_CLOSED);
    } 
    
    len = res;
#ifndef DSRV_NO_PROTOCOL_DEMUX
  }
#endif /* DSRV_NO_PROTOCOL_DEMUX */
#endif /* DSRV_NO_DTLS */

  /* invoke user callback if set */
  if (ctx->cb_read)
    ctx->cb_read(ctx,peer, buf, len);	
}

/** Sends pending data from output queue to network. */
int
handle_write(struct dsrv_context_t *ctx) {
  struct packet_t *p;
  int fd = dsrv_get_fd(ctx, DSRV_WRITE);
  int len;

  p = ctx->wq ? nq_peek(ctx->wq) : NULL;

  if (!p)
    return -1;

  len = sendto(fd, p->buf, p->len, 0, p->raddr, p->rlen);
  
  if (len < 0) {
    warn("sendto: %s", strerror(errno));
#ifndef NDEBUG
    debug("%s\n", debug_format_addr(p->raddr, p->rlen));
#endif
  }
  else {
#ifndef NDEBUG
    debug("sent %d bytes from send queue to %s\n", len, 
	  debug_format_addr(p->raddr, p->rlen));
#endif
    nq_pop(ctx->wq);
  }

  return len;
}

int 
handle_timeout(struct dsrv_context_t *ctx) {
#ifndef DSRV_NO_DTLS
  peer_t *peer, *tmp;
  int result, err;
#endif

  if (ctx->cb_timeout) 
    ctx->cb_timeout(ctx);

#ifndef DSRV_NO_DTLS
  HASH_ITER(hh, ctx->peers, peer, tmp) {
#ifndef DSRV_NO_PROTOCOL_DEMUX
    if (peer->protocol == DTLS) {
#endif /* DSRV_NO_PROTOCOL_DEMUX */
      result = DTLSv1_handle_timeout(peer->ssl);
      if (result < 0) {
	err = SSL_get_error(peer->ssl,result);
	info("dtls1_handle_timeout (%d): %s\n",
	     err, ERR_error_string(err, NULL));
      }
      
      if (peer_get_state(peer) == PEER_ST_CLOSED) {
	dsrv_delete_peer(ctx, peer);
	peer_free(peer);
      }
#ifndef DSRV_NO_PROTOCOL_DEMUX
    }
#endif /* DSRV_NO_PROTOCOL_DEMUX */
  }
#endif /* DSRV_NO_DTLS */
  return 0;
}

void
dsrv_run(struct dsrv_context_t *ctx) {
  fd_set rfds, wfds;
  struct timeval timeout;
  int result;

  if (!ctx)
    return;
  
  while (!ctx->stop) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    dsrv_prepare(ctx, &rfds, DSRV_READ);
    dsrv_prepare(ctx, &wfds, DSRV_WRITE);
    
    timeout.tv_sec = 0;
    timeout.tv_usec = dsrv_get_timeout(ctx);
    
    result = select( FD_SETSIZE, &rfds, &wfds, 0, &timeout);
    
    if (result < 0) {		/* error */
      if (errno != EINTR)
	warn("select: %s\n", strerror(errno));
    } else if (result == 0) {	/* timeout */
      handle_timeout(ctx);
    } else {			/* ok */
      if (dsrv_check(ctx, &wfds, DSRV_WRITE))
	handle_write(ctx);
      else if (dsrv_check(ctx, &rfds, DSRV_READ))
	handle_read(ctx);
    }
  }
  
}
