/* dsrv -- utility functions for servers that use datagram sockets
 *
 * Copyright (C) 2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>

#include "dsrv.h"

struct dsrv_context_t *
dsrv_new_context(struct sockaddr *laddr, size_t laddrlen,
		 int rqsize, int wqsize) {
  struct dsrv_context_t *c = NULL;
  int fd, flags, on;

  if (!laddr)
    return NULL;

  /* init socket and set it to non-blocking */
  fd = socket(laddr->sa_family, SOCK_DGRAM, 0);

  if (fd < 0) {
#ifndef NDEBUG
    perror("socket");
#endif
    return NULL;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
#ifndef NDEBUG
    perror("setsockopt SO_REUSEADDR");
#endif
  }

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
#ifndef NDEBUG
    perror("fcntl");
#endif
    goto error;
  }

  switch(laddr->sa_family) {
  case AF_INET6:
    on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#ifndef NDEBUG
      perror("setsockopt IPV6_PKTINFO");
#endif
    }
    break;
  case AF_INET:
    on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on) ) < 0) {
#ifndef NDEBUG
      perror("setsockopt IP_PKTINFO");
#endif
    }
    break;
  default: 
    ;				/* do nothing byy default */
  }

  if (bind(fd, laddr, laddrlen) < 0) {
#ifndef NDEBUG
    perror("bind");
#endif
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
  return c;

 error:
  close(fd);
  dsrv_free_context(c);
  return NULL;
}


int 
dsrv_pushq(struct netq_t *q, struct packet_t *p) {
  return q ? nq_push(q,p) : 0;
}

struct packet_t *
dsrv_popq(struct netq_t *q) {
  return q ? nq_pop(q) : NULL;
}

int
dsrv_prepare(dsrv_context_t *ctx, fd_set *fds, int mode) {
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


