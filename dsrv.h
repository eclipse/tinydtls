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

#ifndef _DSRV_H_
#define _DSRV_H_

#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>

#include "netq.h"

#define DSRV_READ  0x01
#define DSRV_WRITE 0x02

typedef struct dsrv_context_t {
  int fd;			/* single file descriptor for read/write */
  struct netq_t *rq, *wq;	/* read queue and write queue */
} dsrv_context_t;

struct dsrv_context_t *
dsrv_new_context(struct sockaddr *laddr, size_t laddrlen,
		 int rqsize, int wqsize);

/** 
 * Releases the memory allocated for context C. The associated socket
 * must be closed manually. */
#define dsrv_free_context(C) do {			\
    if (C) { free((C)->rq); free((C)->wq); free(C); }	\
} while(0)

/* Closes the socket that is associated with context C. */ 
#define dsrv_close(C) close(C->fd)

/* Retrieves the file descriptor for operation M (currently always ctx->fd). */
#define dsrv_get_fd(C,M) (C)->fd

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

#endif /* _DSRV_H_ */


