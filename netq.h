/* netq -- definition of a simple network packet queue with fixed length
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

#ifndef _NETQ_H_
#define _NETQ_H_

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

/**
 * Definition of a network packet, containing the remote address, the
 * contents, and a pointer to the next packet in the queue. */
typedef struct packet_t {
  socklen_t rlen;
  struct sockaddr *raddr;
  int ifindex;
  char *buf;
  int len;
  struct packet_t *next;
} packet_t;

#define PACKET_LEN(P) (sizeof(*P) + (P)->rlen + (P)->len)

/** Network queue structure. Internally, this is a linked list of
 * packet_t objects that are stored in packetbuf. As the queue acts as
 * FIFO, we only need pointers to the first and last element,
 * respectively.
 */
typedef struct netq_t {
  size_t bufsize;
  char *packetbuf;
  struct packet_t *pq_first, *pq_last;  
} netq_t;

/* Access functions for first and last element of a network queue. */
#define nq_first(Q) ((Q)->pq_first)
#define nq_last(Q)  ((Q)->pq_last)

/** 
 * Adds the given packet p to the end of the packet queue q. Return
 * value is 1 on success, 0 otherwise. This operation will fail when
 * q's memory buffer does not contain sufficient space to hold the new
 * packet. Note that the packet must be created with nq_new_packet().
 */
int nq_push(struct netq_t *q, struct packet_t *p);

/** 
 * Retrieves the first packet from given queue. Returns a pointer to
 * the packet or NULL when empty. The pointer is valid until the next
 * destructive operation on q (i.e. nq_push() or nq_free()).
 */
struct packet_t *nq_pop(struct netq_t *q);

/** 
 * Creates a new network queue with bufsize bytes fixed packet
 * memory. Return value is a pointer to the new queue. The memory must
 * be released with nq_free() when done. */
struct netq_t *nq_new(int bufsize);

/** Frees the memory that has been allocated with nq_new(). */
#define nq_free(Q) free(Q)

/** Creates a new struct packet_t from the given data and adds it to
 * the packet queue nq. Returns a pointer to the new packet on
 * success, NULL otherwise.  */
struct packet_t *
nq_new_packet(struct netq_t *nq, 
	      struct sockaddr *raddr, 
	      socklen_t rlen,
	      int ifindex,
	      char *buf, size_t len);

/** Returns number of elements in nq. */
int nq_count(struct netq_t *nq);

/** Returns the first element in the packet queue or NULL if empty. */
#define nq_peek(Q) ((Q) ? nq_first(Q) : NULL)

/** Returns non-zero iff nq contains at least at least one element in nq. */
#define nq_pending(Q) (nq_peek(Q) != NULL)

#endif /* _NETQ_H_ */
