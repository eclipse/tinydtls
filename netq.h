/* netq.h -- Simple packet queue
 *
 * Copyright (C) 2010--2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the library tinyDTLS. Please see the file
 * LICENSE for terms of use.
 */

#ifndef _NETQ_H_
#define _NETQ_H_

#include "config.h"
#include "global.h"
#include "dtls.h"
#include "time.h"

/**
 * \defgroup netq Network Packet Queue
 * The netq utility functions implement an ordered queue of data packets
 * to send over the network and can also be used to queue received packets
 * from the network.
 * @{
 */

#ifndef NETQ_MAXCNT
#define NETQ_MAXCNT 4 /**< maximum number of elements in netq structure */
#endif

/** 
 * Datagrams in the netq_t structure have a fixed maximum size of
 * DTLS_MAX_BUF to simplify memory management on constrained nodes. */ 
typedef unsigned char netq_packet_t[DTLS_MAX_BUF];

typedef struct netq_t {
  struct netq_t *next;

  clock_time_t t;	        /**< when to send PDU for the next time */
  unsigned char retransmit_cnt;	/**< retransmission counter, will be removed when zero */
  unsigned int timeout;		/**< randomized timeout value */

  dtls_peer_t *peer;		/**< remote address */

  size_t length;		/**< actual length of data */
  netq_packet_t data;		/**< the datagram to send */
} netq_t;

/** 
 * Adds a node to the given queue, ordered by their time-stamp t.
 * This function returns @c 0 on error, or non-zero if @p node has
 * been added successfully.
 *
 * @param queue A pointer to the queue head where @p node will be added.
 * @param node  The new item to add.
 * @return @c 0 on error, or non-zero if the new item was added.
 */
int netq_insert_node(netq_t **queue, netq_t *node);

/** Destroys specified node and releases any memory that was allocated
 * for the associated datagram. */
void netq_node_free(netq_t *node);

/** Removes all items from given queue and frees the allocated storage */
void netq_delete_all(netq_t *queue);

/** Creates a new node suitable for adding to a netq_t queue. */
netq_t *netq_node_new();

/**
 * Returns a pointer to the first item in given queue or NULL if
 * empty. 
 */
netq_t *netq_head(netq_t **queue);

/**
 * Removes the first item in given queue and returns a pointer to the
 * removed element. If queue is empty when netq_pop_first() is called,
 * this function returns NULL.
 */
netq_t *netq_pop_first(netq_t **queue);

/**@}*/

#endif /* _NETQ_H_ */
