/* dtls -- a very basic DTLS implementation
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

#ifndef _HMAC_H_
#define _HMAC_H_

#define DTLS_HMAC_BLOCKSIZE 64	/**< size of hmac blocks */
#define DTLS_HMAC_MAX       64	/**< max number of bytes in digest */

/**
 * Description of hash function. The context object is carried in \c
 * data, \c init, \c update, and \c finalize reflect the typical
 * multi-stage API of hash operations, see e.g. RFC 1321. */
typedef struct {
  void *data;
  void (*init)(void *);
  void (*update)(void *, const unsigned char *, size_t);
  size_t (*finalize)(unsigned char *, void *);
} dtls_hash_t;

/** List of known hash functions for use in dtls_hmac_init(). */
typedef enum { SHA256=1 } dtls_hashfunc_t;

/**
 * Context for HMAC generation. This object is initialized with
 * dtls_hmac_init() and must be passed to dtls_hmac_update() and
 * dtls_hmac_finalize(). Once, finalized, the component \c H is
 * invalid and must be initialized again with dtls_hmac_init() before
 * the structure can be used again. 
 */
typedef struct {
  unsigned char ipad[DTLS_HMAC_BLOCKSIZE];
  unsigned char opad[DTLS_HMAC_BLOCKSIZE];

  dtls_hash_t *H;
} dtls_hmac_context_t;

/**
 * Initializes the HMAC context \p ctx with the given secret key and
 * the specified hash function. This function returns \c 1 if \c ctx
 * has been set correctly, or \c 0 or \c -1 otherwise. Note that this
 * function allocates new storage for the hash context which is
 * released by dtls_hmac_finalize().
 *
 * \param ctx    The HMAC context to initialize.
 * \param key    The secret key.
 * \param klen   The length of \p key.
 * \param h      The actual hash function to use.
 * \return 1 on success, <= 0 otherwise.
 */
int dtls_hmac_init(dtls_hmac_context_t *ctx,
		   unsigned char *key, size_t klen,
		   dtls_hashfunc_t h);

/**
 * Updates the HMAC context with data from \p input. 
 * 
 * \param ctx    The HMAC context.
 * \param input  The input data.
 * \param ilen   Size of \p input.
 */
void dtls_hmac_update(dtls_hmac_context_t *ctx,
		      const unsigned char *input, size_t ilen);

/** 
 * Completes the HMAC generation and writes the result to the given
 * output parameter \c result. The buffer must be large enough to hold
 * the message digest created by the actual hash function. If in
 * doubt, use \c DTLS_HMAC_MAX. The function returns the number of
 * bytes written to \c result. As this function releases internal
 * storage that was allocated for the hash function, it must be called
 * exactly once whenever dtls_hmac_init() has been called.
 *
 *
 * \param ctx    The HMAC context.
 * \param result Output parameter where the MAC is written to.
 * \return Length of the MAC written to \p result.
 */
int dtls_hmac_finalize(dtls_hmac_context_t *ctx, unsigned char *result);

#endif /* _HMAC_H_ */
