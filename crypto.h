/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011--2012 Olaf Bergmann <bergmann@tzi.org>
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

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include "config.h"

#include <stdlib.h>		/* for rand() and srand() */

#include "aes/rijndael.h"

#include "prng.h"
#include "global.h"
#include "numeric.h"
#include "hmac.h"
#include "ccm.h"

/* TLS_PSK_WITH_AES_128_CCM_8 */
#define DTLS_MAC_KEY_LENGTH    0
#define DTLS_KEY_LENGTH        16 /* AES-128 */
#define DTLS_BLK_LENGTH        16 /* AES-128 */
#define DTLS_MAC_LENGTH        DTLS_HMAC_DIGEST_SIZE
#define DTLS_IV_LENGTH         4  /* length of nonce_explicit */

/** 
 * Maximum size of the generated keyblock. Note that MAX_KEYBLOCK_LENGTH must 
 * be large enough to hold the pre_master_secret, i.e. twice the length of the 
 * pre-shared key + 1.
 */
#define MAX_KEYBLOCK_LENGTH  \
  (2 * DTLS_MAC_KEY_LENGTH + 2 * DTLS_KEY_LENGTH + 2 * DTLS_IV_LENGTH)

/** Length of DTLS master_secret */
#define DTLS_MASTER_SECRET_LENGTH 48

#ifndef DTLS_CIPHER_CONTEXT_MAX
#define DTLS_CIPHER_CONTEXT_MAX 4
#endif

typedef enum { AES128=0 
} dtls_crypto_alg;

/** Crypto context for TLS_PSK_WITH_AES_128_CCM_8 cipher suite. */
typedef struct {
  rijndael_ctx ctx;		       /**< AES-128 encryption context */
  unsigned char N[DTLS_CCM_BLOCKSIZE]; /**< nonce */
} aes128_ccm_t;

typedef struct dtls_cipher_context_t {
  /** numeric identifier of this cipher suite in host byte order. */
  dtls_cipher_t code;
  aes128_ccm_t data;		/**< The crypto context */
} dtls_cipher_context_t;

typedef enum { DTLS_CLIENT=0, DTLS_SERVER } dtls_peer_type;

typedef struct {
  uint8  client_random[32];	/**< client random gmt and bytes */

  dtls_peer_type role; /**< denotes if the remote peer is DTLS_CLIENT or DTLS_SERVER */
  unsigned char compression;		/**< compression method */

  dtls_cipher_t cipher;		/**< cipher type */

  /** the session's master secret */
  uint8 master_secret[DTLS_MASTER_SECRET_LENGTH];

  /** 
   * The key block generated from PRF applied to client and server
   * random bytes. The actual size is given by the selected cipher and
   * can be calculated using dtls_kb_size(). Use \c dtls_kb_ macros to
   * access the components of the key block.
   */
  uint8 key_block[MAX_KEYBLOCK_LENGTH];

  dtls_cipher_context_t *read_cipher;  /**< decryption context */
  dtls_cipher_context_t *write_cipher; /**< encryption context */
} dtls_security_parameters_t;

/* The following macros provide access to the components of the
 * key_block in the security parameters. */

#define dtls_kb_client_mac_secret(Param) ((Param)->key_block)
#define dtls_kb_server_mac_secret(Param)				\
  (dtls_kb_client_mac_secret(Param) + DTLS_MAC_KEY_LENGTH)
#define dtls_kb_remote_mac_secret(Param)				\
  ((Param)->role == DTLS_CLIENT						\
   ? dtls_kb_client_mac_secret(Param)					\
   : dtls_kb_server_mac_secret(Param))
#define dtls_kb_local_mac_secret(Param)					\
  ((Param)->role == DTLS_SERVER						\
   ? dtls_kb_client_mac_secret(Param)					\
   : dtls_kb_server_mac_secret(Param))
#define dtls_kb_mac_secret_size(Param) DTLS_MAC_KEY_LENGTH
#define dtls_kb_client_write_key(Param)					\
  (dtls_kb_server_mac_secret(Param) + DTLS_MAC_KEY_LENGTH)
#define dtls_kb_server_write_key(Param)					\
  (dtls_kb_client_write_key(Param) + DTLS_KEY_LENGTH)
#define dtls_kb_remote_write_key(Param)				\
  ((Param)->role == DTLS_CLIENT					\
   ? dtls_kb_client_write_key(Param)				\
   : dtls_kb_server_write_key(Param))
#define dtls_kb_local_write_key(Param)				\
  ((Param)->role == DTLS_SERVER					\
   ? dtls_kb_client_write_key(Param)				\
   : dtls_kb_server_write_key(Param))
#define dtls_kb_key_size(Param) DTLS_KEY_LENGTH
#define dtls_kb_client_iv(Param)					\
  (dtls_kb_server_write_key(Param) + DTLS_KEY_LENGTH)
#define dtls_kb_server_iv(Param)					\
  (dtls_kb_client_iv(Param) + DTLS_IV_LENGTH)
#define dtls_kb_remote_iv(Param)				\
  ((Param)->role == DTLS_CLIENT					\
   ? dtls_kb_client_iv(Param)					\
   : dtls_kb_server_iv(Param))
#define dtls_kb_local_iv(Param)					\
  ((Param)->role == DTLS_SERVER					\
   ? dtls_kb_client_iv(Param)					\
   : dtls_kb_server_iv(Param))
#define dtls_kb_iv_size(Param) DTLS_IV_LENGTH

#define dtls_kb_size(Param)					\
  (2 * (dtls_kb_mac_secret_size(Param) +			\
	dtls_kb_key_size(Param) + dtls_kb_iv_size(Param)))

/* just for consistency */
#define dtls_kb_digest_size(Param) DTLS_MAC_LENGTH

/** 
 * Expands the secret and key to a block of DTLS_HMAC_MAX 
 * size according to the algorithm specified in section 5 of
 * RFC 4346.
 *
 * \param h       Identifier of the hash function to use.
 * \param key     The secret.
 * \param keylen  Length of \p key.
 * \param seed    The seed. 
 * \param seedlen Length of \p seed.
 * \param buf     Output buffer where the result is XORed into
 *                The buffe must be capable to hold at least
 *                \p buflen bytes.
 * \return The actual number of bytes written to \p buf or 0
 * on error.
 */
size_t dtls_p_hash(dtls_hashfunc_t h, 
		   const unsigned char *key, size_t keylen,
		   const unsigned char *label, size_t labellen,
		   const unsigned char *random1, size_t random1len,
		   const unsigned char *random2, size_t random2len,
		   unsigned char *buf, size_t buflen);

/**
 * This function implements the TLS PRF for DTLS_VERSION. For version
 * 1.0, the PRF is P_MD5 ^ P_SHA1 while version 1.2 uses
 * P_SHA256. Currently, the actual PRF is selected at compile time.
 */
size_t dtls_prf(const unsigned char *key, size_t keylen,
		const unsigned char *label, size_t labellen,
		const unsigned char *random1, size_t random1len,
		const unsigned char *random2, size_t random2len,
		unsigned char *buf, size_t buflen);

/**
 * Calculates MAC for record + cleartext packet and places the result
 * in \p buf. The given \p hmac_ctx must be initialized with the HMAC
 * function to use and the proper secret. As the DTLS mac calculation
 * requires data from the record header, \p record must point to a
 * buffer of at least \c sizeof(dtls_record_header_t) bytes. Usually,
 * the remaining packet will be encrypted, therefore, the cleartext
 * is passed separately in \p packet.
 * 
 * \param hmac_ctx  The HMAC context to use for MAC calculation.
 * \param record    The record header.
 * \param packet    Cleartext payload to apply the MAC to.
 * \param length    Size of \p packet.
 * \param buf       A result buffer that is large enough to hold
 *                  the generated digest.
 */
void dtls_mac(dtls_hmac_context_t *hmac_ctx, 
	      const unsigned char *record,
	      const unsigned char *packet, size_t length,
	      unsigned char *buf);

/** 
 * Encrypts the specified \p src of given \p length, writing the
 * result to \p buf. The cipher implementation may add more data to
 * the result buffer such as an initialization vector or padding
 * (e.g. for block cipers in CBC mode). The caller therefore must
 * ensure that \p buf provides sufficient storage to hold the result.
 * Usually this means ( 2 + \p length / blocksize ) * blocksize.  The
 * function returns a value less than zero on error or otherwise the
 * number of bytes written.
 *
 * \param ctx    The cipher context to use.
 * \param src    The data to encrypt.
 * \param length The actual size of of \p src.
 * \param buf    The result buffer. \p src and \p buf must not 
 *               overlap.
 * \param aad    additional data for AEAD ciphers
 * \param aad_length actual size of @p aad
 * \return The number of encrypted bytes on success, less than zero
 *         otherwise. 
 */
int dtls_encrypt(dtls_cipher_context_t *ctx, 
		 const unsigned char *src, size_t length,
		 unsigned char *buf,
		 const unsigned char *aad, size_t aad_length);

/** 
 * Decrypts the given buffer \p src of given \p length, writing the
 * result to \p buf. The function returns \c -1 in case of an error,
 * or the number of bytes written. Note that for block ciphers, \p
 * length must be a multiple of the cipher's block size. A return
 * value between \c 0 and the actual length indicates that only \c n-1
 * block have been processed. Unlike dtls_encrypt(), the source
 * and destination of dtls_decrypt() may overlap. 
 * 
 * \param ctx     The cipher context to use.
 * \param src     The buffer to decrypt.
 * \param length  The length of the input buffer. 
 * \param buf     The result buffer.
 * \param aad     additional authentication data for AEAD ciphers
 * \param aad_length actual size of @p aad
 * \return Less than zero on error, the number of decrypted bytes 
 *         otherwise.
 */
int dtls_decrypt(dtls_cipher_context_t *ctx, 
		 const unsigned char *src, size_t length,
		 unsigned char *buf,
		 const unsigned char *a_data, size_t a_data_length);

/* helper functions */

/** 
 * Generates pre_master_sercet from given PSK and fills the result
 * according to the "plain PSK" case in section 2 of RFC 4279.
 * Diffie-Hellman and RSA key exchange are currently not supported.
 *
 * @param key    The shared key.
 * @param keylen Length of @p key in bytes.
 * @param result The derived pre master secret.
 * @return The actual length of @p result.
 */
size_t dtls_pre_master_secret(unsigned char *key, size_t keylen,
			      unsigned char *result);

/**
 * Creates a new dtls_cipher_context_t object for given @c cipher.
 * The storage allocated for this object must be released using 
 * dtls_cipher_free().
 *
 * @param code  Code of the requested cipher (host byte order)
 * @param key     The encryption and decryption key.
 * @param keylen  Actual length of @p key.
 * @return A new dtls_cipher_context_t object or @c NULL in case
 *         something went wrong (e.g. insufficient memory or wrong
 *         key length)
 */
dtls_cipher_context_t *dtls_cipher_new(dtls_cipher_t code,
				       unsigned char *key, size_t keylen);

/** 
 * Releases the storage allocated by dtls_cipher_new() for @p cipher_context 
 */
void dtls_cipher_free(dtls_cipher_context_t *cipher_context);


/** 
 * Initializes the given cipher context @p ctx with the initialization
 * vector @p iv of length @p length. */
void dtls_cipher_set_iv(dtls_cipher_context_t *ctx,
			unsigned char *iv, size_t length);

#endif /* _CRYPTO_H_ */

