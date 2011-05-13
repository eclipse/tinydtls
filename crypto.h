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

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdlib.h>		/* for rand() and srand() */

#include "global.h"
#include "numeric.h"
#include "hmac.h"

/** Maximum size of the generated keyblock. */
#define MAX_KEYBLOCK_LENGTH       108    /* TLS_PSK_AES128_CBC_SHA */

/** Length of DTLS master_secret */
#define DTLS_MASTER_SECRET_LENGTH 48

/* Argh! */
#define AES_BLKLEN 16

typedef enum { AES128=0 
} dtls_crypto_alg;

typedef struct {
  void *data;			/**< The crypto context */
  
  void (*init)(void *, unsigned char *, size_t);
  size_t (*encrypt)(void *, const unsigned char *, size_t, unsigned char *);
  size_t (*decrypt)(void *, unsigned char *, size_t);
} dtls_cipher_context_t;

/** Definition of cipher parameters. */
typedef struct {
  uint16 code;
  unsigned char blk_length;	/**< encryption block length */
  unsigned char key_length;	/**< encryption key length */
  unsigned char mac_algorithm;	/**< MAC algorithm */
  unsigned char mac_length;	/**< digest length */
  unsigned char mac_key_length; /**< length of MAC key */
  unsigned char iv_length;	/**< length of initialization vector */
} dtls_cipher_t;

/** The list of actual supported ciphers, excluding the NULL cipher. */
extern const dtls_cipher_t ciphers[];

typedef struct {
  uint8  client_random[32];	/**< client random gmt and bytes */
  uint8  server_random[32];	/**< server random gmt and bytes */

  int cipher;			/**< cipher type index */
  uint8  compression;		/**< compression method */

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
  (dtls_kb_client_mac_secret(Param) + ciphers[(Param)->cipher].mac_key_length)
#define dtls_kb_mac_secret_size(Param) \
  (ciphers[(Param)->cipher].mac_key_length)
#define dtls_kb_client_write_key(Param)					\
  (dtls_kb_server_mac_secret(Param) + ciphers[(Param)->cipher].mac_key_length)
#define dtls_kb_server_write_key(Param)					\
  (dtls_kb_client_write_key(Param) + ciphers[(Param)->cipher].key_length)
#define dtls_kb_key_size(Param) (ciphers[(Param)->cipher].key_length)
#define dtls_kb_client_iv(Param)					\
  (dtls_kb_server_write_key(Param) + ciphers[(Param)->cipher].key_length)
#define dtls_kb_server_iv(Param)					\
  (dtls_kb_client_iv(Param) + ciphers[(Param)->cipher].iv_length)
#define dtls_kb_iv_size(Param) (ciphers[(Param)->cipher].iv_length)

#define dtls_kb_size(Param)					\
  (2 * (dtls_kb_mac_secret_size(Param) +			\
	dtls_kb_key_size(Param) + dtls_kb_iv_size(Param)))

/* just for consistency */
#define dtls_kb_mac_algorithm(Param)		\
  (ciphers[(Param)->cipher].mac_algorithm)
#define dtls_kb_digest_size(Param)		\
  (ciphers[(Param)->cipher].mac_length)

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
		   unsigned char *key, size_t keylen,
		   unsigned char *label, size_t labellen,
		   unsigned char *random1, size_t random1len,
		   unsigned char *random2, size_t random2len,
		   unsigned char *buf, size_t buflen);

/**
 * This function implements the TLS PRF for DTLS_VERSION. For version
 * 1.0, the PRF is P_MD5 ^ P_SHA1 while version 1.2 uses
 * P_SHA256. Currently, the actual PRF is selected at compile time.
 */
size_t dtls_prf(unsigned char *key, size_t keylen,
		unsigned char *label, size_t labellen,
		unsigned char *random1, size_t random1len,
		unsigned char *random2, size_t random2len,
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
	      unsigned char *record,
	      unsigned char *packet, size_t length,
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
 * \param buf    The result buffer.
 * \return The number of encrypted bytes on success, less than zero
 *         otherwise. 
 */
static inline int
dtls_encrypt(dtls_cipher_context_t *ctx, 
	     const unsigned char *src, size_t length,
	     unsigned char *buf) {
  return ctx ?  ctx->encrypt(ctx->data, src, length, buf) : -1; 
}

/** 
 * Decrypts the given buffer \p buf with a maximum length of \p length
 * bytes, writing the result back into \p buf. The function returns
 * \c -1 in case of an error, or the number of bytes written. Note that
 * for block ciphers, \p length must be a multiple of the cipher's 
 * block size. A return value between \c 0 and the actual length 
 * indicates that only \c n-1 block have been processed. 
 * 
 * \param ctx     The cipher context to use.
 * \param buf     The buffer to decrypt.
 * \param length  The length of the input buffer. This value must not
 *                exceed \c INT_MAX.
 * \return Less than zero on error, the number of decrypted bytes 
 *         otherwise.
 */
static inline int
dtls_decrypt(dtls_cipher_context_t *ctx, unsigned char *buf, size_t length) {
  return ctx ?  ctx->decrypt(ctx->data, buf, length) : -1; 
}

/**
 * Verifies the message given in \p record according to the security
 * parameters in \p sec. As the record's payload usually is encrypted,
 * a pointer to the corresponding cleartext of length \p
 * cleartext_length must be passed in \p cleartext. This function
 * returns \c 1 on success, \c 0 otherwise.
 *
 * \param sec     The security parameters to apply.
 * \param record  Pointer to the record header of the original message.
 * \param record_length Original message length.
 * \param cleartext Pointer to the decrypted payload data.
 * \param cleartext_length Size of \p cleartext.
 * \return \c 1 if MAC and padding are valid, \c 0 otherwise.
 */
int dtls_verify(dtls_security_parameters_t *sec,
		unsigned char *record, size_t record_length,
		unsigned char *cleartext, size_t cleartext_length);

/* helper functions */

/** 
 * Generates pre_master_secret from given PSK and fills the result
 * according to the "plain PSK" case in section 2 of RFC 4279.
 * Diffie-Hellman and RSA key exchange are currently not supported.
 *
 * \param key    The shared key.
 * \param keylen Length of \p key in bytes.
 * \param result The derived pre master secret.
 * \return The actual length of \p result.
 */
static inline size_t
dtls_pre_master_secret(unsigned char *key, size_t keylen,
		  unsigned char *result) {
  unsigned char *p = result;

  dtls_int_to_uint16(p, keylen);
  p += sizeof(uint16);

  memset(p, 0, keylen);
  p += keylen;

  memcpy(p, result, sizeof(uint16));
  p += sizeof(uint16);
  
  memcpy(p, key, keylen);

  return (sizeof(uint16) + keylen) << 1;
}

/**
 * Creates a new dtls_cipher_context_t object for given \c cipher.
 * The storage allocated for this object must be released manually
 * using free().
 *
 * \param cipher  Static description of the requested cipher.
 * \param key     The encryption and decryption key.
 * \param keylen  Actual length of \p key.
 * \return A new dtls_cipher_context_t object or \c NULL in case
 *         something went wrong (e.g. insufficient memory or wrong
 *         key length)/
 */
dtls_cipher_context_t *dtls_new_cipher(const dtls_cipher_t *cipher,
				       unsigned char *key, size_t keylen);

/** 
 * Initializes the give cipher context \p ctx with the initialization
 * vector \p iv of length \p length. */
void dtls_init_cipher(dtls_cipher_context_t *ctx,
		      unsigned char *iv, size_t length);

/* helper functions */

/**
 * Fills \p buf with \p len random bytes. This is the default
 * implementation for prng().  You might want to change prng() to use
 * a better PRNG on your specific platform.
 */
static inline int
prng_impl(unsigned char *buf, size_t len) {
  while (len--)
    *buf++ = rand() & 0xFF;
  return 1;
}

#ifndef prng
/** 
 * Fills \p Buf with \p Length bytes of random data. 
 * 
 * \hideinitializer
 */
#define prng(Buf,Length) prng_impl((Buf), (Length))
#endif

#ifndef prng_init
/** 
 * Called by dtls_new_context() to set the PRNG seed. You
 * may want to re-define this to allow for a better PRNG. 
 *
 * \hideinitializer
 */
#define prng_init(Value) srand((unsigned long)(Value))
#endif

#endif /* _CRYPTO_H_ */

