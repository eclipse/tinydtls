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

#include "global.h"
#include "hmac.h"

/** Maximum size of the generated keyblock. */
#define MAX_KEYBLOCK_LENGTH       108    /* TLS_PSK_AES128_CBC_SHA */

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
extern dtls_cipher_t ciphers[];

typedef struct {
  uint8  client_random[32];	/**< client random gmt and bytes */
  uint8  server_random[32];	/**< server random gmt and bytes */

  int cipher;			/**< cipher type index */
  uint8  compression;		/**< compression method */

  /** 
   * The key block generated from PRF applied to client and server
   * random bytes. The actual size is given by the selected cipher and
   * can be calculated using dtls_kb_size(). Use \c dtls_kb_ macros to
   * access the components of the key block.
   */
  uint8 key_block[MAX_KEYBLOCK_LENGTH];
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
		   str *seeds, int num_seeds,
		   unsigned char *buf, size_t buflen);

/**
 * This function implements the TLS PRF for DTLS_VERSION. For version
 * 1.0, the PRF is P_MD5 ^ P_SHA1 while version 1.2 uses
 * P_SHA256. Currently, the actual PRF is selected at compile time.
 */
size_t dtls_prf(unsigned char *key, size_t keylen,
		str *seeds, int num_seeds,
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
 * Decrypts the specified \p record of length \p record_length
 * and writes the result into \p result. The result buffer must
 * provide sufficient space to hold the cleartext contents of
 * the encrypted message. This function returns \c 0 on error,
 * non-zero otherwise.
 * 
 * \param sec     The security parameters in effect.
 * \param record  The record to decrypt.
 * \param record_length Length of the encrypted message pointed to
 *                by \p record.
 * \param result  A buffer large enough to store the result.
 * \param result_length Will be set to the actual size of the 
 *                decrypted data, excluding the IV.
 * \return \c 0 on error, \c 1 otherwise.
 */
int dtls_decrypt(dtls_security_parameters_t *sec,
		 unsigned char *record, size_t record_length,
		 unsigned char *result, size_t *result_length);

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

#endif /* _CRYPTO_H_ */

