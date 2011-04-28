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

/** Maximum size of the generated keyblock. */
#define MAX_KEYBLOCK_LENGTH       108    /* TLS_PSK_AES128_CBC_SHA */

/** Known ciphersuites 
 *
 * \hideinitializer
 */
#define TLS_PSK_WITH_AES_128_CBC_SHA { 0x00, 0x8c }
#define TLS_NULL_WITH_NULL_NULL      { 0x00, 0x00 }

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

#endif /* _CRYPTO_H_ */

