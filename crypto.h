/*******************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Olaf Bergmann  - initial API and implementation
 *    Hauke Mehrtens - memory optimization, ECC integration
 *
 *******************************************************************************/

#ifndef _DTLS_CRYPTO_H_
#define _DTLS_CRYPTO_H_

#include <stdlib.h>		/* for rand() and srand() */
#include <stdint.h>

#include "aes/rijndael.h"

#include "tinydtls.h"
#include "global.h"
#include "state.h"
#include "numeric.h"
#include "hmac.h"
#include "ccm.h"

/* TLS_PSK_WITH_AES_128_CCM_8 */
#define DTLS_MAC_KEY_LENGTH    0
#define DTLS_KEY_LENGTH        16 /* AES-128 */
#define DTLS_BLK_LENGTH        16 /* AES-128 */
#define DTLS_MAC_LENGTH        DTLS_HMAC_DIGEST_SIZE
#define DTLS_IV_LENGTH         4  /* length of nonce_explicit */

/* EC key size for curve secp256r1 */
#define DTLS_EC_KEY_SIZE 32

/** 
 * Maximum size of the generated keyblock. Note that MAX_KEYBLOCK_LENGTH must 
 * be large enough to hold the pre_master_secret, i.e. twice the length of the 
 * pre-shared key + 1.
 */
#define MAX_KEYBLOCK_LENGTH  \
  (2 * DTLS_MAC_KEY_LENGTH + 2 * DTLS_KEY_LENGTH + 2 * DTLS_IV_LENGTH)

/** Length of DTLS master_secret */
#define DTLS_MASTER_SECRET_LENGTH 48
#define DTLS_RANDOM_LENGTH 32

/** Type of index in cipher parameter table */
typedef uint8_t dtls_cipher_index_t;
/** Index in cipher parameter table for NULL cipher */
#define DTLS_CIPHER_INDEX_NULL 0

/** Maximum number of cipher suites */
#define DTLS_MAX_CIPHER_SUITES 4

typedef enum { AES128=0 
} dtls_crypto_alg;

typedef enum {
  DTLS_ECDH_CURVE_SECP256R1
} dtls_ecdh_curve;

/** Crypto context for TLS_PSK_WITH_AES_128_CCM_8 cipher suite. */
typedef struct {
  rijndael_ctx ctx;		       /**< AES-128 encryption context */
  uint8_t tag_length;                  /**< length of MAC tag (=M) */
  uint8_t l;                           /**< number of bytes in length
                                        *   field (= L) */
} aes128_ccm_t;

typedef struct dtls_cipher_context_t {
  /** numeric identifier of this cipher suite in host byte order. */
  aes128_ccm_t data;		/**< The crypto context */
} dtls_cipher_context_t;

typedef struct {
  uint8 own_eph_priv[DTLS_EC_KEY_SIZE];
  uint8 other_eph_pub_x[DTLS_EC_KEY_SIZE];
  uint8 other_eph_pub_y[DTLS_EC_KEY_SIZE];
  uint8 other_pub_x[DTLS_EC_KEY_SIZE];
  uint8 other_pub_y[DTLS_EC_KEY_SIZE];
} dtls_handshake_parameters_ecdsa_t;

/* This is the maximal supported length of the psk client identity and psk
 * server identity hint */
#ifndef DTLS_PSK_MAX_CLIENT_IDENTITY_LEN
#define DTLS_PSK_MAX_CLIENT_IDENTITY_LEN   32
#endif /* DTLS_PSK_MAX_CLIENT_IDENTITY_LEN */

/* This is the maximal supported length of the pre-shared key. */
#define DTLS_PSK_MAX_KEY_LEN DTLS_KEY_LENGTH

typedef struct {
  uint16_t id_length;
  unsigned char identity[DTLS_PSK_MAX_CLIENT_IDENTITY_LEN];
} dtls_handshake_parameters_psk_t;

typedef struct {
    uint64_t cseq;        /**< current read sequence number */
    /**
     * bitfield of already received sequence numbers.
     * B0 := cseqn, B1 := cseqn -1, ..., B63 := cseqn - 63
     * Initially 0, set to 1 (B0) with the first received message of the epoch,
     * or -1 (B0..B63) with a verified ClientHello (server-side only)
     */
    uint64_t bitfield;
} seqnum_t;

/* Maximum CID length. */
#ifndef DTLS_MAX_CID_LENGTH
#define DTLS_MAX_CID_LENGTH 16
#endif

#if (DTLS_MAX_CID_LENGTH > 0)
#ifndef DTLS_USE_CID_DEFAULT
#define DTLS_USE_CID_DEFAULT 1
#endif /* DTLS_USE_CID_DEFAULT */
#endif /* DTLS_MAX_CID_LENGTH > 0 */

typedef struct {
  dtls_compression_t compression;	/**< compression method */

  dtls_cipher_index_t cipher_index;	/**< internal index for cipher_suite_params, DTLS_CIPHER_INDEX_NULL for TLS_NULL_WITH_NULL_NULL */
  uint16_t epoch;	     /**< counter for cipher state changes*/
  uint64_t rseq;	     /**< sequence number of last record sent */

  /** 
   * The key block generated from PRF applied to client and server
   * random bytes. The actual size is given by the selected cipher and
   * can be calculated using dtls_kb_size(). Use \c dtls_kb_ macros to
   * access the components of the key block.
   */
  uint8 key_block[MAX_KEYBLOCK_LENGTH];

#if (DTLS_MAX_CID_LENGTH > 0)
  uint8_t write_cid[DTLS_MAX_CID_LENGTH];
  uint8_t write_cid_length;
#endif /* DTLS_MAX_CID_LENGTH > 0 */

  seqnum_t cseq;        /**<sequence number of last record received*/
} dtls_security_parameters_t;

struct netq_t;

/**
 * Set of user parameters used by the handshake.
 *
 * A copy of default_user_parameters (see dtls.c) are passed to the
 * get_user_parameters callback provided in dtls_handler_t and may be
 * adapted according the user's requirements.
 */
typedef struct dtls_user_parameters_t {
  /**
   * The list of cipher suites.
   * The list must be terminated by TLS_NULL_WITH_NULL_NULL.
   */
  dtls_cipher_t cipher_suites[DTLS_MAX_CIPHER_SUITES + 1];
  unsigned int force_extended_master_secret:1; /** force extended master secret extension (RFC7627) */
  unsigned int force_renegotiation_info:1;     /** force renegotiation info extension (RFC5746) */
#if (DTLS_MAX_CID_LENGTH > 0)
  unsigned int support_cid:1;                  /** indicate CID support (RFC9146) */
#endif
} dtls_user_parameters_t;

typedef struct {
  union {
    struct random_t {
      uint8 client[DTLS_RANDOM_LENGTH];	/**< client random gmt and bytes */
      uint8 server[DTLS_RANDOM_LENGTH];	/**< server random gmt and bytes */
    } random;
    /** the session's master secret */
    uint8 master_secret[DTLS_MASTER_SECRET_LENGTH];
  } tmp;
  struct netq_t *reorder_queue;	/**< the packets to reorder */
  dtls_hs_state_t hs_state;  /**< handshake protocol status */

  dtls_compression_t compression;		/**< compression method */
  dtls_user_parameters_t user_parameters;	/**< user parameters */
  dtls_cipher_index_t cipher_index;		/**< internal index for cipher_suite_params, DTLS_CIPHER_INDEX_NULL for TLS_NULL_WITH_NULL_NULL */

#if (DTLS_MAX_CID_LENGTH > 0)
  uint8_t write_cid[DTLS_MAX_CID_LENGTH];
  uint8_t write_cid_length;
#endif /* DTLS_MAX_CID_LENGTH > 0 */

  unsigned int do_client_auth:1;
  unsigned int extended_master_secret:1;
  unsigned int renegotiation_info:1;
  union {
#ifdef DTLS_ECC
    dtls_handshake_parameters_ecdsa_t ecdsa;
#endif /* DTLS_ECC */
#ifdef DTLS_PSK
    dtls_handshake_parameters_psk_t psk;
#endif /* DTLS_PSK */
  } keyx;
} dtls_handshake_parameters_t;

/* The following macros provide access to the components of the
 * key_block in the security parameters. */

#define dtls_kb_client_mac_secret(Param, Role) ((Param)->key_block)
#define dtls_kb_server_mac_secret(Param, Role)				\
  (dtls_kb_client_mac_secret(Param, Role) + DTLS_MAC_KEY_LENGTH)
#define dtls_kb_remote_mac_secret(Param, Role)				\
  ((Role) == DTLS_SERVER						\
   ? dtls_kb_client_mac_secret(Param, Role)				\
   : dtls_kb_server_mac_secret(Param, Role))
#define dtls_kb_local_mac_secret(Param, Role)				\
  ((Role) == DTLS_CLIENT						\
   ? dtls_kb_client_mac_secret(Param, Role)				\
   : dtls_kb_server_mac_secret(Param, Role))
#define dtls_kb_mac_secret_size(Param, Role) DTLS_MAC_KEY_LENGTH
#define dtls_kb_client_write_key(Param, Role)				\
  (dtls_kb_server_mac_secret(Param, Role) + DTLS_MAC_KEY_LENGTH)
#define dtls_kb_server_write_key(Param, Role)				\
  (dtls_kb_client_write_key(Param, Role) + DTLS_KEY_LENGTH)
#define dtls_kb_remote_write_key(Param, Role)				\
  ((Role) == DTLS_SERVER						\
   ? dtls_kb_client_write_key(Param, Role)				\
   : dtls_kb_server_write_key(Param, Role))
#define dtls_kb_local_write_key(Param, Role)				\
  ((Role) == DTLS_CLIENT						\
   ? dtls_kb_client_write_key(Param, Role)				\
   : dtls_kb_server_write_key(Param, Role))
#define dtls_kb_key_size(Param, Role) DTLS_KEY_LENGTH
#define dtls_kb_client_iv(Param, Role)					\
  (dtls_kb_server_write_key(Param, Role) + DTLS_KEY_LENGTH)
#define dtls_kb_server_iv(Param, Role)					\
  (dtls_kb_client_iv(Param, Role) + DTLS_IV_LENGTH)
#define dtls_kb_remote_iv(Param, Role)					\
  ((Role) == DTLS_SERVER						\
   ? dtls_kb_client_iv(Param, Role)					\
   : dtls_kb_server_iv(Param, Role))
#define dtls_kb_local_iv(Param, Role)					\
  ((Role) == DTLS_CLIENT						\
   ? dtls_kb_client_iv(Param, Role)					\
   : dtls_kb_server_iv(Param, Role))
#define dtls_kb_iv_size(Param, Role) DTLS_IV_LENGTH

#define dtls_kb_size(Param, Role)					\
  (2 * (dtls_kb_mac_secret_size(Param, Role) +				\
	dtls_kb_key_size(Param, Role) + dtls_kb_iv_size(Param, Role)))

/* just for consistency */
#define dtls_kb_digest_size(Param, Role) DTLS_MAC_LENGTH

/** 
 * Expands the secret and key to a block of DTLS_HMAC_MAX 
 * size according to the algorithm specified in section 5 of
 * RFC 4346.
 *
 * \param h       Identifier of the hash function to use.
 * \param key     The secret.
 * \param keylen  Length of \p key.
 * \param label    The label.
 * \param labellen Length of \p label.
 * \param random1 The random pt 1. 
 * \param random1len Length of \p random1.
 * \param random2 The random pt 2. 
 * \param random2len Length of \p random2.
 * \param buf     Output buffer where the result is XORed into
 * \param buflen  The available space for \p buf
 *
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
 * Represents AEAD parameters for dtls_encrypt_params().
 */
typedef struct {
  const uint8_t *nonce;         /**< must be exactly 15 - l bytes */
  uint8_t tag_length;           /**< the MAC tag length (M) */
  uint8_t l;                    /**< number of bytes in the length
                                 *   field (L) */
} dtls_ccm_params_t;

/**
 * Encrypts the specified \p src of given \p length, writing the
 * result to \p buf. The cipher implementation may add more data to
 * the result buffer such as an initialization vector or padding
 * (e.g. for block ciphers in CBC mode). The caller therefore must
 * ensure that \p buf provides sufficient storage to hold the result.
 * Usually this means ( 2 + \p length / blocksize ) * blocksize.  The
 * function returns a value less than zero on error or otherwise the
 * number of bytes written. The provided \p src and \p buf may overlap.
 *
 * \param params AEAD parameters: Nonce, M and L.
 * \param src    The data to encrypt.
 * \param length The actual size of of \p src.
 * \param buf    The result buffer. \p src and \p buf must not
 *               overlap.
 * \param key     The key to use
 * \param keylen  The length of the key
 * \param aad    additional data for AEAD ciphers
 * \param aad_length actual size of @p aad
 * \return The number of encrypted bytes on success, less than zero
 *         otherwise.
 */
int dtls_encrypt_params(const dtls_ccm_params_t *params,
                        const unsigned char *src, size_t length,
                        unsigned char *buf,
                        const unsigned char *key, size_t keylen,
                        const unsigned char *aad, size_t aad_length);

/** 
 * Encrypts the specified \p src of given \p length, writing the
 * result to \p buf. The cipher implementation may add more data to
 * the result buffer such as an initialization vector or padding
 * (e.g. for block ciphers in CBC mode). The caller therefore must
 * ensure that \p buf provides sufficient storage to hold the result.
 * Usually this means ( 2 + \p length / blocksize ) * blocksize.  The
 * function returns a value less than zero on error or otherwise the
 * number of bytes written. The provided \p src and \p buf may overlap.
 *
 * \param src    The data to encrypt.
 * \param length The actual size of of \p src.
 * \param buf    The result buffer.
 * \param nonce  The nonce used for encryption. Must be exactly 13
 *               bytes, because L is set to 2.
 * \param key    The key to use
 * \param keylen The length of the key
 * \param aad    additional data for AEAD ciphers
 * \param aad_length actual size of @p aad
 *
 * \return The number of encrypted bytes on success, less than zero
 *         otherwise. 
 *
 * \deprecated dtls_encrypt() always sets M=8, L=2. Use
 *             dtls_encrypt_params() instead.
 */
int dtls_encrypt(const unsigned char *src, size_t length,
		 unsigned char *buf,
		 const unsigned char *nonce,
		 const unsigned char *key, size_t keylen,
		 const unsigned char *aad, size_t aad_length);

/**
 * Decrypts the given buffer \p src of given \p length, writing the
 * result to \p buf. The function returns \c -1 in case of an error,
 * or the number of bytes written. Note that for block ciphers, \p
 * length must be a multiple of the cipher's block size. A return
 * value between \c 0 and the actual length indicates that only \c n-1
 * block have been processed. The provided \p src and \p buf may overlap.
 *
 * \param params AEAD parameters: Nonce, M and L.
 * \param src     The input buffer to decrypt.
 * \param length  The length of the input buffer.
 * \param buf     The result buffer.
 * \param key     The key to use
 * \param keylen  The length of the key
 * \param aad     additional authentication data for AEAD ciphers
 * \param aad_length actual size of @p aad
 *
 * \return Less than zero on error, the number of decrypted bytes
 *         otherwise.
 */
int dtls_decrypt_params(const dtls_ccm_params_t *params,
                        const unsigned char *src, size_t length,
                        unsigned char *buf,
                        const unsigned char *key, size_t keylen,
                        const unsigned char *aad, size_t aad_length);

/** 
 * Decrypts the given buffer \p src of given \p length, writing the
 * result to \p buf. The function returns \c -1 in case of an error,
 * or the number of bytes written. Note that for block ciphers, \p
 * length must be a multiple of the cipher's block size. A return
 * value between \c 0 and the actual length indicates that only \c n-1
 * block have been processed. The provided \p src and \p buf may overlap.
 * 
 * \param src     The buffer to decrypt.
 * \param length  The length of the input buffer.
 * \param buf     The result buffer.
 * \param nonce  The nonce used for encryption. Must be exactly 13
 *               bytes, because L is set to 2.
 * \param key     The key to use
 * \param keylen  The key to use
 * \param a_data  additional authentication data for AEAD ciphers
 * \param a_data_length actual size of @p aad
 * \return Less than zero on error, the number of decrypted bytes 
 *         otherwise.
 *
 * \deprecated dtls_decrypt() always sets M=8, L=2. Use
 *             dtls_decrypt_params() instead.
 */
int dtls_decrypt(const unsigned char *src, size_t length,
		 unsigned char *buf,
		 const unsigned char *nonce,
		 const unsigned char *key, size_t keylen,
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
 * @param result_len The length of derived pre master secret.
 * @return The actual length of @p result.
 */
int dtls_psk_pre_master_secret(unsigned char *key, size_t keylen,
			       unsigned char *result, size_t result_len);

int dtls_ecdh_pre_master_secret(unsigned char *priv_key,
				unsigned char *pub_key_x,
                                unsigned char *pub_key_y,
                                size_t key_size,
                                unsigned char *result,
                                size_t result_len);

void dtls_ecdsa_generate_key(unsigned char *priv_key,
			     unsigned char *pub_key_x,
			     unsigned char *pub_key_y,
			     size_t key_size);

void dtls_ecdsa_create_sig_hash(const unsigned char *priv_key, size_t key_size,
				const unsigned char *sign_hash, size_t sign_hash_size,
				uint32_t point_r[9], uint32_t point_s[9]);

void dtls_ecdsa_create_sig(const unsigned char *priv_key, size_t key_size,
			   const unsigned char *client_random, size_t client_random_size,
			   const unsigned char *server_random, size_t server_random_size,
			   const unsigned char *keyx_params, size_t keyx_params_size,
			   uint32_t point_r[9], uint32_t point_s[9]);

int dtls_ecdsa_verify_sig_hash(const unsigned char *pub_key_x,
			       const unsigned char *pub_key_y, size_t key_size,
			       const unsigned char *sign_hash, size_t sign_hash_size,
			       unsigned char *result_r, unsigned char *result_s);

int dtls_ecdsa_verify_sig(const unsigned char *pub_key_x,
			  const unsigned char *pub_key_y, size_t key_size,
			  const unsigned char *client_random, size_t client_random_size,
			  const unsigned char *server_random, size_t server_random_size,
			  const unsigned char *keyx_params, size_t keyx_params_size,
			  unsigned char *result_r, unsigned char *result_s);

int dtls_ec_key_asn1_from_uint32(const uint32_t *key, size_t key_size,
				 unsigned char *buf);


dtls_handshake_parameters_t *dtls_handshake_new(void);

void dtls_handshake_free(dtls_handshake_parameters_t *handshake);

dtls_security_parameters_t *dtls_security_new(void);

void dtls_security_free(dtls_security_parameters_t *security);
void crypto_init(void);

#endif /* _DTLS_CRYPTO_H_ */

