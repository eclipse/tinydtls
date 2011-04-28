#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "aes/rijndael.h"

#include "debug.h"
#include "dtls.h"
#include "numeric.h"
#include "hmac.h"

#define DTLS_MASTER_SECRET_LENGTH 48

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
pre_master_secret(unsigned char *key, size_t keylen,
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

void dump(unsigned char *buf, size_t len) {
  while (len--) 
    printf("%02x", *buf++);
}

int main(int argc, char **argv) {
  unsigned char key[] = "secretPSK";
  unsigned char pre_master[2 * sizeof(key) + 2];

  static unsigned char master_secret[DTLS_MASTER_SECRET_LENGTH];
  size_t len, plen, key_block_len;
  int i;

  dtls_security_parameters_t sec = { 
    { 0x4d, 0xb6, 0xfc, 0x22, 0xac, 0x77, 0x38, 0x82, 
      0xaa, 0x67, 0xf2, 0x2d, 0xdd, 0x22, 0x31, 0xfd, 
      0x4b, 0xa7, 0x61, 0xf3, 0x6d, 0x96, 0xb5, 0xbe, 
      0xc0, 0xb6, 0x49, 0x14, 0x6a, 0xc2, 0x49, 0x2f },
    { 0x4d, 0xb6, 0xfc, 0x22, 0xab, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13 },
    0,				/* cipher index */
    0				/* compression */
  };

  str master_seeds[] = {
    { 13, (unsigned char *)"master secret" },
    /* client random: */
    { 32, sec.client_random },
    /* server random: */
    { 32, sec.server_random }
  };

  str key_block_seeds[] = {
    { 13, (unsigned char *)"key expansion" },
    /* server random: */
    { 32, sec.server_random },
    /* client random: */
    { 32, sec.client_random }
  };

  unsigned char packet[] = {
    0x16, 0xfe, 0xff, 0x00, 0x01, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, 0x35, 
    0xdf, 0x52, 0xc3, 0x75, 0x82, 0x26, 0x21, 0x76, 
    0x55, 0xb6, 0xc3, 0x4c, 0x73, 0x35, 0x36, 0x45, 
    0xa5, 0x18, 0x2e, 0xf6, 0xee, 0xff, 0xf5, 0xf0, 
    0xd1, 0xee, 0x90, 0x08, 0x20, 0x3f, 0x03, 0x72, 
    0x52, 0x34, 0x94, 0x27, 0x53, 0xb3, 0xc2, 0x27, 
    0xbc, 0x7e, 0x97, 0x1f, 0x56, 0x77, 0xcd, 0x0f, 
    0xa0, 0x01, 0xc7, 0xa3, 0x1e, 0x40, 0x5e, 0x75, 
    0x08, 0xb7, 0xf9, 0x94, 0x32, 0x4a, 0x08 };
  unsigned char cleartext[1000];

  size_t cleartext_length;

  /**********************************************************************
   * key derivation
   **********************************************************************/

  /* create pre_master_secret */
  plen = pre_master_secret(key, sizeof(key) - 1, pre_master);

  /* create master_secret from pre_master_secret
   * master_secret = PRF(pre_master_secret, 
                         "master secret" + client_random + server_random) */
  len = dtls_prf(pre_master, plen,
		 master_seeds, sizeof(master_seeds) / sizeof(str),
		 master_secret, DTLS_MASTER_SECRET_LENGTH);
  
  printf("master_secret:\n");
  for(i = 0; i < len; i++) 
    printf("%02x", master_secret[i]);
  printf("\n");

  /* create key_block from master_secret
   * key_block = PRF(master_secret,
                     "key expansion" + server_random + client_random) */
  key_block_len = dtls_prf(master_secret, len,
			   key_block_seeds, sizeof(key_block_seeds) / sizeof(str),
			   sec.key_block, 
			   dtls_kb_size(&sec));

  printf("key_block:\n");
  printf("  client_MAC_secret:\t");  
  dump(dtls_kb_client_mac_secret(&sec), dtls_kb_mac_secret_size(&sec));
  printf("\n");

  printf("  server_MAC_secret:\t");  
  dump(dtls_kb_server_mac_secret(&sec), dtls_kb_mac_secret_size(&sec));
  printf("\n");

  printf("  client_write_key:\t");  
  dump(dtls_kb_client_write_key(&sec), dtls_kb_key_size(&sec));
  printf("\n");

  printf("  server_write_key:\t");  
  dump(dtls_kb_server_write_key(&sec), dtls_kb_key_size(&sec));
  printf("\n");

  printf("  client_IV:\t\t");  
  dump(dtls_kb_client_iv(&sec), dtls_kb_iv_size(&sec));
  printf("\n");

  printf("  server_IV:\t\t");  
  dump(dtls_kb_server_iv(&sec), dtls_kb_iv_size(&sec));
  printf("\n");

  
  /* FIXME: calculate Finished hash: */
  /* PRF(master_secret, "client finished", MD5(handshake_messages) + */
  /*         SHA-1(handshake_messages)) [0..11]; */

  /**********************************************************************
   * decrypt 
   **********************************************************************/
  if (!dtls_decrypt(&sec,
		    packet, sizeof(packet),
		    cleartext, &cleartext_length)) {
    printf("decryption failed!\n");
    return -1;
  }

  printf("cleartext:\n");  
  dump(cleartext, cleartext_length);
  printf("\n");

  if (!dtls_verify(&sec,
		   packet, sizeof(packet),
		   cleartext, cleartext_length)) {
    printf("invalid MAC!\n");
    return -1;
  }

  return 0;
}

#if 0
http://www.openssl.org/~bodo/tls-cbc.txt

/* from packets2.c */
ba93e4e8808960c823ade4792b94679c
14				/* type:   Finished */
00000c				/* length: 12 */
0003				/* message sequence number */
000000				/* fragment offset */
00000c				/* fragment length */
6b42ce072c16da23e77320a6	/* verify data */
4a54498d473486371560464c376135f0c00f20da /* MAC using SHA-1 */
03030303				 /* padding */

/* from packets3.c: */
ab 15 b1 7a 64 a5 89 2b 36 75 96 42 86 c1 1c 1e   /* random */
14 00 00 0c 00 03 00 00 00 00 00 0c 75 53 b1 ef 3d f1 b0 86 58 2b 43 a6 2b f8 ab 47 43 bf b6 6b a8 5a dc ca 42 71 56 8d 11 f1 f9 f8 03 03 03 03

/* ciphertext: */
a9 1c 46 b2 9a 11 54 19 2a 30 d3 ad e1 69 d8 7a d3 ad a1 7e a4 4b 51 ed 74 b7 2d 00 7e 18 23 7b 88 08 bd 5e b4 4b 12 a6 2a 0d 19 d1 4e fb 33 19 12 09 12 7a 20 20 25 68 93 c4 af 57 f1 56 32 8e
#endif
