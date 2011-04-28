#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "aes/rijndael.h"

#include "debug.h"
#include "dtls.h"
#include "numeric.h"
#include "hmac.h"


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
    { 0x4d, 0xb9, 0xca, 0x2f, 0x69, 0xe4, 0x01, 0x00, 
      0xd4, 0xb9, 0xb2, 0xb4, 0xfd, 0x9c, 0x0c, 0xd8, 
      0xe4, 0x5f, 0x90, 0x38, 0x18, 0x5c, 0xa5, 0x06, 
      0xd6, 0xad, 0x23, 0x2e, 0xaf, 0x19, 0xef, 0x07 },
    { 0x4d, 0xb9, 0xca, 0x2f, 0xab, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13 },
    0,				/* cipher index */
    0				/* compression */
  };

  unsigned char packet[] = {
    0x16, 0xfe, 0xff, 0x00, 0x01, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x38, 0xe3, 
    0xac, 0x89, 0x15, 0x7e, 0x94, 0x1e, 0x5f, 0x71, 
    0x10, 0x84, 0x19, 0xdc, 0xfc, 0xa2, 0x8c, 0x06, 
    0xae, 0x8c, 0x7f, 0xca, 0x47, 0xdb, 0xb3, 0x79, 
    0xa5, 0x00, 0x92, 0x62, 0x88, 0x13, 0x9b, 0x41, 
    0xec, 0xf9, 0xec, 0xac, 0x6c, 0xa1, 0x6c, 0x08, 
    0x25, 0x87, 0x38, 0xc9, 0x02, 0x7c, 0x3e, 0xab, 
    0x57, 0x6d, 0xa0, 0x77, 0x2c, 0x59, 0xa7, 0xac, 
    0x39, 0x1c, 0xcf, 0x31, 0x5d, 0xe1
  };
  unsigned char cleartext[1000];

  size_t cleartext_length;

  /**********************************************************************
   * key derivation
   **********************************************************************/

  /* create pre_master_secret */
  plen = dtls_pre_master_secret(key, sizeof(key) - 1, pre_master);

  /* create master_secret from pre_master_secret
   * master_secret = PRF(pre_master_secret, 
                         "master secret" + client_random + server_random) */
  len = dtls_prf(pre_master, plen,
		 (unsigned char *)"master secret", 13,
		 sec.client_random, 32,
		 sec.server_random, 32,
		 master_secret, DTLS_MASTER_SECRET_LENGTH);
  
  printf("master_secret:\n");
  for(i = 0; i < len; i++) 
    printf("%02x", master_secret[i]);
  printf("\n");

  /* create key_block from master_secret
   * key_block = PRF(master_secret,
                     "key expansion" + server_random + client_random) */
  key_block_len = dtls_prf(master_secret, len,
			   (unsigned char *)"key expansion", 13,
			   sec.server_random, 32,
			   sec.client_random, 32,
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
  if (!dtls_cbc_decrypt(&sec,
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

/* handshake1 */

master_secret:
5ceccf7342151cfb0e8c86a0a63ebfcbbeb80c48da24c93d1f02b7828e3249b43808a77b71baad2f1a8b93ab0db6f0b1
key_block:
  client_MAC_secret:	d34fec533adaab09441e65a9ae13154fc44fcded
  server_MAC_secret:	bd61d4eeacae81bddcc116968800353dad3edd12
  client_write_key:	e9118d20ba7cd765995c2033bd8e2cbe
  server_write_key:	01cdd239693d8b203241b7635d3f09fc
  client_IV:		b2109802adf4f08c15b22816d1d668fb
  server_IV:		8507d8b2e51fa89d40000e2b2436b0b1
cleartext:
1400000c000300000000000c0963da17108dc8e481275891923704d906485a1d3767250f5e134d135d1e491003030303
MAC (valid):
923704d906485a1d3767250f5e134d135d1e4910

#endif
