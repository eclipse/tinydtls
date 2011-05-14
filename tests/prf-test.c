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

void
print_mac(dtls_security_parameters_t *sec,
	  unsigned char *record, size_t length) {
  dtls_hmac_context_t hmac_ctx;
  unsigned char mac[DTLS_HMAC_MAX];

  dtls_hmac_init(&hmac_ctx, 
		 dtls_kb_client_mac_secret(sec),
		 dtls_kb_mac_secret_size(sec),
		 dtls_kb_mac_algorithm(sec));
  
  dtls_mac(&hmac_ctx, 
	   record, 		/* the pre-filled record header */
	   record + sizeof(dtls_record_header_t),
	   length - sizeof(dtls_record_header_t),
	   mac);

  printf("  MAC is:\t\t");
  dump(mac, dtls_kb_digest_size(sec));
  printf("\n");
}

int main(int argc, char **argv) {
  unsigned char key[] = "secretPSK";
  unsigned char pre_master[2 * sizeof(key) + 2];

  static unsigned char master_secret[DTLS_MASTER_SECRET_LENGTH];
  size_t len, plen, key_block_len;
  int i;

  dtls_security_parameters_t sec = { 
    { 0x4d, 0xc7, 0xd0, 0x3f, 0xef, 0xed, 0x89, 0x4e, 
      0x76, 0xd7, 0x83, 0xcc, 0xa6, 0x51, 0x2b, 0x58, 
      0xc4, 0x27, 0x7a, 0xa1, 0x9a, 0xdb, 0xef, 0xab, 
      0xb9, 0x26, 0x2b, 0x4b, 0x34, 0x22, 0x29, 0xa4 },
    { 0x4d, 0xc7, 0xd0, 0x3f, 0xab, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13 },
    0,				/* cipher index */
    0				/* compression */
  };

  unsigned char packet[] = {
    0x16, 0xfe, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x2c, 0x14, 0x00, 0x00, 
    0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x0c, 0x75, 0x53, 0xb1, 0xef, 0x3d, 0xf1, 0xb0, 
    0x86, 0x58, 0x2b, 0x43, 0xa6, 0xf2, 0x92, 0x09, 
    0x4f, 0xeb, 0xc9, 0xe2, 0x5e, 0xac, 0x8c, 0x18, 
    0x71, 0x6c, 0xa9, 0xbb, 0x7a, 0x81, 0xa0, 0xac, 
    0x76
  };

  int res;
  unsigned char buf[1000];

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


  printf("\n");
  print_mac(&sec, packet, sizeof(packet) - dtls_kb_digest_size(&sec));
  printf("\n");

  /**********************************************************************
   * encrypt 
   **********************************************************************/

  sec.read_cipher = 
    dtls_new_cipher(&ciphers[0],
		    dtls_kb_client_write_key(&sec),
		    dtls_kb_key_size(&sec));

  if (!sec.read_cipher) {
    warn("cannot create cipher\n");
    return -1;
  }

  dtls_init_cipher(sec.read_cipher,
		   dtls_kb_client_iv(&sec),
		   dtls_kb_iv_size(&sec));


  res = 
    dtls_encrypt(sec.read_cipher, packet + sizeof(dtls_record_header_t), 
		 sizeof(packet) - sizeof(dtls_record_header_t),
		 buf);

  /* fix record length according to padding and IV */
  dtls_int_to_uint16(packet + 11, res);

  printf("encrypted packet (%d bytes payload)\n", res);
  dump(packet, sizeof(dtls_record_header_t));
  dump(buf, res);
  printf("\n");
  

  /**********************************************************************
   * decrypt 
   **********************************************************************/

  dtls_init_cipher(sec.read_cipher,
		   dtls_kb_client_iv(&sec),
		   dtls_kb_iv_size(&sec));


  res = dtls_decrypt(sec.read_cipher, buf, res, buf);

  if (res < 0) {
    printf("decryption failed!\n");
    return -1;
  }

  printf("cleartext (%d bytes):\n", res);  
  dump(packet, sizeof(dtls_record_header_t));
  dump(buf, res);
  printf("\n");

  {
    unsigned char mac[DTLS_HMAC_MAX];
    dtls_hmac_context_t hmac_ctx;

    dtls_hmac_init(&hmac_ctx, 
		   dtls_kb_client_mac_secret(&sec),
		   dtls_kb_mac_secret_size(&sec),
		   dtls_kb_mac_algorithm(&sec));

    res -= dtls_kb_digest_size(&sec);

    dtls_mac(&hmac_ctx, packet, buf, res, mac);
      
    if (memcmp(mac, buf + res, dtls_kb_digest_size(&sec)) == 0)
      printf("MAC OK\n");
    else
      printf("invalid MAC!\n");
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
