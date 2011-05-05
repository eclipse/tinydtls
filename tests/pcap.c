#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <pcap/pcap.h>

#include "debug.h"
#include "dtls.h"
#include "numeric.h"
#include "hmac.h"

/** dumps packets in usual hexdump format */
void hexdump(const unsigned char *packet, int length) {
  int n = 0;

  while (length--) { 
    if (n % 16 == 0)
      printf("%08X ",n);

    printf("%02X ", *packet++);
    
    n++;
    if (n % 8 == 0) {
      if (n % 16 == 0)
	printf("\n");
      else
	printf(" ");
    }
  }
}

/** dump as narrow string of hex digits */
void dump(unsigned char *buf, size_t len) {
  while (len--) 
    printf("%02x", *buf++);
}

#define TRANSPORT_HEADER_SIZE (14+20+8) /* Ethernet + IP + UDP */

/* the pre_master_secret is generated from the PSK at startup */
unsigned char pre_master_secret[60];
size_t pre_master_len = 0;

unsigned char master_secret[DTLS_MASTER_SECRET_LENGTH];
size_t master_secret_len = 0;

dtls_security_parameters_t security_params[2]; 
int config = 0;
unsigned int epoch = 0;

#if DTLS_VERSION == 0xfeff
dtls_hash_t *hs_hash[2];
#elif DTLS_VERSION == 0xfefd
dtls_hash_t *hs_hash[1];
#endif

static inline void
update_hash(uint8 *record, size_t rlength, 
	    uint8 *data, size_t data_length) {
  int i;

  if (!hs_hash[0])
    return;

  printf("add MAC data: ");
  dump(data, data_length);
  printf("\n");
  for (i = 0; i < sizeof(hs_hash) / sizeof(dtls_hash_t *); ++i) {
    /* hs_hash[i]->update(hs_hash[i]->data, record, rlength); */
    hs_hash[i]->update(hs_hash[i]->data, data, data_length);
  }
}

static inline void
finalize_hash(uint8 *buf) {
  if (!hs_hash[0])
    return;
  
  hs_hash[0]->finalize(buf, hs_hash[0]->data);
#if DTLS_VERSION == 0xfeff
  hs_hash[1]->finalize(buf + 16, hs_hash[1]->data);
#endif
  printf("finalize_hash: raw hash is: ");
  dump(buf, 16); printf(" "); dump(buf + 16, 20);
  printf("\n");
}

static inline void
clear_hash() {
  int i;

  for (i = 0; i < sizeof(hs_hash) / sizeof(dtls_hash_t *); ++i)
    free(hs_hash[i]);
  memset(hs_hash, 0, sizeof(hs_hash));
}

#define CURRENT_CONFIG (&security_params[config])
#define OTHER_CONFIG   (&security_params[!(config & 0x01)])
#define SWITCH_CONFIG  (config = !(config & 0x01))

int
decrypt_record(uint8 *packet, size_t length,
	       uint8 **cleartext, size_t *clen) {
  static uint8 buf[400];

  switch (CURRENT_CONFIG->cipher) {
  case -1:			/* no cipher suite selected */
    *cleartext = packet + sizeof(dtls_record_header_t);
    *clen = dtls_uint16_to_int(((dtls_record_header_t *)packet)->length);
    return 1;
  case 0:			/* TLS_PSK_WITH_AES128_CBC_SHA */
    if (length > 400) 
      return 0;

    if (dtls_cbc_decrypt(CURRENT_CONFIG, packet, length, buf, clen)) {
      *cleartext = buf;
      return 1;
    }
    
#ifndef NDEBUG
    fprintf(stderr,"decryption failed!\n");
#endif
    break;
  default:
#ifndef NDEBUG
    fprintf(stderr,"unknown cipher!\n");
#endif    
  }

  return 0;
}

void
handle_packet(const u_char *packet, int length) {
  static int n = 0;
  static unsigned char initial_hello[] = { 
    0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
  };
  uint8 *data; 
  size_t data_length;
  int i;
#if DTLS_VERSION == 0xfeff
#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH 20
#endif
  uint8 hash_buf[16 + SHA1_DIGEST_LENGTH];
#elif DTLS_VERSION == 0xfefd
  uint8 hash_buf[SHA256_DIGEST_LENGTH];
#endif
#define verify_data_length 12
  uint8 verify_data[verify_data_length];
  int is_client;
  n++;

  /* skip frame, IP, UDP header */
  if (length < TRANSPORT_HEADER_SIZE) 
    return;

  is_client = 
    (dtls_uint16_to_int(packet + 14 + 20) != 20220);

  packet += TRANSPORT_HEADER_SIZE;
  length -= TRANSPORT_HEADER_SIZE;

  while (length) {
    /* skip packet if it is from a different epoch */
    if (dtls_uint16_to_int(packet + 3) != epoch)
      goto next;

    if (!decrypt_record((uint8 *)packet, 
	      dtls_uint16_to_int(packet + 11) + sizeof(dtls_record_header_t),
              &data, &data_length))
      goto next;

    if (packet[0] == 22 && data[0] == 1) { /* ClientHello */
      if (memcmp(packet, initial_hello, sizeof(initial_hello)) == 0)
	goto next;
      
      memcpy(OTHER_CONFIG->client_random, data + 14, 32);
      clear_hash();
#if DTLS_VERSION == 0xfeff
      hs_hash[0] = dtls_new_hash(HASH_MD5);
      hs_hash[1] = dtls_new_hash(HASH_SHA1);

      hs_hash[0]->init(hs_hash[0]->data);
      hs_hash[1]->init(hs_hash[1]->data);
#elif DTLS_VERSION == 0xfefd
      hs_hash[0] = dtls_new_hash(HASH_SHA256);
      hs_hash[0]->init(hs_hash[0]->data);
#endif
    }
    
    if (packet[0] == 22 && data[0] == 2) { /* ServerHello */
      memcpy(OTHER_CONFIG->server_random, data + 14, 32);
      OTHER_CONFIG->cipher = 0;	/* FIXME: search in ciphers */
    }
    
    if (packet[0] == 20 && data[0] == 1) { /* ChangeCipherSpec */
      master_secret_len = 
	dtls_prf(pre_master_secret, pre_master_len,
		 (unsigned char *)"master secret", 13,
		 OTHER_CONFIG->client_random, 32,
		 OTHER_CONFIG->server_random, 32,
		 master_secret, DTLS_MASTER_SECRET_LENGTH);
  
      printf("master_secret:\n  ");
      for(i = 0; i < master_secret_len; i++) 
	printf("%02x", master_secret[i]);
      printf("\n");

      /* create key_block from master_secret
       * key_block = PRF(master_secret,
                     "key expansion" + server_random + client_random) */
      dtls_prf(master_secret, master_secret_len,
	       (unsigned char *)"key expansion", 13,
	       OTHER_CONFIG->server_random, 32,
	       OTHER_CONFIG->client_random, 32,
	       OTHER_CONFIG->key_block, 
	       dtls_kb_size(OTHER_CONFIG));

      SWITCH_CONFIG;
      epoch++;

      printf("key_block:\n");
      printf("  client_MAC_secret:\t");  
      dump(dtls_kb_client_mac_secret(CURRENT_CONFIG), 
	   dtls_kb_mac_secret_size(CURRENT_CONFIG));
      printf("\n");

      printf("  server_MAC_secret:\t");  
      dump(dtls_kb_server_mac_secret(CURRENT_CONFIG), 
	   dtls_kb_mac_secret_size(CURRENT_CONFIG));
      printf("\n");

      printf("  client_write_key:\t");  
      dump(dtls_kb_client_write_key(CURRENT_CONFIG), 
	   dtls_kb_key_size(CURRENT_CONFIG));
      printf("\n");

      printf("  server_write_key:\t");  
      dump(dtls_kb_server_write_key(CURRENT_CONFIG), 
	   dtls_kb_key_size(CURRENT_CONFIG));
      printf("\n");

      printf("  client_IV:\t\t");  
      dump(dtls_kb_client_iv(CURRENT_CONFIG), 
	   dtls_kb_iv_size(CURRENT_CONFIG));
      printf("\n");
      
      printf("  server_IV:\t\t");  
      dump(dtls_kb_server_iv(CURRENT_CONFIG), 
	   dtls_kb_iv_size(CURRENT_CONFIG));
      printf("\n");
      
    }

    printf("packet %d:\n", n);
    hexdump(packet, sizeof(dtls_record_header_t));
    printf("\n");
    hexdump(data, data_length);
    printf("\n");

    if (packet[0] == 22) {
      if (data[0] == 20) { /* Finished (from client) */
	finalize_hash(hash_buf);
	clear_hash();
#if 1
	dtls_prf(master_secret, master_secret_len,
		 (unsigned char *)"client finished", 15,
		 hash_buf, sizeof(hash_buf),
		 NULL, 0,
		 data + sizeof(dtls_handshake_header_t),
		 verify_data_length);
	printf("verify_data:\n");
	dump(data, data_length);
	printf("\n");

#else
	dtls_prf(master_secret, master_secret_len,
		 (unsigned char *)"client finished", 15,
		 hash_buf, sizeof(hash_buf),
		 NULL, 0,
		 verify_data,
		 verify_data_length);
	printf("verify_data:\n");
	dump(verify_data, verify_data_length);
	printf("\n");
#endif
      } else {
	update_hash((unsigned char *)packet, sizeof(dtls_record_header_t),
		    data,
		    sizeof(dtls_handshake_header_t) +
		    dtls_uint24_to_int(((dtls_handshake_header_t *)data)->length));
      }
    }

  next:
    length -= dtls_uint16_to_int(packet + 11) + sizeof(dtls_record_header_t);
    packet += dtls_uint16_to_int(packet + 11) + sizeof(dtls_record_header_t);
  }
}

void init() {
  memset(security_params, 0, sizeof(security_params));
  CURRENT_CONFIG->cipher = -1;

  memset(hs_hash, 0, sizeof(hs_hash));

  /* set pre_master_secret to default if no PSK was given */
  if (!pre_master_len)
    pre_master_len = 
      dtls_pre_master_secret((unsigned char *)"secretPSK", 9, 
			     pre_master_secret);
}

int main(int argc, char **argv) {
  pcap_t *pcap;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr *pkthdr;
  const u_char *packet;
  int res = 0;
  int c, option_index = 0;

  static struct option opts[] = {
    { "psk",  1, 0, 'p' },
    { 0, 0, 0, 0 }
  };

  /* handle command line options */
  while (1) {
    c = getopt_long(argc, argv, "p:", opts, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'p':
      pre_master_len = dtls_pre_master_secret((unsigned char *)optarg, 
	      			      strlen(optarg), pre_master_secret);
      break;
    }
  }

  if (argc <= optind) {
    fprintf(stderr, "usage: %s [-p|--psk PSK] pcapfile\n", argv[0]);
    return -1;
  }

  init();

  pcap = pcap_open_offline(argv[optind], errbuf);
  if (!pcap) {
    fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
    return -2;
  }

  for (;;) {
    res = pcap_next_ex(pcap, &pkthdr, &packet);
    
    switch(res) {
    case -2: goto done;
    case -1: pcap_perror(pcap, "read packet"); break;
    case  1: handle_packet(packet, pkthdr->caplen); break;
    default: 
      ;
    }      
  }
 done:

  pcap_close(pcap);

  return 0;
}
