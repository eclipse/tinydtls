#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>

#ifndef DSRV_NO_DTLS
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define SERVER_CERT_PEM "./server-cert.pem"
#define SERVER_KEY_PEM  "./server-key.pem"
#define CA_CERT_PEM     "./ca-cert.pem"
#endif

#include "debug.h" 
#include "dsrv.h" 

/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  dsrv_stop(dsrv_get_context());
}

#ifndef DSRV_NO_PROTOCOL_DEMUX
protocol_t
demux_protocol(struct sockaddr *raddr, socklen_t rlen,
	       int ifindex, char *buf, int len) {
  return (buf[0] & 0xfc) == 0x14 ? DTLS : RAW;
}
#endif /* DSRV_NO_PROTOCOL_DEMUX */

void
peer_handle_read(dsrv_context_t *ctx, peer_t *peer, char *buf, int len) {
  int i;
  for (i=0; i<len; i++)
    printf("%c", buf[i]);

  peer_write(peer, buf, len);
}

#ifndef DSRV_NO_DTLS
int 
generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
  /* FIXME: generate secure client-specific cookie */
#define DUMMYSTR "ABCDEFGHIJKLMNOP"
  *cookie_len = strlen(DUMMYSTR);
  memcpy(cookie, DUMMYSTR, *cookie_len);

  return 1;
}

int 
verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len) {
  /* FIXME */
  return 1;
}

#ifndef min
#define min(A,B) ((A) <= (B) ? (A) : (B))
#endif

unsigned int
psk_server_callback(SSL *ssl, const char *identity,
		    unsigned char *psk, unsigned int max_psk_len) {
  static char keybuf[] = "secretPSK";

  printf("psk_server_callback: check identity of client %s\n", identity);
  memcpy(psk, keybuf, min(strlen(keybuf), max_psk_len));

  return min(strlen(keybuf), max_psk_len);
}

int
init_ssl(SSL_CTX *sslctx) {
  int res;

  SSL_CTX_set_cipher_list(sslctx, "ALL");
  SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_OFF);
  
  res = SSL_CTX_use_certificate_file(sslctx, SERVER_CERT_PEM, SSL_FILETYPE_PEM);
  if (res != 1) {
    fprintf(stderr, "cannot read server certificate from file '%s' (%s)\n", 
	    SERVER_CERT_PEM, ERR_error_string(res,NULL));
    return 0;
  }
  
  res = SSL_CTX_use_PrivateKey_file(sslctx, SERVER_KEY_PEM, SSL_FILETYPE_PEM);
  if (res != 1) {
    fprintf(stderr, "cannot read server key from file '%s' (%s)\n", 
	    SERVER_KEY_PEM, ERR_error_string(res,NULL));
    return 0;
  }

  res = SSL_CTX_check_private_key (sslctx);
  if (res != 1) {
    fprintf(stderr, "invalid private key\n");
    return 0;
  }

  res = SSL_CTX_load_verify_locations(sslctx, CA_CERT_PEM, NULL);
  if (res != 1) {
    fprintf(stderr, "cannot read ca file '%s'\n", CA_CERT_PEM);
    return 0;
  }

  /* Client has to authenticate */
  SSL_CTX_set_cookie_generate_cb(sslctx, generate_cookie);
  SSL_CTX_set_cookie_verify_cb(sslctx, verify_cookie);

  SSL_CTX_use_psk_identity_hint(sslctx, "Enter password for DTLS test server");
  SSL_CTX_set_psk_server_callback(sslctx, psk_server_callback);

  return 1;
}
#endif

void 
peer_timeout(struct dsrv_context_t *ctx) {
}

int main(int argc, char **argv) {

#ifdef WANT_IP4
  struct sockaddr_in listen_addr = { AF_INET, htons(20220), { htonl(0x7f000001) } };
#else
  struct sockaddr_in6 listen_addr = { AF_INET6, htons(20220), 0, IN6ADDR_ANY_INIT, 0 };
#endif
  static dsrv_context_t *ctx;

  set_log_level(LOG_DEBUG);
  ctx = dsrv_new_context((struct sockaddr *)&listen_addr, 
			 sizeof(listen_addr), 
			 2000,2000);

  if (!ctx) {
    fprintf(stderr, "E: cannot create server context\n");
    return -1;
  }

  dsrv_set_cb(ctx, peer_timeout, timeout);
  dsrv_set_cb(ctx, peer_handle_read, read);
#ifndef DSRV_NO_PROTOCOL_DEMUX
  dsrv_set_cb(ctx, demux_protocol, demux);
#endif

#ifndef DSRV_NO_DTLS
  if (!init_ssl(ctx->sslctx)) {
    fprintf(stderr, "E: cannot initialize SSL engine\n");
    goto end;
  }
#endif

  /* install signal handler for server shutdown */
  signal(SIGINT, handle_sigint);

  dsrv_run(ctx);

 end:
  dsrv_free_context(ctx);

  return 0;
}
