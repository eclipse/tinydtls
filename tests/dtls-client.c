#include "config.h" 

/* This is needed for apple */
#define __APPLE_USE_RFC_3542

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "global.h" 
#include "debug.h" 
#include "dtls.h" 

#define DEFAULT_PORT 20220
#define PRINTF(...) printf(__VA_ARGS__)

static char buf[200];
static size_t len = 0;

static str output_file = { 0, NULL }; /* output file name */

static dtls_context_t *dtls_context = NULL;


static const unsigned char ecdsa_priv_key[] = {
			0x41, 0xC1, 0xCB, 0x6B, 0x51, 0x24, 0x7A, 0x14,
			0x43, 0x21, 0x43, 0x5B, 0x7A, 0x80, 0xE7, 0x14,
			0x89, 0x6A, 0x33, 0xBB, 0xAD, 0x72, 0x94, 0xCA,
			0x40, 0x14, 0x55, 0xA1, 0x94, 0xA9, 0x49, 0xFA};

static const unsigned char ecdsa_pub_key_x[] = {
			0x36, 0xDF, 0xE2, 0xC6, 0xF9, 0xF2, 0xED, 0x29,
			0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91,
			0x63, 0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5,
			0xE4, 0x7C, 0xFB, 0xF2, 0x5F, 0xA5, 0x8F, 0x52};

static const unsigned char ecdsa_pub_key_y[] = {
			0x71, 0xA0, 0xD4, 0xFC, 0xDE, 0x1A, 0xB8, 0x78,
			0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB,
			0xE9, 0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B,
			0x4F, 0xAB, 0xC3, 0x6F, 0xC7, 0x72, 0xF8, 0x29};

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identiy within this particular
 * session. */
int
get_psk_key(struct dtls_context_t *ctx,
	    const session_t *session,
	    const unsigned char *id, size_t id_len,
	    const dtls_psk_key_t **result) {
  static const dtls_psk_key_t psk = {
    .id = (unsigned char *)"Client_identity",
    .id_length = 15,
    .key = (unsigned char *)"secretPSK",
    .key_length = 9
  };

  *result = &psk;
  return 0;
}

int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}

void
try_send(struct dtls_context_t *ctx, session_t *dst) {
  int res;
  res = dtls_write(ctx, dst, (uint8 *)buf, len);
  if (res >= 0) {
    memmove(buf, buf + res, len - res);
    len -= res;
  }
}

void
handle_stdin() {
  if (fgets(buf + len, sizeof(buf) - len, stdin))
    len += strlen(buf + len);
}

int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  return 0;
}

int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  int fd = *(int *)dtls_get_app_data(ctx);
  return sendto(fd, data, len, MSG_DONTWAIT,
		&session->addr.sa, session->size);
}

int
dtls_handle_read(struct dtls_context_t *ctx) {
  int fd;
  session_t session;
#define MAX_READ_BUF 2000
  static uint8 buf[MAX_READ_BUF];
  int len;

  fd = *(int *)dtls_get_app_data(ctx);
  
  if (!fd)
    return -1;

  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);
  len = recvfrom(fd, buf, MAX_READ_BUF, 0, 
		 &session.addr.sa, &session.size);
  
  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dtls_dsrv_log_addr(LOG_DEBUG, "peer", &session);
    dtls_dsrv_hexdump_log(LOG_DEBUG, "bytes from peer", buf, len, 0);
  }

  return dtls_handle_message(ctx, &session, buf, len);
}    

static void dtls_handle_signal(int sig)
{
  dtls_free_context(dtls_context);
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}

/* stolen from libcoap: */
int 
resolve_address(const char *server, struct sockaddr *dst) {
  
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;

  memset(addrstr, 0, sizeof(addrstr));
  if (server && strlen(server) > 0)
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:

      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
      return ainfo->ai_addrlen;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return -1;
}

/*---------------------------------------------------------------------------*/
void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf(stderr, "%s v%s -- DTLS client implementation\n"
	  "(c) 2011-2012 Olaf Bergmann <bergmann@tzi.org>\n\n"
	  "usage: %s [-o file][-p port] [-v num] addr [port]\n"
	  "\t-o file\t\toutput received data to this file (use '-' for STDOUT)\n"
	  "\t-p port\t\tlisten on specified port (default is %d)\n"
	  "\t-v num\t\tverbosity level (default: 3)\n",
	   program, version, program, DEFAULT_PORT);
}

static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
  .get_psk_key = get_psk_key,
  .get_ecdsa_key = get_ecdsa_key,
  .verify_ecdsa_key = verify_ecdsa_key
};

#define DTLS_CLIENT_CMD_CLOSE "client:close"
#define DTLS_CLIENT_CMD_RENEGOTIATE "client:renegotiate"

int 
main(int argc, char **argv) {
  fd_set rfds, wfds;
  struct timeval timeout;
  unsigned short port = DEFAULT_PORT;
  char port_str[NI_MAXSERV] = "0";
  log_t log_level = LOG_WARN;
  int fd, result;
  int on = 1;
  int opt, res;
  session_t dst;

  dtls_init();
  snprintf(port_str, sizeof(port_str), "%d", port);

  while ((opt = getopt(argc, argv, "p:o:v:")) != -1) {
    switch (opt) {
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'o' :
      output_file.length = strlen(optarg);
      output_file.s = (unsigned char *)malloc(output_file.length + 1);
      
      if (!output_file.s) {
	dsrv_log(LOG_CRIT, "cannot set output file: insufficient memory\n");
	exit(-1);
      } else {
	/* copy filename including trailing zero */
	memcpy(output_file.s, optarg, output_file.length + 1);
      }
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    default:
      usage(argv[0], PACKAGE_VERSION);
      exit(1);
    }
  }

  dtls_set_log_level(log_level);
  
  if (argc <= optind) {
    usage(argv[0], PACKAGE_VERSION);
    exit(1);
  }
  
  memset(&dst, 0, sizeof(session_t));
  /* resolve destination address where server should be sent */
  res = resolve_address(argv[optind++], &dst.addr.sa);
  if (res < 0) {
    dsrv_log(LOG_EMERG, "failed to resolve address\n");
    exit(-1);
  }
  dst.size = res;

  /* use port number from command line when specified or the listen
     port, otherwise */
  dst.addr.sin.sin_port = htons(atoi(optind < argc ? argv[optind++] : port_str));

  
  /* init socket and set it to non-blocking */
  fd = socket(dst.addr.sa.sa_family, SOCK_DGRAM, 0);

  if (fd < 0) {
    dsrv_log(LOG_ALERT, "socket: %s\n", strerror(errno));
    return 0;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dsrv_log(LOG_ALERT, "setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }
#if 0
  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    dsrv_log(LOG_ALERT, "fcntl: %s\n", strerror(errno));
    goto error;
  }
#endif
  on = 1;
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IPV6_RECVPKTINFO */
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
#endif /* IPV6_RECVPKTINFO */
    dsrv_log(LOG_ALERT, "setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
  }

  if (signal(SIGINT, dtls_handle_signal) == SIG_ERR) {
    dsrv_log(LOG_ALERT, "An error occurred while setting a signal handler.\n");
    return EXIT_FAILURE;
  }

  dtls_context = dtls_new_context(&fd);
  if (!dtls_context) {
    dsrv_log(LOG_EMERG, "cannot create context\n");
    exit(-1);
  }

  dtls_set_handler(dtls_context, &cb);

  dtls_connect(dtls_context, &dst);

  while (1) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fileno(stdin), &rfds);
    FD_SET(fd, &rfds);
    /* FD_SET(fd, &wfds); */
    
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    result = select(fd+1, &rfds, &wfds, 0, &timeout);
    
    if (result < 0) {		/* error */
      if (errno != EINTR)
	perror("select");
    } else if (result == 0) {	/* timeout */
    } else {			/* ok */
      if (FD_ISSET(fd, &wfds))
	/* FIXME */;
      else if (FD_ISSET(fd, &rfds))
	dtls_handle_read(dtls_context);
      else if (FD_ISSET(fileno(stdin), &rfds))
	handle_stdin();
    }

    if (len) {
      if (len >= strlen(DTLS_CLIENT_CMD_CLOSE) &&
	  !memcmp(buf, DTLS_CLIENT_CMD_CLOSE, strlen(DTLS_CLIENT_CMD_CLOSE))) {
	printf("client: closing connection\n");
	dtls_close(dtls_context, &dst);
	len = 0;
      } else if (len >= strlen(DTLS_CLIENT_CMD_RENEGOTIATE) &&
	         !memcmp(buf, DTLS_CLIENT_CMD_RENEGOTIATE, strlen(DTLS_CLIENT_CMD_RENEGOTIATE))) {
	printf("client: renegotiate connection\n");
	dtls_renegotiate(dtls_context, &dst);
	len = 0;
      } else {
	try_send(dtls_context, &dst);
      }
    }
  }
  
  dtls_free_context(dtls_context);
  exit(0);
}

