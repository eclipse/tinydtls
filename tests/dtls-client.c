#include "config.h" 

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

extern size_t dsrv_print_addr(const session_t *, unsigned char *, size_t);

static char buf[200];
static size_t len = 0;

static str output_file = { 0, NULL }; /* output file name */

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identiy within this particular
 * session. */
int
get_key(struct dtls_context_t *ctx, 
	const session_t *session, 
	const unsigned char *id, size_t id_len, 
	const dtls_key_t **result) {

  static const dtls_key_t psk = {
    .type = DTLS_KEY_PSK,
    .key.psk.id = (unsigned char *)"Client_identity", 
    .key.psk.id_length = 15,
    .key.psk.key = (unsigned char *)"secretPSK", 
    .key.psk.key_length = 9
  };
   
  *result = &psk;
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

#ifndef NDEBUG
extern void dump(unsigned char *buf, size_t len);
#endif

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
#ifndef NDEBUG
    unsigned char addrbuf[72];
    dsrv_print_addr(&session, addrbuf, sizeof(addrbuf));
    dsrv_log(LOG_DEBUG, "got %d bytes from %s\n", len, (char *)addrbuf);
    dump((unsigned char *)&session, sizeof(session_t));
    PRINTF("\n");
    dump(buf, len);
    PRINTF("\n");
#endif
  }

  return dtls_handle_message(ctx, &session, buf, len);
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
  .get_key = get_key
};

int 
main(int argc, char **argv) {
  dtls_context_t *dtls_context = NULL;
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

    if (len)
      try_send(dtls_context, &dst);
  }
  
  dtls_free_context(dtls_context);
  exit(0);
}

