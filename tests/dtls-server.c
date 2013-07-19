
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>

#include "config.h" 
#include "dtls.h" 
#include "debug.h" 

#define DEFAULT_PORT 20220

extern size_t dsrv_print_addr(const session_t *, unsigned char *, size_t);

#if 0
/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  dsrv_stop(dsrv_get_context());
}
#endif

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

int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    printf("%c", data[i]);

  return dtls_write(ctx, session, data, len);
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
  int *fd;
  session_t session;
  static uint8 buf[DTLS_MAX_BUF];
  int len;

  fd = dtls_get_app_data(ctx);

  assert(fd);

  session.size = sizeof(session.addr);
  len = recvfrom(*fd, buf, sizeof(buf), 0, 
		 &session.addr.sa, &session.size);
  
  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dsrv_log(LOG_DEBUG, "got %d bytes from port %d\n", len, 
	     ntohs(session.addr.sin6.sin6_port));
  }

  return dtls_handle_message(ctx, &session, buf, len);
}    

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

      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
      return ainfo->ai_addrlen;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return -1;
}

void
usage(const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf(stderr, "%s v%s -- DTLS server implementation\n"
	  "(c) 2011-2012 Olaf Bergmann <bergmann@tzi.org>\n\n"
	  "usage: %s [-A address] [-p port] [-v num]\n"
	  "\t-A address\t\tlisten on specified address (default is ::)\n"
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
  dtls_context_t *the_context = NULL;
  log_t log_level = LOG_WARN;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, opt, result;
  int on = 1;
  struct sockaddr_in6 listen_addr;

  memset(&listen_addr, 0, sizeof(struct sockaddr_in6));

  /* fill extra field for 4.4BSD-based systems (see RFC 3493, section 3.4) */
#if defined(SIN6_LEN) || defined(HAVE_SOCKADDR_IN6_SIN6_LEN)
  listen_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif

  listen_addr.sin6_family = AF_INET6;
  listen_addr.sin6_port = htons(DEFAULT_PORT);
  listen_addr.sin6_addr = in6addr_any;

  while ((opt = getopt(argc, argv, "A:p:v:")) != -1) {
    switch (opt) {
    case 'A' :
      if (resolve_address(optarg, (struct sockaddr *)&listen_addr) < 0) {
	fprintf(stderr, "cannot resolve address\n");
	exit(-1);
      }
      break;
    case 'p' :
      listen_addr.sin6_port = htons(atoi(optarg));
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

  /* init socket and set it to non-blocking */
  fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

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

  if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
    dsrv_log(LOG_ALERT, "bind: %s\n", strerror(errno));
    goto error;
  }

  dtls_init();

  the_context = dtls_new_context(&fd);

  dtls_set_handler(the_context, &cb);

  while (1) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fd, &rfds);
    /* FD_SET(fd, &wfds); */
    
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    result = select( fd+1, &rfds, &wfds, 0, &timeout);
    
    if (result < 0) {		/* error */
      if (errno != EINTR)
	perror("select");
    } else if (result == 0) {	/* timeout */
    } else {			/* ok */
      if (FD_ISSET(fd, &wfds))
	;
      else if (FD_ISSET(fd, &rfds)) {
	dtls_handle_read(the_context);
      }
    }
  }
  
 error:
  dtls_free_context(the_context);
  exit(0);
}
