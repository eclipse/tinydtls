
#ifndef DSRV_NO_DTLS

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

#include "debug.h" 
#include "config.h" 
#include "dsrv.h" 

static char buf[200];
static size_t len = 0;

void 
peer_timeout(struct dsrv_context_t *ctx) {
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

void
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
}

int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  int fd = *(int *)dtls_get_app_data(ctx);
  return sendto(fd, data, len, MSG_DONTWAIT,
		&session->raddr.sa, session->rlen);
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
  session.rlen = sizeof(session.raddr);
  len = recvfrom(fd, buf, MAX_READ_BUF, 0, 
		 &session.raddr.sa, &session.rlen);

  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dsrv_log(LOG_DEBUG, "got %d bytes from port %d\n", len, 
	     ntohs(session.raddr.sin6.sin6_port));
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

extern int dtls_connect(dtls_context_t *ctx, session_t *dst);

int 
main(int argc, char **argv) {
  dtls_context_t *the_context = NULL;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, result;
  int on = 1;
  session_t dst;

  set_log_level(LOG_DEBUG);

  /* init socket and set it to non-blocking */
  fd = socket(AF_INET, SOCK_DGRAM, 0);

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
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
    dsrv_log(LOG_ALERT, "setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
  }

  the_context = dtls_new_context(&fd);
  dtls_set_psk(the_context, (unsigned char *)"secretPSK", 9,
	       (unsigned char *)"Client_identity", 15);

  dtls_set_cb(the_context, read_from_peer, read);
  dtls_set_cb(the_context, send_to_peer, write);


  /* FIXME: set dst */
  /* resolve destination address where server should be sent */
  memset(&dst, 0, sizeof(session_t));
  result = resolve_address("127.0.0.1", &dst.raddr.sa);
  
  if (result < 0) {
    fprintf(stderr, "failed to resolve address\n");
    exit(-1);
  }

  dst.rlen = result;
  dst.raddr.sin.sin_port = htons(20220);

  dtls_connect(the_context, &dst);
  
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
	dtls_handle_read(the_context);
      else if (FD_ISSET(fileno(stdin), &rfds))
	handle_stdin();
    }
    if (len)
      try_send(the_context, &dst);
  }
  
  dtls_free_context(the_context);
  exit(0);
}

#endif /* DSRV_NO_DTLS */
