
#ifndef DSRV_NO_DTLS

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>

#include "debug.h" 
#include "config.h" 
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
peer_timeout(struct dsrv_context_t *ctx) {
}

int write_func(struct dtls_context_t *ctx, 
	       struct sockaddr *dst, socklen_t dstlen, int ifindex, 
	       uint8 *buf, int len) {
  int fd = *(int *)dtls_get_app_data(ctx);

  return sendto(fd, buf, len, 0, dst, dstlen);
}

#if 0
void
peer_handle_read(dsrv_context_t *ctx, peer_t *peer, char *buf, int len) {
  int i;
  for (i=0; i<len; i++)
    printf("%c", buf[i]);

  peer_write(peer, buf, len);
}
#else
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
#endif

#if 0
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

#ifdef WITH_OPENSSL
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
#else
int 
main(int argc, char **argv) {
  dtls_context_t *the_context = NULL;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, result;
  int on = 1;
  struct sockaddr_in6 listen_addr = { AF_INET6, htons(20220), 0, IN6ADDR_ANY_INIT, 0 };

  set_log_level(LOG_DEBUG);

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
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
    dsrv_log(LOG_ALERT, "setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
  }

  if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
    dsrv_log(LOG_ALERT, "bind: %s\n", strerror(errno));
    goto error;
  }

  the_context = dtls_new_context(&fd);
  dtls_set_psk(the_context, (unsigned char *)"secretPSK", 9);

  dtls_set_cb(the_context, write_func, write);

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
#endif

#else
/* just include a no-op when built without DTLS */
int main(int argc, char **argv) {
  return 0;
}
#endif /* DSRV_NO_DTLS */
