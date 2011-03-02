#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "dsrv.h" 

void
handle_read(struct dsrv_context_t *ctx) {
  int len;
  static char buf[200];
  struct sockaddr_storage src;
  socklen_t srclen = sizeof(src);

  len = recvfrom(dsrv_get_fd(ctx, DSRV_READ), buf, sizeof(buf), 0, 
		 (struct sockaddr *)&src, &srclen);

  if (len < 0) {
    perror("recvfrom");
  } else {
    printf("read data: '%*s'\n", len, buf);
  }
}

void
handle_write(struct dsrv_context_t *ctx) {
  printf("FIXME: write pending data from ctx\n");
}

int main(int argc, char **argv) {

  struct sockaddr_in6 listen_addr = { AF_INET6, htons(20220), 0, IN6ADDR_ANY_INIT, 0 };
  fd_set rfds, wfds;
  struct timeval timeout;
  struct dsrv_context_t *ctx;
  int result;

  ctx = dsrv_new_context((struct sockaddr *)&listen_addr, sizeof(listen_addr), 
			 200,200);

  if (!ctx) {
    fprintf(stderr, "E: cannot create server context\n");
    return -1;
  }

  while (1) {
    dsrv_prepare(ctx, &rfds, DSRV_READ);
    dsrv_prepare(ctx, &rfds, DSRV_WRITE);
    
    timeout.tv_sec = 0;
    timeout.tv_usec = dsrv_get_timeout(ctx);
    
    result = select( FD_SETSIZE, &rfds, &wfds, 0, &timeout);
    
    if (result < 0) {		/* error */
      if (errno != EINTR)
	perror("select");
    } else if (result == 0) {	/* timeout */
      printf(".");		
    } else {			/* ok */
      if (dsrv_check(ctx, &rfds, DSRV_READ))
	handle_read(ctx);
      else if (dsrv_check(ctx, &wfds, DSRV_WRITE))
	handle_write(ctx);
    }
  }

  dsrv_close(ctx);
  dsrv_free_context(ctx);

  return 0;
}
