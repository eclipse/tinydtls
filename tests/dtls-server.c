/*******************************************************************************
 *
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 *******************************************************************************/

/* This is needed for apple */
#define __APPLE_USE_RFC_3542

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#include <signal.h>

#include "tinydtls.h"
#include "dtls_debug.h"
#include "dtls_ciphers_util.h"
#include "dtls.h" 

#ifdef IS_WINDOWS
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#define MSG_DONTWAIT 0
#define MSG_TRUNC 0
#else /* ! IS_WINDOWS */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif /* ! IS_WINDOWS */

#define DEFAULT_PORT 20220

static dtls_context_t *the_context = NULL;
static volatile int cmd_exit = 0;
static const dtls_cipher_t* ciphers = NULL;
static unsigned int force_extended_master_secret = 0;
static unsigned int force_renegotiation_info = 0;

static volatile int quit = 0;

#ifdef DTLS_ECC
static const unsigned char ecdsa_priv_key[] = {
            0xD9, 0xE2, 0x70, 0x7A, 0x72, 0xDA, 0x6A, 0x05,
            0x04, 0x99, 0x5C, 0x86, 0xED, 0xDB, 0xE3, 0xEF,
            0xC7, 0xF1, 0xCD, 0x74, 0x83, 0x8F, 0x75, 0x70,
            0xC8, 0x07, 0x2D, 0x0A, 0x76, 0x26, 0x1B, 0xD4};

static const unsigned char ecdsa_pub_key_x[] = {
            0xD0, 0x55, 0xEE, 0x14, 0x08, 0x4D, 0x6E, 0x06,
            0x15, 0x59, 0x9D, 0xB5, 0x83, 0x91, 0x3E, 0x4A,
            0x3E, 0x45, 0x26, 0xA2, 0x70, 0x4D, 0x61, 0xF2,
            0x7A, 0x4C, 0xCF, 0xBA, 0x97, 0x58, 0xEF, 0x9A};

static const unsigned char ecdsa_pub_key_y[] = {
            0xB4, 0x18, 0xB6, 0x4A, 0xFE, 0x80, 0x30, 0xDA,
            0x1D, 0xDC, 0xF4, 0xF4, 0x2E, 0x2F, 0x26, 0x31,
            0xD0, 0x43, 0xB1, 0xFB, 0x03, 0xE2, 0x2F, 0x4D,
            0x17, 0xDE, 0x43, 0xF9, 0xF9, 0xAD, 0xEE, 0x70};
#endif /* DTLS_ECC */

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length) {

  struct keymap_t {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[3] = {
    { (unsigned char *)"Client_identity", 15,
      (unsigned char *)"secretPSK", 9 },
    { (unsigned char *)"default identity", 16,
      (unsigned char *)"\x11\x22\x33", 3 },
    { (unsigned char *)"\0", 2,
      (unsigned char *)"", 1 }
  };
  (void)ctx;
  (void)session;

  if (type != DTLS_PSK_KEY) {
    return 0;
  }

  if (id) {
    size_t i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
      if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
        if (result_length < psk[i].key_length) {
          dtls_warn("buffer too small for PSK");
          return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
        }

        memcpy(result, psk[i].key, psk[i].key_length);
        return psk[i].key_length;
      }
    }
  }

  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}

#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int
get_ecdsa_key(struct dtls_context_t *ctx,
              const session_t *session,
              const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };
  (void)ctx;
  (void)session;

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
                 const session_t *session,
                 const unsigned char *other_pub_x,
                 const unsigned char *other_pub_y,
                 size_t key_size) {
  (void)ctx;
  (void)session;
  (void)other_pub_x;
  (void)other_pub_y;
  (void)key_size;
  return 0;
}
#endif /* DTLS_ECC */

#define DTLS_SERVER_CMD_CLOSE "server:close"
#define DTLS_SERVER_CMD_EXIT "server:exit"

static int
is_command(const char* cmd, const uint8 *data, size_t len) {
  size_t cmd_len = strlen(cmd);
  if (len >= cmd_len && memcmp(cmd, data, cmd_len) == 0) {
    return 1;
  } else {
    return 0;
  }
}

static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len) {
  if (write(STDOUT_FILENO, data, len) == -1)
    dtls_debug("write failed: %s\n", strerror(errno));
  if (is_command(DTLS_SERVER_CMD_CLOSE, data, len)) {
    printf("server: closing connection\n");
    dtls_close(ctx, session);
    return len;
  } else if (is_command(DTLS_SERVER_CMD_EXIT, data, len)) {
    printf("server: exit\n");
    cmd_exit = 1;
    return len;
  }

  /* send it back */
  return dtls_write(ctx, session, data, len);
}

static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8 *data, size_t len) {

  int fd = *(int *)dtls_get_app_data(ctx);
  return sendto(fd, data, len, MSG_DONTWAIT,
                &session->addr.sa, session->size);
}

static void
get_user_parameters(struct dtls_context_t *ctx,
                    session_t *session, dtls_user_parameters_t *user_parameters) {
  (void) ctx;
  (void) session;
  user_parameters->force_extended_master_secret = force_extended_master_secret;
  user_parameters->force_renegotiation_info = force_renegotiation_info;
  if (ciphers) {
    int i = 0;
    while (i < DTLS_MAX_CIPHER_SUITES) {
      user_parameters->cipher_suites[i] = ciphers[i];
      if (ciphers[i] == TLS_NULL_WITH_NULL_NULL) {
        break;
      }
      ++i;
    }
    if (i == DTLS_MAX_CIPHER_SUITES) {
      user_parameters->cipher_suites[i] = TLS_NULL_WITH_NULL_NULL;
    }
  }
}

static int
dtls_handle_read(struct dtls_context_t *ctx) {
  int *fd;
  session_t session;
  static uint8 buf[DTLS_MAX_BUF];
  int len;

  fd = dtls_get_app_data(ctx);

  assert(fd);

  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);
  len = recvfrom(*fd, buf, sizeof(buf), MSG_TRUNC,
                 &session.addr.sa, &session.size);

  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dtls_debug("got %d bytes from port %d\n", len, 
               ntohs(session.addr.sin6.sin6_port));
    if (len <= DTLS_MAX_BUF) {
      dtls_debug_dump("bytes from peer", buf, len);
    } else {
      dtls_debug_dump("bytes from peer", buf, sizeof(buf));
      dtls_warn("%d bytes exceeds buffer %d, drop message!", len, DTLS_MAX_BUF);
      return -1;
    }
  }

  return dtls_handle_message(ctx, &session, buf, len);
}

static void dtls_handle_signal(int sig)
{
  (void)sig;
  quit = 1;
}

static int
resolve_address(const char *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error, len=-1;

  memset(addrstr, 0, sizeof(addrstr));
  if (server && strlen(server) > 0)
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, NULL, &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:
      len = (int)ainfo->ai_addrlen;
      memcpy(dst, ainfo->ai_addr, len);
      goto finish;
    default:
      ;
    }
  }

finish:
  freeaddrinfo(res);
  return len;
}

static void
usage(const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf(stderr, "%s v%s -- DTLS server implementation\n"
         "(c) 2011-2024 Olaf Bergmann <bergmann@tzi.org>\n\n"
         "usage: %s [-A address] [-c cipher suites] [-e] [-p port] [-r] [-v num]\n"
         "\t-A address\t\tlisten on specified address (default is ::)\n",
         program, version, program);
  cipher_suites_usage(stderr, "\t");
  fprintf(stderr, "\t-e\t\tforce extended master secret (RFC7627)\n"
         "\t-p port\t\tlisten on specified port (default is %d)\n"
         "\t-r\t\tforce renegotiation info (RFC5746)\n"
         "\t-v num\t\tverbosity level (default: 3)\n",
         DEFAULT_PORT);
}

static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .get_user_parameters = get_user_parameters,
  .event = NULL,
#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  .get_ecdsa_key = get_ecdsa_key,
  .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
};

int
main(int argc, char **argv) {
  log_t log_level = DTLS_LOG_WARN;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, opt, result;
  int on = 1;
  int off = 0;
  struct sockaddr_in6 listen_addr;
#ifndef IS_WINDOWS
  struct sigaction sa;
#endif /* ! IS_WINDOWS */
  uint16_t port = htons(DEFAULT_PORT);

  memset(&listen_addr, 0, sizeof(struct sockaddr_in6));

  /* fill extra field for 4.4BSD-based systems (see RFC 3493, section 3.4) */
#if defined(SIN6_LEN) || defined(HAVE_SOCKADDR_IN6_SIN6_LEN)
  listen_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif

  listen_addr.sin6_family = AF_INET6;
  listen_addr.sin6_addr = in6addr_any;

  while ((opt = getopt(argc, argv, "A:c:ep:rv:")) != -1) {
    switch (opt) {
    case 'A' :
      if (resolve_address(optarg, (struct sockaddr *)&listen_addr) < 0) {
        fprintf(stderr, "cannot resolve address\n");
        exit(-1);
      }
      break;
    case 'c' :
      ciphers = init_cipher_suites(optarg);
      break;
    case 'e' :
      force_extended_master_secret = 1;
      break;
    case 'p' :
      port = htons(atoi(optarg));
      break;
    case 'r' :
      force_renegotiation_info = 1;
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    default:
      usage(argv[0], dtls_package_version());
      exit(1);
    }
  }
  if (argc != optind) {
    dtls_warn("no arguments supported!\n");
    usage(argv[0], dtls_package_version());
    exit(1);
  }
  listen_addr.sin6_port = port;

  dtls_set_log_level(log_level);

  /* init socket and set it to non-blocking */
  fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

  if (fd < 0) {
    dtls_alert("socket: %s\n", strerror(errno));
    return 0;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dtls_alert("setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }
#if 0
  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    dtls_alert("fcntl: %s\n", strerror(errno));
    goto error;
  }
#endif
  on = 1;
  if (listen_addr.sin6_family == AF_INET6) {
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) < 0) {
      dtls_alert("setsockopt IPV6_V6ONLY: %s\n", strerror(errno));
    }
#ifdef IPV6_RECVPKTINFO
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IPV6_RECVPKTINFO */
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
#endif /* IPV6_RECVPKTINFO */
      dtls_alert("setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
    }
  }
  if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
    dtls_alert("setsockopt IP_PKTINFO: %s\n", strerror(errno));
  }

  if (bind(fd, (struct sockaddr *)&listen_addr,
           listen_addr.sin6_family == AF_INET ? sizeof(struct sockaddr_in) :
                                                sizeof(listen_addr)) < 0) {
    dtls_alert("bind: %s\n", strerror(errno));
    goto error;
  }

  dtls_init();

#ifndef IS_WINDOWS
  memset (&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = dtls_handle_signal;
  sa.sa_flags = 0;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  /* So we do not exit on a SIGPIPE */
  sa.sa_handler = SIG_IGN;
  sigaction (SIGPIPE, &sa, NULL);
#endif /* ! IS_WINDOWS */

  the_context = dtls_new_context(&fd);

  dtls_set_handler(the_context, &cb);

  while (!quit) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    FD_SET(fd, &rfds);
    /* FD_SET(fd, &wfds); */

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    result = select( fd+1, &rfds, &wfds, 0, &timeout);

    if (result < 0) {
      /* error */
      if (errno != EINTR)
        perror("select");
    } else if (result == 0) {
      /* timeout */
    } else {
      /* ok */
      if (FD_ISSET(fd, &wfds))
        /* FIXME */;
      else if (FD_ISSET(fd, &rfds)) {
        dtls_handle_read(the_context);
        if (cmd_exit) {
          break;
        }
      }
    }
  }

error:
  dtls_free_context(the_context);
  exit(0);
}
