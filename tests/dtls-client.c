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

#include "tinydtls.h"

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
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "global.h"
#include "dtls_debug.h"
#include "dtls_ciphers_util.h"
#include "dtls.h"

#define DEFAULT_PORT 20220

#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#define PSK_OPTIONS          "i:k:"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

#ifndef NI_MAXSERV
/* Set a default value for NI_MAXSERV in case it does not get defined
 * by netdb.h */
#define NI_MAXSERV 32
#endif

typedef struct {
  size_t length;               /* length of string */
  unsigned char *s;            /* string data */
} dtls_str;

static dtls_str output_file = { 0, NULL }; /* output file name */

static dtls_context_t *dtls_context = NULL;
static dtls_context_t *orig_dtls_context = NULL;

static const dtls_cipher_t* ciphers = NULL;
static unsigned int force_extended_master_secret = 0;
static unsigned int force_renegotiation_info = 0;
#if (DTLS_MAX_CID_LENGTH > 0)
static unsigned int support_cid = 0;
#endif

#ifdef DTLS_ECC
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
#endif /* DTLS_ECC */

#ifdef DTLS_PSK
static ssize_t
read_from_file(char *arg, unsigned char *buf, size_t max_buf_len) {
  FILE *f;
  ssize_t result = 0;

  f = fopen(arg, "r");
  if (f == NULL)
    return -1;

  while (!feof(f)) {
    size_t bytes_read;
    bytes_read = fread(buf, 1, max_buf_len, f);
    if (ferror(f)) {
      result = -1;
      break;
    }

    buf += bytes_read;
    result += bytes_read;
    max_buf_len -= bytes_read;
  }

  fclose(f);
  return result;
}

/* The PSK information for DTLS */
#define PSK_ID_MAXLEN 256
#define PSK_MAXLEN 256
static unsigned char psk_id[PSK_ID_MAXLEN];
static size_t psk_id_length = 0;
static unsigned char psk_key[PSK_MAXLEN];
static size_t psk_key_length = 0;

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx UNUSED_PARAM,
             const session_t *session UNUSED_PARAM,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length) {

  switch (type) {
  case DTLS_PSK_IDENTITY:
    if (id_len) {
      dtls_debug("got psk_identity_hint: '%.*s'\n", (int)id_len, id);
    }

    if (result_length < psk_id_length) {
      dtls_warn("cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_id, psk_id_length);
    return psk_id_length;
  case DTLS_PSK_KEY:
    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
      dtls_warn("PSK for unknown id requested, exiting\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    } else if (result_length < psk_key_length) {
      dtls_warn("cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_key, psk_key_length);
    return psk_key_length;
  case DTLS_PSK_HINT:
  default:
    dtls_warn("unsupported request type: %d\n", type);
  }

  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
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

static void
try_send(struct dtls_context_t *ctx, session_t *dst, size_t len, char *buf) {
  int res;
  res = dtls_write(ctx, dst, (uint8 *)buf, len);
  if (res >= 0) {
    memmove(buf, buf + res, len - res);
    len -= res;
  }
}

static void
handle_stdin(size_t *len, char *buf, size_t buf_len) {
  if (fgets(buf + *len, buf_len - *len, stdin))
    *len += strlen(buf + *len);
}

static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8 *data, size_t len) {
  (void)ctx;
  (void)session;

  if (write(STDOUT_FILENO, data, len) == -1)
    dtls_debug("write failed: %s\n", strerror(errno));

  return 0;
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
#if (DTLS_MAX_CID_LENGTH > 0)
  user_parameters->support_cid = support_cid;
#endif
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
  len = recvfrom(fd, buf, MAX_READ_BUF, MSG_TRUNC,
                 &session.addr.sa, &session.size);

  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "peer", &session);
    if (len <= MAX_READ_BUF) {
      dtls_debug_dump("bytes from peer", buf, len);
    } else {
      dtls_debug_dump("bytes from peer", buf, MAX_READ_BUF);
      dtls_warn("%d bytes exceeds buffer %d, drop message!", len, MAX_READ_BUF);
      return -1;
    }
  }

  return dtls_handle_message(ctx, &session, buf, len);
}

static void
dtls_handle_signal(int sig) {
  dtls_free_context(dtls_context);
  dtls_free_context(orig_dtls_context);
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}

/* stolen from libcoap: */
static int
resolve_address(const char *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error, result;

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

  result = -1;
  for (ainfo = res; (result == -1) && (ainfo != NULL); ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:

      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
      result = ainfo->ai_addrlen;
      break;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return result;
}

/*---------------------------------------------------------------------------*/
static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf(stderr, "%s v%s -- DTLS client implementation\n"
          "(c) 2011-2024 Olaf Bergmann <bergmann@tzi.org>\n\n"
          "usage: %s [-c cipher suites] [-e] "
#ifdef DTLS_PSK
          "[-i file] [-k file] [-o file]\n"
          "       %*s [-p port] [-r] [-v num]"
#else /*  DTLS_PSK */
          "[-o file] [-p port] [-r]\n"
          "       %*s [-v num]"
#endif /* DTLS_PSK */
#if (DTLS_MAX_CID_LENGTH > 0)
          " [-z]"
#endif /* DTLS_MAX_CID_LENGTH > 0*/
          " addr [port]\n",
          program, version, program, (int)strlen(program), "");
  cipher_suites_usage(stderr, "\t");
  fprintf(stderr, "\t-e\t\tforce extended master secret (RFC7627)\n"
#ifdef DTLS_PSK
          "\t-i file\t\tread PSK identity from file\n"
          "\t-k file\t\tread pre-shared key from file\n"
#endif /* DTLS_PSK */
          "\t-o file\t\toutput received data to this file\n"
          "\t       \t\t(use '-' for STDOUT)\n"
          "\t-p port\t\tlisten on specified port\n"
          "\t       \t\t(default is an ephemeral free port).\n"
          "\t-r\t\tforce renegotiation info (RFC5746)\n"
          "\t-v num\t\tverbosity level (default: 3)\n"
#if (DTLS_MAX_CID_LENGTH > 0)
          "\t-z\t\tsupport CID (RFC9146)\n"
#endif /* DTLS_MAX_CID_LENGTH > 0*/
          "\tDefault destination port: %d\n",
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

#define DTLS_CLIENT_CMD_CLOSE "client:close"

/* As per RFC 6347 section 4.2.8, DTLS Server should support requests
 * from clients who have silently abandoned the existing association
 * and initiated a new handshake request by sending a ClientHello.
 * Below command tests this feature.
 */
#define DTLS_CLIENT_CMD_REHANDSHAKE "client:rehandshake"

#define DTLS_CLIENT_CMD_EXIT "client:exit"

int 
main(int argc, char **argv) {
  fd_set rfds, wfds;
  struct timeval timeout;
  unsigned short dst_port = 0;
  unsigned short local_port = 0;
  log_t log_level = DTLS_LOG_WARN;
  int fd;
  ssize_t result;
  int on = 1;
  int opt, res;
  session_t dst;
  session_t listen;
  char buf[200];
  size_t len = 0;
  int buf_ready = 0;

  memset(&dst, 0, sizeof(session_t));
  memset(&listen, 0, sizeof(session_t));

  dtls_init();

#ifdef DTLS_PSK
  psk_id_length = strlen(PSK_DEFAULT_IDENTITY);
  psk_key_length = strlen(PSK_DEFAULT_KEY);
  memcpy(psk_id, PSK_DEFAULT_IDENTITY, psk_id_length);
  memcpy(psk_key, PSK_DEFAULT_KEY, psk_key_length);
#endif /* DTLS_PSK */

  while (optind < argc) {
    opt = getopt(argc, argv, "c:eo:p:rv:z" PSK_OPTIONS);
    switch (opt) {
#ifdef DTLS_PSK
    case 'i' :
      result = read_from_file(optarg, psk_id, PSK_ID_MAXLEN);
      if (result < 0) {
        dtls_warn("cannot read PSK identity\n");
      } else {
        psk_id_length = result;
      }
      break;
    case 'k' :
      result = read_from_file(optarg, psk_key, PSK_MAXLEN);
      if (result < 0) {
        dtls_warn("cannot read PSK\n");
      } else {
        psk_key_length = result;
      }
      break;
#endif /* DTLS_PSK */
    case 'c' :
      ciphers = init_cipher_suites(optarg);
      break;
    case 'e' :
      force_extended_master_secret = 1;
      break;
    case 'o' :
      output_file.length = strlen(optarg);
      output_file.s = (unsigned char *)malloc(output_file.length + 1);

      if (!output_file.s) {
        dtls_crit("cannot set output file: insufficient memory\n");
        exit(-1);
      } else {
        /* copy filename including trailing zero */
        memcpy(output_file.s, optarg, output_file.length + 1);
      }
      break;
    case 'p' :
      local_port = atoi(optarg);
      break;
    case 'r' :
      force_renegotiation_info = 1;
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
#if (DTLS_MAX_CID_LENGTH > 0)
    case 'z' :
      support_cid = 1;
      break;
#endif /* DTLS_MAX_CID_LENGTH > 0*/
    case -1 :
      /* handle arguments */
      if (!dst.size) {
        /* first argument: destination address */
        /* resolve destination address of server where data should be sent */
        res = resolve_address(argv[optind++], &dst.addr.sa);
        if (res < 0) {
          dtls_emerg("failed to resolve address\n");
          exit(-1);
        }
        dst.size = res;
      } else if (!dst_port) {
        /* second argument: destination port (optional) */
        dst_port = atoi(argv[optind++]);
      } else {
        dtls_warn("too many arguments!\n");
        usage(argv[0], dtls_package_version());
        exit(1);
      }
      break;
    default:
      usage(argv[0], dtls_package_version());
      exit(1);
    }
  }

  if (!dst.size) {
    dtls_warn("missing destination address!\n");
    usage(argv[0], dtls_package_version());
    exit(1);
  }
  if (!dst_port) {
    /* destination port not provided, use default */
    dst_port = DEFAULT_PORT;
  }
  if (dst.addr.sa.sa_family == AF_INET6) {
    dst.addr.sin6.sin6_port = htons(dst_port);
  } else {
    dst.addr.sin.sin_port = htons(dst_port);
  }

  dtls_set_log_level(log_level);

  /* init socket and set it to non-blocking */
  fd = socket(dst.addr.sa.sa_family, SOCK_DGRAM, 0);

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
  if (dst.addr.sa.sa_family == AF_INET6) {
#ifdef IPV6_RECVPKTINFO
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IPV6_RECVPKTINFO */
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
#endif /* IPV6_RECVPKTINFO */
      dtls_alert("setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
    }
  }
  else {
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on) ) < 0) {
      dtls_alert("setsockopt IP_PKTINFO: %s\n", strerror(errno));
    }
  }

  if (local_port) {
    listen.addr = dst.addr;
    listen.size = dst.size;
    if (listen.addr.sa.sa_family == AF_INET6) {
      listen.addr.sin6.sin6_addr = in6addr_any;
      listen.addr.sin6.sin6_port = htons(local_port);
      dtls_info("bind to local IPv6, port %u\n", local_port);
    } else {
      listen.addr.sin.sin_addr.s_addr = INADDR_ANY;
      listen.addr.sin.sin_port = htons(local_port);
      dtls_info("bind to local IPv4, port %u\n", local_port);
    }
    if (bind(fd, (struct sockaddr *)&listen.addr.sa, listen.size) < 0) {
      dtls_alert("bind: %s\n", strerror(errno));
      return EXIT_FAILURE;
    }
  }

  if (signal(SIGINT, dtls_handle_signal) == SIG_ERR) {
    dtls_alert("An error occurred while setting a signal handler.\n");
    return EXIT_FAILURE;
  }

  dtls_context = dtls_new_context(&fd);
  if (!dtls_context) {
    dtls_emerg("cannot create context\n");
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
      else if (FD_ISSET(fd, &rfds))
        dtls_handle_read(dtls_context);
      else if (FD_ISSET(fileno(stdin), &rfds)) {
        handle_stdin(&len, buf, sizeof(buf));
        if (len && buf[len - 1] == '\n') {
          buf_ready = 1;
        }
      }
    }

    if (buf_ready) {
      buf_ready = 0;
      if (strstr(buf, DTLS_CLIENT_CMD_CLOSE) == buf) {
        printf("client: closing connection\n");
        dtls_close(dtls_context, &dst);
      } else if (strstr(buf, DTLS_CLIENT_CMD_EXIT) == buf) {
        printf("client: exit\n");
        break;
      } else if (strstr(buf, DTLS_CLIENT_CMD_REHANDSHAKE) == buf) {
        printf("client: rehandshake connection\n");
        if (orig_dtls_context == NULL) {
          /* Cache the current context. We cannot free the current context as it will notify
           * the Server to close the connection (which we do not want).
           */
          orig_dtls_context = dtls_context;
          /* Now, Create a new context and attempt to initiate a handshake. */
          dtls_context = dtls_new_context(&fd);
          if (!dtls_context) {
            dtls_emerg("cannot create context\n");
            exit(-1);
          }
          dtls_set_handler(dtls_context, &cb);
          dtls_connect(dtls_context, &dst);
        }
      } else {
        try_send(dtls_context, &dst, len, buf);
      }
      len = 0;
    }
  }

  dtls_free_context(dtls_context);
  dtls_free_context(orig_dtls_context);
  exit(0);
}
