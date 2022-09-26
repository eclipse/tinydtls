/************************************************************************/
/* LwIP-specific parameters                                             */
/************************************************************************/


#ifndef _LWIP_PLATFORM_
#define _LWIP_PLATFORM_

/*
 * SETTING FOR TINYDTLS OVER LWIP
 * In standard installation of TinyDTLS they are at dtls_config.h
 * Only those used by the main library (not test/ or test* files) are here.
 */

#include <lwip/opt.h>
#if ! LWIP_SOCKET
#define WITH_LWIP_NO_SOCKET
#endif /* ! LWIP_SOCKET */

#ifndef DTLS_ECC
#define DTLS_ECC
#endif /* DTLS_ECC */

#ifndef DTLS_PSK
#define DTLS_PSK
#endif /* DTLS_PSK */

/* LwIP supports  <assert.h> header file.  */
#define HAVE_ASSERT_H 1

/* LwIP supports  <inttypes.h> header file.  */
#define HAVE_INTTYPES_H 1

/* LwIP supports the member sin6_len */
#define HAVE_SOCKADDR_IN6_SIN6_LEN 1

/* LwIP supports the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* LwIP supports the <time.h> header file. */
#define HAVE_TIME_H 1

/* LwIP has partial support for the `vprintf' function. */
/* DANGER Removing bring issues with dtls_debug.h and dtls_debug.c */
#define HAVE_VPRINTF 1


/*
 * INFORMATION ABOUT TINYDTLS
 * NOTE: This is used mostly by dtls_debug
 */

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "tinydtls"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "tinydtls 0.8.6"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "tinydtls"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.8.6"



/** do not use uthash's hash tables (the tables uses malloc/free) */
#define DTLS_PEERS_NOHASH 1

/*
 * INFORMATION SHA2/ LIBRARY VARIABLES
 *
 * TODO: Clarify the way LwIP identifies BYTE_ORDER
 */

/*
 * LwIP supports the  <inttypes.h> header file.
 * NOTE: uintXX_t definitions with the ANSI C headers instead of custom typedef
 */
#define SHA2_USE_INTTYPES_H 1

/* LwIP "supports" memset()/memcpy() BUT not bzero()/mcopy(). */
#define SHA2_USE_MEMSET_MEMCPY 1


/*
 * NOTE Gcc is who define if we are big endian or little endian.
 * Because LwIP has __BYTE_ORDER__ and BYTE_ORDER it is not clear which one
 * should take preference here. Or, if the #define inside of sha2/sha2.h
 * should be removed at all.
 */
#ifndef BIG_ENDIAN
#if !defined(__BIG_ENDIAN__)
#    define BIG_ENDIAN    4321
#  else
#    define BIG_ENDIAN    __BIG_ENDIAN__
#  endif
#endif

#ifndef LITTLE_ENDIAN
#if !defined(__LITTLE_ENDIAN__)
#    define LITTLE_ENDIAN    1234
#  else
#    define LITTLE_ENDIAN    __LITTLE_ENDIAN__
#  endif
#endif

#endif /* _LWIP_PLATFORM_ */
