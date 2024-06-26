# About tinydtls

tinydtls is a library for Datagram Transport Layer Security (DTLS 1.2 
[RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)) covering both the client
and the server state machine. It is implemented in C and provides support
for a minimal set of cipher suites suitable for the Internet of Things.

This library contains functions and structures that can help
constructing a single-threaded UDP server with DTLS support in
C99. The following components are available:

* dtls
  Basic support for DTLS with pre-shared key mode and RPK mode with ECC.

* tests
  The subdirectory tests contains test programs that show how each
  component is used.

# BUILDING

tinydtls supports multiple platforms, including both Real-time
and general-purpose Operating Systems. Below you find build instructions for
all supported environments.

## POSIX-oriented Operating Systems

When using the code from the git
[repository](https://github.com/eclipse/tinydtls) at GitHub, invoke

    $ ./autogen.sh
    $ ./configure

to re-create the configure script.

## Contiki

On Contiki, place the tinydtls library into the apps folder. After
configuration, invoke make to build the library and associated test
programs. To add tinydtls as Contiki application, drop it into the
apps directory and add the following line to your Makefile:

    APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls

## RIOT

On RIOT, you need to add the line `USEPKG += tinydtls`.
You can use `RIOT/examples/dtls-echo/` as a guide for integrating tinyDTLS
to your application.

Also, if you need a specific commit of tinyDTLS you can modify
`RIOT/pkg/tinydtls/Makefile`.

## CMake

The current cmake support is experimental. Don't hesitate to report issues
and/or provided fixes for it. For general and more details on using CMake,
please consider [CMake - help](https://cmake.org/cmake/help/latest/index.html).

Usage:

```
mkdir tinydtls_build
cd tinydtls_build
cmake -Dmake_tests=ON <path-to-tinydtls>
cmake --build .
```

Available options:

| Option | Description | Default |
| ------ | ----------- | ------- |
| BUILD_SHARED_LIBS | build shared libraries instead of static link library | OFF |
| make_tests | build tests including the examples | OFF |
| DTLS_ECC | enable/disable ECDHE_ECDSA cipher suites | ON |
| DTLS_PSK | enable/disable PSK cipher suites | ON |

## Windows

Using CMake, you can also build on and for Windows using either GCC or Visual
Studio.
Note, however, that the `make_tests` option is currently not supported when
compiling with Visual Studio, as parts of the tests rely on POSIX APIs.

For Visual Studio, you can apply the CMake instructions outlined above from the
command line or use the CMake GUI application.

In order to be able to use GCC, you need to specify a different generator than
the default.
For instance, you can use the `Unix Makefiles` generator, which creates a
Makefile for controlling the build process using GCC.
The example below leads to the output of a shared library file
`libtinydtls.dll`.

```
cmake -G "Unix Makefiles" -DBUILD_SHARED_LIBS=ON .
make
```

Using MinGW64, you can also cross compile from a POSIX-oriented
platform for Windows using Autotools by providing a corresponding `--host`
argument:

```
./autogen.sh
./configure --host x86_64-w64-mingw32
make
mv libtinydtls.so libtinydtls.dll # Apply Windows file extension
```

# Implemented Cipher Suites

| Name | ID | RFC |
| ------ | ----------- | ------- |
| TLS_PSK_WITH_AES_128_CCM | 0xC0A4 | [RFC 6655](https://www.rfc-editor.org/rfc/rfc6655) |
| TLS_PSK_WITH_AES_128_CCM_8 | 0xC0A8 | [RFC 6655](https://www.rfc-editor.org/rfc/rfc6655) |
| TLS_ECDHE_ECDSA_WITH_AES_128_CCM | 0xC0AC | [RFC 7251](https://www.rfc-editor.org/rfc/rfc7251) |
| TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 | 0xC0AE | [RFC 7251](https://www.rfc-editor.org/rfc/rfc7251) |

# Supported TLS Extensions

| Name | RFC |
| ------ | ------- |
| Pre Shared Key (PSK) | [RFC 4279](https://www.rfc-editor.org/rfc/rfc4279) |
| TLS Renegotiation Indication (minimal version) | [RFC 5746](https://www.rfc-editor.org/rfc/rfc5746) |
| Raw Public Key (RPK) | [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250) |
| Extended Master Secret | [RFC 7627](https://www.rfc-editor.org/rfc/rfc7627) |
| DTLS 1.2 Connection ID (client only, feature branch) | [RFC 9146](https://www.rfc-editor.org/rfc/rfc9146) |

# License

Copyright (c) 2011–2022 Olaf Bergmann (TZI) and others.
All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v. 1.0 which accompanies this distribution.

The Eclipse Public License is available at
http://www.eclipse.org/legal/epl-v10.html and the Eclipse Distribution
License is available at
http://www.eclipse.org/org/documents/edl-v10.php.
