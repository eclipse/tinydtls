/*
 * hmac.c
 *
 * Version 1.0.0
 *
 * Written by Aaron D. Gifford <me@aarongifford.com>
 *
 * Copyright 1998, 2000 Aaron D. Gifford.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This is a simple command-line program to compute HMAC-SHA-1 for a
 * message using key.  It's used like this:
 *
 *     ./hmac <key-file> [<mesage-file>]
 *   OR
 *     ./hmac -k <key-data> [<message-file>]
 *
 * If the message file is not specified, the program reads
 * from standard input.  The key data can either be read
 * from the specified file, or from the command line.
 *
 * Compiles and works on my FreeBSD 4.0 system using:
 *
 *   cc -o hmac hmac.c hmac_sha1.c sha1.c
 *
 * Or if you don't wish to use Steve Reid's public domain implementation
 * of SHA1 and your machine has SHA1 available in a library, you can edit
 * hmac_sha1.h and make sure it includes the appropriate header, then do
 * something like this (which also works on my FreeBSD system which includes
 * Eric A. Young's SSH1 implementation in libmd):
 *
 *   cc -o hmac hmac.c hmac_sha1.c -lmd
 *
 *
 * Examples: (these work for me on my FreeBSD machine)
 *
 *   echo -n 'what do ya want for nothing?' | ./hmac -k Jefe
 *
 * This SHOULD give the result RFC 2202 says you should get
 * for HMAC-SHA-1 test case #3:
 *
 *   0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79
 *
 * Another test vector, test case #7 can be reproduced thus:
 *
 *   echo -n 'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data' | ./hmac -k `perl -e 'print pack("C",0xaa) x 80;'`
 *
 * Which SHOULD give:
 *
 *   0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91
 *
 * Here are all the HMAC-SHA1 test cases from RFC 2202:
 *
 * 1)
 *    key =       0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
 *    key_len =   20
 *    data =      "Hi There"
 *    data_len =  8
 *    digest =    0xb617318655057264e28bc0b6fb378c8ef146be00
 *
 * 2)
 *    key =       "Jefe"
 *    key_len =   4
 *    data =      "what do ya want for nothing?"
 *    data_len =  28
 *    digest =    0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79
 *
 * 3)
 *    key =       0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *    key_len =   20
 *    data =      0xdd repeated 50 times
 *    data_len =  50
 *    digest =    0x125d7342b9ac11cd91a39af48aa17b4f63f175d3
 *
 * 4)
 *    key =       0x0102030405060708090a0b0c0d0e0f10111213141516171819
 *    key_len =   25
 *    data =      0xcd repeated 50 times
 *    data_len =  50
 *    digest =    0x4c9007f4026250c6bc8414f9bf50c86c2d7235da
 *
 * 5)
 *    key =       0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
 *    key_len =   20
 *    data =      "Test With Truncation"
 *    data_len =  20
 *    digest =    0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04
 *    digest-96 = 0x4c1a03424b55e07fe7f27be1
 *
 * 6)
 *    key =       0xaa repeated 80 times
 *    key_len =   80
 *    data =      "Test Using Larger Than Block-Size Key - Hash Key First"
 *    data_len =  54
 *    digest =    0xaa4ae5e15272d00e95705637ce8a3b55ed402112
 *
 * 7)
 *    key =       0xaa repeated 80 times
 *    key_len =   80
 *    data =      "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
 *    data_len =  73
 *    digest =    0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91
 *
 */

#include <stdio.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "hmac_sha1.h"

void usage(char *prog) {
	fprintf(stderr, "Usage:\n\t%s <key-file> [<message-file>]\n\tOR\n\t%s -k <key-data> [<message-file>]\n\n", prog, prog);
	exit(EX_USAGE);
}

void hexout(unsigned char *data, int datalen) {

	printf("0x");
	while (datalen-- > 0)
		printf("%02x",(unsigned char)*data++);
	printf("\n");
}

#define BUFLEN 4096

int main(int argc, char **argv) {
	int		kl, l, fd, i;
	FILE		*IN;
	HMAC_SHA1_CTX	ctx;
	unsigned char	buf[BUFLEN];

	HMAC_SHA1_Init(&ctx);
	if (argc < 2 || argc > 4)
		usage(argv[0]);
	if (*argv[1] == '-') {
		if (*(argv[1]+1) != 'k' || (*(argv[1]+1) != '\0' && *(argv[1]+2)))
			usage(argv[0]);
		if (argc < 3)
			usage(argv[0]);
		if (strlen(argv[2]) < 1)
			fprintf(stderr, "%s: WARNING: Key contains no data.  Using null key anyway.\n", argv[0]);
		HMAC_SHA1_UpdateKey(&ctx, argv[2], strlen(argv[2]));
		HMAC_SHA1_EndKey(&ctx);
		i = 3;
	} else {
		if ((IN = fopen(argv[1], "r")) == NULL) {
			perror(argv[0]);
			exit(EX_NOINPUT);
		}
		fd = fileno(IN);
		kl = 0;
		while ((l = read(fd,buf,BUFLEN)) > 0) {
			kl += l;
			HMAC_SHA1_UpdateKey(&ctx, buf, l);
		}
		fclose(IN);
		if (kl == 0)
			fprintf(stderr, "%s: WARNING: File %s contained no key data.  Using null key anyway.\n", argv[0], argv[1]);
		HMAC_SHA1_EndKey(&ctx);
		i = 2;
	}
	
	if (argc == i) {
		/* Read data from STDIN */
		fd = fileno(stdin);
	} else if (argc == (i + 1)) {
		/* Read data from FILE */
		if ((IN = fopen(argv[i], "r")) == NULL) {
			perror(argv[0]);
			exit(EX_NOINPUT);
		}
		fd = fileno(IN);
	} else {
		usage(argv[0]);
	}
	HMAC_SHA1_StartMessage(&ctx);
	kl = 0;
	while ((l = read(fd,buf,BUFLEN)) > 0) {
		kl += l;
		HMAC_SHA1_UpdateMessage(&ctx, buf, l);
	}
	if (argc == (i + 1))
		fclose(IN);
	HMAC_SHA1_EndMessage(buf, &ctx);
	hexout(buf, HMAC_SHA1_DIGEST_LENGTH);

	return 1;
}
