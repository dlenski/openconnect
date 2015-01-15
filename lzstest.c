/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#define __OPENCONNECT_INTERNAL_H__

int lzs_decompress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen);
int lzs_compress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen);

#include "lzs.c"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define NR_PKTS 2048
#define MAX_PKT 65536

int main(void)
{
	int i, j, ret;
	int pktlen;
	unsigned char pktbuf[MAX_PKT + 3];
	unsigned char comprbuf[MAX_PKT * 9 / 8 + 2];
	unsigned char uncomprbuf[MAX_PKT];

	srand(0xdeadbeef);

	/* Just because we're lazy and fill the buffer three bytes at a time. */
	if (RAND_MAX < 0x1000000) {
		fprintf(stderr, "RAND_MAX 0x%x is smaller than we expect\n", RAND_MAX);
		exit(1);
	}
		
	for (i = 0; i < NR_PKTS; i++) {
		if (i)
			pktlen = (random() % MAX_PKT) + 1;
		else
			pktlen = MAX_PKT;

		for (j = 0; j < pktlen; j+= 3) {
			int r = rand();
#if __BYTE_ORDER == __BIG_ENDIAN
			r <<= 8;
#endif
			*(int *)(pktbuf + j) = r;
		}		

		ret = lzs_compress(comprbuf, sizeof(comprbuf), pktbuf, pktlen);
		if (ret < 0) {
			fprintf(stderr, "Compressing packet %d failed: %s\n", i, strerror(-ret));
			exit(1);
		}
		ret = lzs_decompress(uncomprbuf, pktlen, comprbuf, sizeof(comprbuf));
		if (ret != pktlen) {
			fprintf(stderr, "Compressing packet %d failed\n", i);
			exit(1);
		}
		if (memcmp(uncomprbuf, pktbuf, pktlen)) {
			fprintf(stderr, "Comparing packet %d failed\n", i);
			exit(1);
		}
	}

	return 0;
}
