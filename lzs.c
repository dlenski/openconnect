/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
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

#include <config.h>

#include <errno.h>

#include "openconnect-internal.h"

#define GET_BITS(bits)							\
do {									\
	if (srclen < 1 + (bits_left < bits))				\
		return -EINVAL;						\
	/* Explicit comparison with 8 to optimise the bits == 9 case	\
	 * because the compiler doesn't know that bits_left can never	\
	 * be larger than 8. */						\
	if (bits >= 8 || bits >= bits_left) {				\
		/* We need *all* the bits that are left in the current	\
		 * byte. Take them and bump the input pointer. */	\
		data = (src[0] << (bits - bits_left)) & ((1ULL << bits) - 1); \
		src++;							\
		srclen--;						\
		bits_left += 8 - bits;					\
		if (bits > 8 || bits_left < 8) {			\
			/* We need bits from the next byte too... */	\
			data |= src[0] >> bits_left;			\
			/* ...if we used *all* of them then bump the	\
			 * input pointer again so we never leave	\
			 * bits_left == 0. */				\
			if (!bits_left) {				\
				bits_left = 8;				\
				src++;					\
				srclen--;				\
			}						\
		}							\
	} else {							\
		/* We need fewer bits than are left in the current byte */ \
		data = (src[0] >> (bits_left - bits)) & ((1ULL << bits) - 1); \
		bits_left -= bits;					\
	}								\
} while (0)

int lzs_decompress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen)
{
	int outlen = 0;
	int bits_left = 8; /* Bits left in the current byte at *src */
	int data;
	int offset, length;

	while (1) {
		/* Get 9 bits, which is the minimum and a common case */
		GET_BITS(9);

		/* 0bbbbbbbb is a literal byte */
		if (data < 0x100) {
			if (outlen == dstlen)
				return -EFBIG;
			dst[outlen++] = data;
			continue;
		}

		/* 110000000 is the end marker */
		if (data == 0x180)
			return outlen;

		/* 11bbbbbbb is a 7-bit offset */
		offset = data & 0x7f;

		/* 10bbbbbbbbbbb is an 11-bit offset, so get the next 4 bits */
		if (data < 0x180) {
			GET_BITS(4);

			offset <<= 4;
			offset |= data;
		}

		/* This is a compressed sequence; now get the length */
		GET_BITS(2);
		if (data != 3) {
			/* 00, 01, 10 ==> 2, 3, 4 */
			length = data + 2;
		} else {
			GET_BITS(2);
			if (data != 3) {
				/* 1100, 1101, 1110 => 5, 6, 7 */
				length = data + 5;
			} else {
				/* For each 1111 prefix add 15 to the length. Then add
				   the value of final nybble. */
				length = 8;

				while (1) {
					GET_BITS(4);
					if (data != 15) {
						length += data;
						break;
					}
					length += 15;
				}
			}
		}
		if (offset > outlen)
			return -EINVAL;
		if (length + outlen > dstlen)
			return -EFBIG;

		while (length) {
			dst[outlen] = dst[outlen - offset];
			outlen++;
			length--;
		}
	}
	return -EINVAL;
}
