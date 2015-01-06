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
#include <string.h>
#include <stdint.h>

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

static inline int find_match_len(const unsigned char *buf, int potential, int pos, int min, int max)
{
	if (memcmp(buf + potential, buf + pos, min))
		return 0;

	while (min < max && buf[potential + min] == buf[pos + min])
		min++;

	return min;
}

#define PUT_BITS(nr, bits)					\
do {								\
	outbits <<= (nr);					\
	outbits |= (bits);					\
	nr_outbits += (nr);					\
	while (nr_outbits >= 8) {				\
		nr_outbits -= 8;				\
		dst[outpos++] = outbits >> nr_outbits;		\
		if (outpos >= dstlen)				\
			return -EFBIG;				\
	}							\
} while (0)

/*
 * Much of the compression algorithm used here is based very loosely on ideas
 * from isdn_lzscomp.c by Andre Beck: http://micky.ibh.de/~beck/stuff/lzs4i4l/
 */
struct lzs_state {
	/*
	 * Each pair of bytes from the input is hashed into a hash value of
	 * size HASH_BITS (currently 12 bits). We could use 16 bits and stop
	 * calling it a hash, I suppose, since RAM is cheap these days.
	 */
#define HASH_BITS 12
#define HASH_TABLE_SIZE (1ULL << HASH_BITS)
#define HASH(p) ((p)[0] << (HASH_BITS - 8) ^ (p)[1])

	/*
	 * There are two data structures for tracking the history. The first
	 * is the true hash table, an array indexed by the hash value described
	 * above. It yields the offset in the input buffer at which the given
	 * hash was most recently seen. We use INVALID_OFS (0xffff) for none
	 * since we know IP packets are limited to 64KiB and we can never be
	 * *starting* a match at the penultimate byte of the packet.
	 */
#define INVALID_OFS 0xffffffff
	uint32_t hash_table[HASH_TABLE_SIZE]; /* Buffer offset for first match */

	/*
	 * The second data structure allows us to find the previous occurrences
	 * of the same hash value. It is a ring buffer containing links only for
	 * the latest MAX_HISTORY bytes of the input. The lookup for a given
	 * offset will yield the previous offset at which the same data hash
	 * value was found.
	 */
#define MAX_HISTORY (1ULL<<11) /* Highest offset LZS can represent is 11 bits */
	uint32_t hash_chain[MAX_HISTORY];
	uint32_t virt_ofs;

};

struct lzs_state *alloc_lzs_state(void)
{
	struct lzs_state *lzs = malloc(sizeof(*lzs));
	if (!lzs)
		return NULL;

	lzs->virt_ofs = 0;

	return lzs;
}

int lzs_compress(struct lzs_state *lzs, unsigned char *dst, int dstlen,
		 const unsigned char *src, int srclen)
{
	int inpos = 0;
	uint32_t match_len;
	uint32_t hash;
	uint32_t hofs, longest_match_len, longest_match_ofs;
	int outpos = 0;
	uint32_t outbits = 0;
	int nr_outbits = 0;
	uint32_t pkt_ofs;

	/* Just in case anyone tries to use this in a more general-purpose
	 * scenario... */
	if (srclen > 0x10000)
		return -EFBIG;

	if (!lzs->virt_ofs) {
		memset(lzs->hash_table, 0xff, sizeof(lzs->hash_table));
		memset(lzs->hash_chain, 0xff, sizeof(lzs->hash_chain));
	}
	pkt_ofs = lzs->virt_ofs;

	/* Ensure the next packet cannot see any of our history. */
	lzs->virt_ofs += (srclen + MAX_HISTORY + MAX_HISTORY - 1) & ~(MAX_HISTORY - 1);

	while (inpos < srclen - 1) {
		hash = HASH(src + inpos);
		hofs = lzs->hash_table[hash];

		longest_match_len = 0;

		/* For a given 32-bit virtual offset to be reasonable, it must
		   actually fall within the range of the packet that we've seen so
		   far (i.e. pkt_ofs to pkt_ofs + inpos - 1). It must also not be
		   further behind pkt_ofs + inpos than MAX_HISTORY */
		while (hofs != INVALID_OFS && hofs < pkt_ofs + inpos && hofs >= pkt_ofs &&
		       hofs + MAX_HISTORY > pkt_ofs + inpos) {
			match_len = find_match_len(src, hofs - pkt_ofs, inpos,
						   longest_match_len ? : 2, srclen - inpos);
			if (match_len > longest_match_len) {
				longest_match_len = match_len;
				longest_match_ofs = hofs - pkt_ofs;
			}
			/* Sanity check to prevent looping — we should always be
			 * working *backwards* */
			if (lzs->hash_chain[hofs & (MAX_HISTORY - 1)] >= hofs)
				break;
			hofs = lzs->hash_chain[hofs & (MAX_HISTORY - 1)];
		}
		if (longest_match_len) {
			/* Output offset, as 7-bit or 11-bit as appropriate */
			int offset = inpos - longest_match_ofs;
			int length = longest_match_len;

			if (offset < 0x80) {
				PUT_BITS(2, 3);
				PUT_BITS(7, offset);
			} else {
				PUT_BITS(2, 2);
				PUT_BITS(11, offset);
			}
			/* Output length */
			if (length < 5)
				PUT_BITS(2, length - 2);
			else if (length < 8)
				PUT_BITS(4, length + 7);
			else {
				length += 7;
				while (length >= 15) {
					PUT_BITS(4, 15);
					length -= 15;
				}
				PUT_BITS(4, length);
			}
		} else {
			PUT_BITS(9, src[inpos]);
			longest_match_len = 1;
		}

		/* Add byte(s) to the hash tables unless we're done */
		if (inpos + longest_match_len >= srclen - 1) {
			inpos += longest_match_len;
			break;
		}

		while (longest_match_len--) {
			hash = HASH(src + inpos);
			lzs->hash_chain[inpos & (MAX_HISTORY - 1)] = lzs->hash_table[hash];
			lzs->hash_table[hash] = pkt_ofs + inpos++;
		}
	}
	if (inpos < srclen)
		PUT_BITS(9, src[inpos]);

	/* End marker */
	PUT_BITS(9, 0x180);
	/* ... which must have its final bits flushed to the output. */
	PUT_BITS(7, 0);

	return outpos;
}
