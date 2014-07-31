/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
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

#include <iconv.h>
#include <errno.h>
#include <string.h>

#include "openconnect-internal.h"

static char *convert_str(struct openconnect_info *vpninfo, iconv_t ic,
			 char *instr)

{
	char *ic_in, *ic_out, *outstr;
	size_t insize, outsize;
	int addq = 0;

	if (ic == (iconv_t)-1)
		return instr;

	iconv(ic, NULL, NULL, NULL, NULL);

	insize = strlen(instr) + 1;
	ic_in = instr;

	outsize = insize;
	ic_out = outstr = malloc(outsize);
	if (!outstr)
		return instr;

	while (insize) {
		if (iconv(ic, &ic_in, &insize, &ic_out, &outsize) == (size_t)-1) {
			perror("iconv");
			if (errno == EILSEQ) {
				do {
					ic_in++;
					insize--;
				} while (insize && (ic_in[0] & 0xc0) == 0x80);
				addq = 1;
			}

			if (!outsize || errno == E2BIG) {
				int outlen = ic_out - outstr;
				realloc_inplace(outstr, outlen + 10);
				if (!outstr)
					return instr;
				ic_out = outstr + outlen;
				outsize = 10;
			} else if (errno != EILSEQ) {
				/* Should never happen */
				free(outstr);
				return instr;
			}
			if (addq) {
				addq = 0;
				*(ic_out++) = '?';
				outsize--;
			}
		}
	}

	return outstr;
}

char *openconnect_legacy_to_utf8(struct openconnect_info *vpninfo,
				 const char *legacy)
{
	return convert_str(vpninfo, vpninfo->ic_legacy_to_utf8, (char *)legacy);
}

char *openconnect_utf8_to_legacy(struct openconnect_info *vpninfo,
				 const char *utf8)
{
	return convert_str(vpninfo, vpninfo->ic_utf8_to_legacy, (char *)utf8);
}
