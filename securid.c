/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2010 Intel Corporation.
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */

#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "openconnect.h"

int add_securid_pin(char *token, char *pin)
{
	int i;

	/* If PIN longer than original token, move token up to cope */
	if (strlen(pin) > strlen(token)) {
		int extend = strlen(token) - strlen(pin);
		memmove(token, token + extend, strlen(token)+1);
		for (i=0; i<extend; i++)
			token[i] = '0';
	}
	token += strlen(token) - strlen(pin);

	for (i=0; token[i]; i++) {
		if (!isdigit(token[i]) || !isdigit(pin[i]))
			return -EINVAL;

		token[i] += pin[i] - '0';
		if (token[i] > '9')
			token[i] -= 10;
	}
	return 0;
}

int generate_securid_tokencodes(struct openconnect_info *vpninfo)
{
	/* FIXME: Script the Windows or Java binaries to get the current
	   and next tokens, and put them in vpninfo->sid_tokencode and
	   vpninfo->sid_nexttokencode. This dirty hack is just for testing. */
	static int got_from_env = 0;

	if (!got_from_env) {
		char *t1, *t2;

		got_from_env = 1;

		t1 = getenv("SID_TOKEN1");
		t2 = getenv("SID_TOKEN2");

		if (t1 && t2) {
			strncpy(vpninfo->sid_tokencode, t1, 8);
			strncpy(vpninfo->sid_nexttokencode, t2, 8);
			return 0;
		}
	}
	return -EINVAL;
}
