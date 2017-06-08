/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2016 Intel Corporation.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/* Normally it's nice for header files to automatically include anything
 * they need. But winsock is a horrid can of worms; we 're not going to
 * make openconnect.h include anything for itself. So just do this... */
#ifdef _WIN32
#define SOCKET int
#endif

#include "../openconnect.h"

static void progress(void *privdata, int level, const char *fmt, ...)
{
	va_list args;

	if (level > PRG_ERR)
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

static int validate_peer_cert(void *_vpninfo, const char *reason)
{
	printf("%s\n", openconnect_get_peer_cert_hash(_vpninfo));
	exit(0);
}

/* We do this in a separate test tool because we *really* don't want
 * people scripting it to recover the --no-cert-check functionality.
 * Validate your server certs properly, people! */
int main(int argc, char **argv)
{
	struct openconnect_info *vpninfo;

	if (argc != 2) {
		fprintf(stderr, "usage: serverhash <server>\n");
		exit(1);
	}
	openconnect_init_ssl();
	vpninfo = openconnect_vpninfo_new(NULL, validate_peer_cert, NULL, NULL, progress, NULL);
	if (openconnect_parse_url(vpninfo, argv[1])) {
		fprintf(stderr, "Failed to parse URL\n");
		exit(1);
	}
	openconnect_set_system_trust(vpninfo, 0);
	openconnect_obtain_cookie(vpninfo);
	return -1;
}
