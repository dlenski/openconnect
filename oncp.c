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

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>

#include "openconnect-internal.h"

/* XX: This is actually a lot of duplication with the CSTP version. */
void oncp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	struct oc_vpn_option *opt;

	buf_append(buf, "Host: %s\r\n", vpninfo->hostname);
	buf_append(buf, "User-Agent: %s\r\n", vpninfo->useragent);
	buf_append(buf, "Accept: */*\r\n");
	buf_append(buf, "Accept-Encoding: identity\r\n");

	if (vpninfo->cookies) {
		buf_append(buf, "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			buf_append(buf, "%s=%s%s", opt->option,
				      opt->value, opt->next ? "; " : "\r\n");
	}
}

int oncp_obtain_cookie(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR, _("oNCP authentication not yet implemented\n"));
	return -EOPNOTSUPP;
}

int oncp_connect(struct openconnect_info *vpninfo)
{
	return 0;
}

int oncp_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	return 0;
}
