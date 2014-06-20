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

#include <errno.h>
#include <string.h>

#include "openconnect-internal.h"


int digest_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *hdrbuf)
{
	vpn_progress(vpninfo, PRG_INFO,
		     _("Attempting Digest authentication to proxy\n"));
	return -EIO;
}

void cleanup_digest_auth(struct openconnect_info *vpninfo)
{
}
