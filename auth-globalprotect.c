/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Author: Dan Lenski <dlenski@gmail.com>
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

void gpst_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	http_common_headers(vpninfo, buf);

	buf_append(buf, "Connection: Keep-Alive\r\n");
	buf_append(buf, "User-Agent: PAN GlobalProtect\r\n");
}

int gpst_obtain_cookie(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
	             _("Auth support for PAN GlobalProtect not yet implemented\n"));
	return -EINVAL;
}
