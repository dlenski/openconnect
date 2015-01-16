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
