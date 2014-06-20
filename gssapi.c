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

static void print_gss_err(struct openconnect_info *vpninfo, OM_uint32 err_maj, OM_uint32 err_min)
{
	OM_uint32 major, minor, msg_ctx = 0;
	gss_buffer_desc status;

	do {
		major = gss_display_status(&minor, err_maj, GSS_C_GSS_CODE,
					   GSS_C_NO_OID, &msg_ctx, &status);
		if (GSS_ERROR(major))
			break;
		vpn_progress(vpninfo, PRG_ERR, "GSSAPI: %s\n", (char *)status.value);
		gss_release_buffer(&minor, &status);

		major = gss_display_status(&minor, err_min, GSS_C_MECH_CODE,
					   GSS_C_NO_OID, &msg_ctx, &status);
		if (GSS_ERROR(major))
			break;
		vpn_progress(vpninfo, PRG_ERR, "GSSAPI: %s\n", (char *)status.value);
		gss_release_buffer(&minor, &status);
	} while (msg_ctx);
}

static int gssapi_setup(struct openconnect_info *vpninfo)
{
	OM_uint32 major, minor;
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	char *service;

	if (asprintf(&service, "HTTP@%s", vpninfo->proxy) == -1)
		return -ENOMEM;
	token.length = strlen(service);
	token.value = service;

	major = gss_import_name(&minor, &token, (gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &vpninfo->gss_target_name);
	free(service);
	if (GSS_ERROR(major)) {
		print_gss_err(vpninfo, major, minor);
		return -EIO;
	}
	return 0;
}

#define GSSAPI_CONTINUE	2
#define GSSAPI_COMPLETE	3

int gssapi_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *hdrbuf)
{
	OM_uint32 major, minor;
	gss_buffer_desc in = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;

	if (vpninfo->auth[AUTH_TYPE_GSSAPI].state == AUTH_AVAILABLE && gssapi_setup(vpninfo)) {
		vpninfo->auth[AUTH_TYPE_GSSAPI].state = AUTH_FAILED;
		return -EIO;
	}

	if (vpninfo->auth[AUTH_TYPE_GSSAPI].challenge && *vpninfo->auth[AUTH_TYPE_GSSAPI].challenge) {
		int len = openconnect_base64_decode(in.value, vpninfo->auth[AUTH_TYPE_GSSAPI].challenge);
		if (len < 0)
			return -EINVAL;
		in.length = len;
	} else if (vpninfo->auth[AUTH_TYPE_GSSAPI].state > AUTH_AVAILABLE) {
		/* This indicates failure. We were trying, but got an empty
		   'Proxy-Authorization: Negotiate' header back from the server
		   implying that we should start again... */
		goto fail_gssapi;
	}

	major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &vpninfo->gss_context,
				     vpninfo->gss_target_name, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG,
				     GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, &in, NULL,
				     &out, NULL, NULL);
	if (major == GSS_S_COMPLETE)
		vpninfo->auth[AUTH_TYPE_GSSAPI].state = GSSAPI_COMPLETE;
	else if (major == GSS_S_CONTINUE_NEEDED)
		vpninfo->auth[AUTH_TYPE_GSSAPI].state = GSSAPI_CONTINUE;
	else {
		print_gss_err(vpninfo, major, minor);
	fail_gssapi:
		vpninfo->auth[AUTH_TYPE_GSSAPI].state = AUTH_FAILED;
		gss_release_name(&minor, &vpninfo->gss_target_name);
		gss_delete_sec_context(&minor, &vpninfo->gss_context, GSS_C_NO_BUFFER);
		return -EAGAIN;
	}
	buf_append(hdrbuf, "Proxy-Authorization: Negotiate ");
	buf_append_base64(hdrbuf, out.value, out.length);
	buf_append(hdrbuf, "\r\n");
	if (in.value)
		free(in.value);
	gss_release_buffer(&minor, &out);
	if (!vpninfo->auth[AUTH_TYPE_GSSAPI].challenge)
		vpn_progress(vpninfo, PRG_INFO,
			     _("Attempting GSSAPI authentication to proxy\n"));
	return 0;
}

void cleanup_gssapi_auth(struct openconnect_info *vpninfo)
{
	OM_uint32 minor;

	if (vpninfo->auth[AUTH_TYPE_GSSAPI].state <= AUTH_AVAILABLE)
		return;

	gss_release_name(&minor, &vpninfo->gss_target_name);
	vpninfo->gss_target_name = GSS_C_NO_NAME;
	gss_delete_sec_context(&minor, &vpninfo->gss_context, GSS_C_NO_BUFFER);
	vpninfo->gss_context = GSS_C_NO_CONTEXT;
}
