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

	if (vpninfo->gssapi_auth.state == AUTH_AVAILABLE && gssapi_setup(vpninfo)) {
		vpninfo->gssapi_auth.state = AUTH_FAILED;
		return -EIO;
	}

	if (vpninfo->gssapi_auth.challenge && *vpninfo->gssapi_auth.challenge) {
		int len = openconnect_base64_decode(in.value, vpninfo->gssapi_auth.challenge);
		if (len < 0)
			return -EINVAL;
		in.length = len;
	}

	major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &vpninfo->gss_context,
				     vpninfo->gss_target_name, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG,
				     GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, &in, NULL,
				     &out, NULL, NULL);
	if (major == GSS_S_COMPLETE)
		vpninfo->gssapi_auth.state = GSSAPI_COMPLETE;
	else if (major == GSS_S_CONTINUE_NEEDED)
		vpninfo->gssapi_auth.state = GSSAPI_CONTINUE;
	else {
		print_gss_err(vpninfo, major, minor);
		vpninfo->gssapi_auth.state = AUTH_FAILED;
		gss_release_name(&minor, &vpninfo->gss_target_name);
		gss_delete_sec_context(&minor, &vpninfo->gss_context, GSS_C_NO_BUFFER);
		return -EIO;
	}
	buf_append(hdrbuf, "Proxy-Authorization: Negotiate ");
	buf_append_base64(hdrbuf, out.value, out.length);
	buf_append(hdrbuf, "\r\n");
	if (in.value)
		free(in.value);
	gss_release_buffer(&minor, &out);
	return 0;
}

void cleanup_gssapi_auth(struct openconnect_info *vpninfo)
{
	OM_uint32 minor;

	if (vpninfo->gssapi_auth.state <= AUTH_AVAILABLE)
		return;

	gss_release_name(&minor, &vpninfo->gss_target_name);
	vpninfo->gss_target_name = GSS_C_NO_NAME;
	gss_delete_sec_context(&minor, &vpninfo->gss_context, GSS_C_NO_BUFFER);
	vpninfo->gss_context = GSS_C_NO_CONTEXT;
}
