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

#include <errno.h>
#include <string.h>

#include "openconnect-internal.h"


static int sspi_setup(struct openconnect_info *vpninfo, const char *service)
{
	SECURITY_STATUS status;

	if (asprintf(&vpninfo->sspi_target_name, "%s/%s", service, vpninfo->proxy) == -1)
		return -ENOMEM;

	status = AcquireCredentialsHandle(NULL, (SEC_CHAR *)"Negotiate", SECPKG_CRED_OUTBOUND,
					  NULL, NULL, NULL, NULL, &vpninfo->sspi_cred, NULL);
	if (status != SEC_E_OK) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("AcquireCredentialsHandle() failed: %lx\n"), status);
		free(vpninfo->sspi_target_name);
		vpninfo->sspi_target_name = NULL;
		return -EIO;
	}

	return 0;
}

int gssapi_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *hdrbuf)
{
	SECURITY_STATUS status;
	SecBufferDesc input_desc, output_desc;
	SecBuffer in_token, out_token;
	ULONG ret_flags;
	int first = 1;

	if (vpninfo->auth[AUTH_TYPE_GSSAPI].state == AUTH_AVAILABLE && sspi_setup(vpninfo, "HTTP")) {
		vpninfo->auth[AUTH_TYPE_GSSAPI].state = AUTH_FAILED;
		return -EIO;
	}

	if (vpninfo->auth[AUTH_TYPE_GSSAPI].challenge && *vpninfo->auth[AUTH_TYPE_GSSAPI].challenge) {
		int token_len;

		input_desc.cBuffers = 1;
		input_desc.pBuffers = &in_token;
		input_desc.ulVersion = SECBUFFER_VERSION;

		in_token.BufferType = SECBUFFER_TOKEN;
		token_len = openconnect_base64_decode((unsigned char **)&in_token.pvBuffer,
						      vpninfo->auth[AUTH_TYPE_GSSAPI].challenge);
		if (token_len < 0)
			return token_len;
		in_token.cbBuffer = token_len;

		first = 0;

	} else if (vpninfo->auth[AUTH_TYPE_GSSAPI].state > AUTH_AVAILABLE) {
		/* This indicates failure. We were trying, but got an empty
		   'Proxy-Authorization: Negotiate' header back from the server
		   implying that we should start again... */
		goto fail_gssapi;
	}

	vpninfo->auth[AUTH_TYPE_GSSAPI].state = AUTH_IN_PROGRESS;

	output_desc.cBuffers = 1;
	output_desc.pBuffers = &out_token;
	output_desc.ulVersion = SECBUFFER_VERSION;

	out_token.BufferType = SECBUFFER_TOKEN;
	out_token.cbBuffer = 0;
	out_token.pvBuffer = NULL;

	status = InitializeSecurityContext(&vpninfo->sspi_cred, first ? NULL : &vpninfo->sspi_ctx,
					   (SEC_CHAR *)vpninfo->sspi_target_name,
					   ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION,
					   0, SECURITY_NETWORK_DREP, first ? NULL : &input_desc, 0, &vpninfo->sspi_ctx,
					   &output_desc, &ret_flags, NULL);
	if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("InitializeSecurityContext() failed: %lx\n"), status);
	fail_gssapi:
		cleanup_gssapi_auth(vpninfo);
		vpninfo->auth[AUTH_TYPE_GSSAPI].state = AUTH_FAILED;
		/* -EAGAIN to first a reconnect if we had been trying. Else -EIO */
		return first ? -EIO : -EAGAIN;
	}

	buf_append(hdrbuf, "Proxy-Authorization: Negotiate ");
	buf_append_base64(hdrbuf, out_token.pvBuffer, out_token.cbBuffer);
	buf_append(hdrbuf, "\r\n");

	FreeContextBuffer(out_token.pvBuffer);

	return 0;
}

void cleanup_gssapi_auth(struct openconnect_info *vpninfo)
{
	if (vpninfo->auth[AUTH_TYPE_GSSAPI].state >= AUTH_IN_PROGRESS) {
		free(vpninfo->sspi_target_name);
		vpninfo->sspi_target_name = NULL;
		FreeCredentialsHandle(&vpninfo->sspi_cred);
		DeleteSecurityContext(&vpninfo->sspi_ctx);
	}
}

