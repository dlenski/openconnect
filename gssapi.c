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

static int gssapi_setup(struct openconnect_info *vpninfo, const char *service)
{
	OM_uint32 major, minor;
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	char *name;

	if (asprintf(&name, "%s@%s", service, vpninfo->proxy) == -1)
		return -ENOMEM;
	token.length = strlen(name);
	token.value = name;

	major = gss_import_name(&minor, &token, (gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
				&vpninfo->gss_target_name);
	free(name);
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

	if (vpninfo->auth[AUTH_TYPE_GSSAPI].state == AUTH_AVAILABLE && gssapi_setup(vpninfo, "HTTP")) {
		vpninfo->auth[AUTH_TYPE_GSSAPI].state = AUTH_FAILED;
		return -EIO;
	}

	if (vpninfo->auth[AUTH_TYPE_GSSAPI].challenge && *vpninfo->auth[AUTH_TYPE_GSSAPI].challenge) {
		int len = openconnect_base64_decode((unsigned char **)&in.value, vpninfo->auth[AUTH_TYPE_GSSAPI].challenge);
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
		cleanup_gssapi_auth(vpninfo);
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

	if (vpninfo->gss_target_name != GSS_C_NO_NAME)
		gss_release_name(&minor, &vpninfo->gss_target_name);

	if (vpninfo->gss_context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&minor, &vpninfo->gss_context, GSS_C_NO_BUFFER);

	/* Shouldn't be necessary, but make sure... */
	vpninfo->gss_target_name = GSS_C_NO_NAME;
	vpninfo->gss_context = GSS_C_NO_CONTEXT;
}

int socks_gssapi_auth(struct openconnect_info *vpninfo)
{
	gss_buffer_desc in = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	unsigned char *pktbuf;
	int i;
	int ret = -EIO;

	if (gssapi_setup(vpninfo, "rcmd"))
		return -EIO;

	pktbuf = malloc(65538);
	if (!pktbuf)
		return -ENOMEM;
	while (1) {
		major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &vpninfo->gss_context,
					     vpninfo->gss_target_name, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG,
					     GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, &in, NULL,
					     &out, NULL, NULL);
		in.value = NULL;
		if (major == GSS_S_COMPLETE) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("GSSAPI authentication completed\n"));
			gss_release_buffer(&minor, &out);
			ret = 0;
			break;
		}
		if (major != GSS_S_CONTINUE_NEEDED) {
			print_gss_err(vpninfo, major, minor);
			break;
		}
		if (out.length > 65535) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("GSSAPI token too large (%zd bytes)\n"),
				     out.length);
			break;
		}

		pktbuf[0] = 1; /* ver */
		pktbuf[1] = 1; /* mtyp */
		pktbuf[2] = (out.length >> 8) & 0xff;
		pktbuf[3] = out.length & 0xff;
		memcpy(pktbuf + 4, out.value, out.length);

		free(out.value);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending GSSAPI token of %zu bytes\n"), out.length + 4);

		i = vpninfo->ssl_write(vpninfo, (void *)pktbuf, out.length + 4);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send GSSAPI authentication token to proxy: %s\n"),
				     strerror(-i));
			break;
		}

		i = vpninfo->ssl_read(vpninfo, (void *)pktbuf, 4);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to receive GSSAPI authentication token from proxy: %s\n"),
				     strerror(-i));
			break;
		}
		if (pktbuf[1] == 0xff) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS server reported GSSAPI context failure\n"));
			break;
		} else if (pktbuf[1] != 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown GSSAPI status response (0x%02x) from SOCKS server\n"),
				     pktbuf[1]);
			break;
		}
		in.length = (pktbuf[2] << 8) | pktbuf[3];
		in.value = pktbuf;

		i = vpninfo->ssl_read(vpninfo, (void *)pktbuf, in.length);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to receive GSSAPI authentication token from proxy: %s\n"),
				     strerror(-i));
			break;
		}
		vpn_progress(vpninfo, PRG_TRACE, _("Got GSSAPI token of %zu bytes: %02x %02x %02x %02x\n"),
			     in.length, pktbuf[0], pktbuf[1], pktbuf[2], pktbuf[3]);
	}

	if (!ret) {
		ret = -EIO;

		pktbuf[0] = 0;
		in.value = pktbuf;
		in.length = 1;

		major = gss_wrap(&minor, vpninfo->gss_context, 0,
				 GSS_C_QOP_DEFAULT, &in, NULL, &out);
		if (major != GSS_S_COMPLETE) {
			print_gss_err(vpninfo, major, minor);
			goto err;
		}

		pktbuf[0] = 1;
		pktbuf[1] = 2;
		pktbuf[2] = (out.length >> 8) & 0xff;
		pktbuf[3] = out.length & 0xff;
		memcpy(pktbuf + 4, out.value, out.length);

		free(out.value);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending GSSAPI protection negotiation of %zu bytes\n"), out.length + 4);

		i = vpninfo->ssl_write(vpninfo, (void *)pktbuf, out.length + 4);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send GSSAPI protection response to proxy: %s\n"),
				     strerror(-i));
			goto err;
		}

		i = vpninfo->ssl_read(vpninfo, (void *)pktbuf, 4);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to receive GSSAPI protection response from proxy: %s\n"),
				     strerror(-i));
			goto err;
		}
		in.length = (pktbuf[2] << 8) | pktbuf[3];
		in.value = pktbuf;

		i = vpninfo->ssl_read(vpninfo, (void *)pktbuf, in.length);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to receive GSSAPI protection response from proxy: %s\n"),
				     strerror(-i));
			goto err;
		}
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Got GSSAPI protection response of %zu bytes: %02x %02x %02x %02x\n"),
			     in.length, pktbuf[0], pktbuf[1], pktbuf[2], pktbuf[3]);

		major = gss_unwrap(&minor, vpninfo->gss_context, &in, &out, NULL, GSS_C_QOP_DEFAULT);
		if (major != GSS_S_COMPLETE) {
			print_gss_err(vpninfo, major, minor);
			goto err;
		}
		if (out.length != 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid GSSAPI protection response from proxy (%zu bytes)\n"),
				     out.length);
			gss_release_buffer(&minor, &out);
			goto err;
		}
		i = *(char *)out.value;
		gss_release_buffer(&minor, &out);
		if (i == 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy demands message integrity, which is not supported\n"));
			goto err;
		} else if (i == 2) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy demands message confidentiality, which is not supported\n"));
			goto err;
		} else if (i) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy demands protection unknown type 0x%02x\n"),
				     (unsigned char)i);
			goto err;
		}
		ret = 0;
	}
 err:
	cleanup_gssapi_auth(vpninfo);
	free(pktbuf);

	return ret;
}
