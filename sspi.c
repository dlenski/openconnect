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

#include <errno.h>
#include <string.h>

#include "openconnect-internal.h"


static int sspi_setup(struct openconnect_info *vpninfo, struct http_auth_state *auth_state, const char *service, int proxy)
{
	SECURITY_STATUS status;
	struct oc_text_buf *buf = buf_alloc();

	buf_append_utf16le(buf, service);
	buf_append_utf16le(buf, "/");
	buf_append_utf16le(buf, proxy ? vpninfo->proxy : vpninfo->hostname);

	if (buf_error(buf))
		return buf_free(buf);

	auth_state->sspi_target_name = (wchar_t *)buf->data;
	buf->data = NULL;
	buf_free(buf);

	status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate",
					   SECPKG_CRED_OUTBOUND, NULL, NULL,
					   NULL, NULL, &auth_state->sspi_cred,
					   NULL);
	if (status != SEC_E_OK) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("AcquireCredentialsHandle() failed: %lx\n"), status);
		free(auth_state->sspi_target_name);
		auth_state->sspi_target_name = NULL;
		return -EIO;
	}

	return 0;
}

int gssapi_authorization(struct openconnect_info *vpninfo, int proxy,
			 struct http_auth_state *auth_state, struct oc_text_buf *hdrbuf)
{
	SECURITY_STATUS status;
	SecBufferDesc input_desc, output_desc;
	SecBuffer in_token, out_token;
	ULONG ret_flags;
	int first = 1;

	if (auth_state->state == AUTH_AVAILABLE && sspi_setup(vpninfo, auth_state, "HTTP", proxy)) {
		auth_state->state = AUTH_FAILED;
		return -EIO;
	}

	if (auth_state->challenge && *auth_state->challenge) {
		int token_len = -EINVAL;

		input_desc.cBuffers = 1;
		input_desc.pBuffers = &in_token;
		input_desc.ulVersion = SECBUFFER_VERSION;

		in_token.BufferType = SECBUFFER_TOKEN;
		in_token.pvBuffer = openconnect_base64_decode(&token_len,
							      auth_state->challenge);
		if (!in_token.pvBuffer)
			return token_len;
		in_token.cbBuffer = token_len;

		first = 0;

	} else if (auth_state->state > AUTH_AVAILABLE) {
		/* This indicates failure. We were trying, but got an empty
		   'Proxy-Authorization: Negotiate' header back from the server
		   implying that we should start again... */
		goto fail_gssapi;
	}

	auth_state->state = AUTH_IN_PROGRESS;

	output_desc.cBuffers = 1;
	output_desc.pBuffers = &out_token;
	output_desc.ulVersion = SECBUFFER_VERSION;

	out_token.BufferType = SECBUFFER_TOKEN;
	out_token.cbBuffer = 0;
	out_token.pvBuffer = NULL;

	status = InitializeSecurityContextW(&auth_state->sspi_cred,
					    first ? NULL : &auth_state->sspi_ctx,
					    auth_state->sspi_target_name,
					    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION,
					    0, SECURITY_NETWORK_DREP,
					    first ? NULL : &input_desc,
					    0, &auth_state->sspi_ctx,
					    &output_desc, &ret_flags, NULL);
	if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("InitializeSecurityContext() failed: %lx\n"), status);
	fail_gssapi:
		cleanup_gssapi_auth(vpninfo, auth_state);
		auth_state->state = AUTH_FAILED;
		/* -EAGAIN to first a reconnect if we had been trying. Else -EIO */
		return first ? -EIO : -EAGAIN;
	}

	buf_append(hdrbuf, "%sAuthorization: Negotiate ", proxy ? "Proxy-" : "");
	buf_append_base64(hdrbuf, out_token.pvBuffer, out_token.cbBuffer);
	buf_append(hdrbuf, "\r\n");

	FreeContextBuffer(out_token.pvBuffer);

	return 0;
}

void cleanup_gssapi_auth(struct openconnect_info *vpninfo,
			 struct http_auth_state *auth_state)

{
	if (auth_state->state >= AUTH_IN_PROGRESS) {
		free(auth_state->sspi_target_name);
		auth_state->sspi_target_name = NULL;
		FreeCredentialsHandle(&auth_state->sspi_cred);
		DeleteSecurityContext(&auth_state->sspi_ctx);
	}
}

int socks_gssapi_auth(struct openconnect_info *vpninfo)
{
	SECURITY_STATUS status;
	SecBufferDesc input_desc, output_desc;
	SecBuffer in_token, out_token;
	ULONG ret_flags;
	unsigned char *pktbuf;
	int first = 1;
	int i;
	int ret = -EIO;
	struct http_auth_state *auth_state = &vpninfo->proxy_auth[AUTH_TYPE_GSSAPI];

	if (sspi_setup(vpninfo, auth_state, "rcmd", 1))
		return -EIO;

	vpninfo->proxy_auth[AUTH_TYPE_GSSAPI].state = AUTH_IN_PROGRESS;

	pktbuf = malloc(65538);
	if (!pktbuf)
		return -ENOMEM;

	input_desc.cBuffers = 1;
	input_desc.pBuffers = &in_token;
	input_desc.ulVersion = SECBUFFER_VERSION;

	in_token.BufferType = SECBUFFER_TOKEN;

	output_desc.cBuffers = 1;
	output_desc.pBuffers = &out_token;
	output_desc.ulVersion = SECBUFFER_VERSION;

	out_token.BufferType = SECBUFFER_TOKEN;
	out_token.cbBuffer = 0;
	out_token.pvBuffer = NULL;

	while (1) {
		status = InitializeSecurityContextW(&auth_state->sspi_cred,
						    first ? NULL : &auth_state->sspi_ctx,
						    auth_state->sspi_target_name,
						    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION,
						    0, SECURITY_NETWORK_DREP,
						    first ? NULL : &input_desc,
						    0, &auth_state->sspi_ctx,
						    &output_desc, &ret_flags, NULL);
		if (status == SEC_E_OK) {
			/* If we still have a token to send, send it. */
			if (!out_token.cbBuffer) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("GSSAPI authentication completed\n"));
				ret = 0;
				break;
			}
		} else if (status != SEC_I_CONTINUE_NEEDED) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("InitializeSecurityContext() failed: %lx\n"), status);
			break;
		}

		if (out_token.cbBuffer > 65535) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSPI token too large (%ld bytes)\n"),
				     out_token.cbBuffer);
			break;
		}

		pktbuf[0] = 1; /* ver */
		pktbuf[1] = 1; /* mtyp */
		store_be16(pktbuf + 2, out_token.cbBuffer);
		memcpy(pktbuf + 4, out_token.pvBuffer, out_token.cbBuffer);

		FreeContextBuffer(out_token.pvBuffer);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending SSPI token of %lu bytes\n"), out_token.cbBuffer + 4);

		i = vpninfo->ssl_write(vpninfo, (void *)pktbuf, out_token.cbBuffer + 4);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send SSPI authentication token to proxy: %s\n"),
				     strerror(-i));
			break;
		}

		i = vpninfo->ssl_read(vpninfo, (void *)pktbuf, 4);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to receive SSPI authentication token from proxy: %s\n"),
				     strerror(-i));
			break;
		}
		if (pktbuf[1] == 0xff) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS server reported SSPI context failure\n"));
			break;
		} else if (pktbuf[1] != 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown SSPI status response (0x%02x) from SOCKS server\n"),
				     pktbuf[1]);
			break;
		}
		in_token.cbBuffer = load_be16(pktbuf + 2);
		in_token.pvBuffer = pktbuf;
		first = 0;

		if (!in_token.cbBuffer) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("GSSAPI authentication completed\n"));
			ret = 0;
			break;
		}

		i = vpninfo->ssl_read(vpninfo, (void *)pktbuf, in_token.cbBuffer);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to receive SSPI authentication token from proxy: %s\n"),
				     strerror(-i));
			break;
		}
		vpn_progress(vpninfo, PRG_TRACE, _("Got SSPI token of %lu bytes: %02x %02x %02x %02x\n"),
			     in_token.cbBuffer, pktbuf[0], pktbuf[1], pktbuf[2], pktbuf[3]);

	}

	if (!ret) {
		SecPkgContext_Sizes sizes;
		SecBufferDesc enc_desc;
		SecBuffer enc_bufs[3];
		int len;

		ret = -EIO;

		status = QueryContextAttributes(&auth_state->sspi_ctx, SECPKG_ATTR_SIZES, &sizes);
		if (status != SEC_E_OK) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("QueryContextAttributes() failed: %lx\n"), status);
			goto err;
		}

		enc_desc.cBuffers = 3;
		enc_desc.pBuffers = enc_bufs;
		enc_desc.ulVersion = SECBUFFER_VERSION;

		enc_bufs[0].BufferType = SECBUFFER_TOKEN;
		enc_bufs[0].cbBuffer = sizes.cbSecurityTrailer;
		enc_bufs[0].pvBuffer = malloc(sizes.cbSecurityTrailer);
		if (!enc_bufs[0].pvBuffer) {
			ret = -ENOMEM;
			goto err;
		}
		memset(enc_bufs[0].pvBuffer, 0, enc_bufs[0].cbBuffer);

		enc_bufs[1].BufferType = SECBUFFER_DATA;
		enc_bufs[1].pvBuffer = pktbuf;
		enc_bufs[1].cbBuffer = 1;

		/* All this just to sign this single byte... */
		pktbuf[0] = 0;

		enc_bufs[2].BufferType = SECBUFFER_PADDING;
		enc_bufs[2].cbBuffer = sizes.cbBlockSize;
		enc_bufs[2].pvBuffer = malloc(sizes.cbBlockSize);
		if (!enc_bufs[2].pvBuffer) {
			free(enc_bufs[0].pvBuffer);
			ret = -ENOMEM;
			goto err;
		}

		status = EncryptMessage(&auth_state->sspi_ctx, SECQOP_WRAP_NO_ENCRYPT, &enc_desc, 0);
		if (status != SEC_E_OK) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("EncryptMessage() failed: %lx\n"), status);
			free(enc_bufs[0].pvBuffer);
			free(enc_bufs[2].pvBuffer);
			goto err;
		}

		len = enc_bufs[0].cbBuffer + enc_bufs[1].cbBuffer + enc_bufs[2].cbBuffer;
		/* Check each one to avoid the (utterly theoretical) overflow when calculated
		   into an 'int' type. */
		if (enc_bufs[1].cbBuffer != 1 || enc_bufs[0].cbBuffer > 65535 ||
		    enc_bufs[2].cbBuffer > 65535 || len > 65535) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("EncryptMessage() result too large (%lu + %lu + %lu)\n"),
				     enc_bufs[0].cbBuffer, enc_bufs[1].cbBuffer, enc_bufs[2].cbBuffer);
			free(enc_bufs[0].pvBuffer);
			free(enc_bufs[2].pvBuffer);
			goto err;
		}

		/* Our single byte of payload was *supposed* to be unencrypted but
		   Windows doesn't always manage to do as it's told... */
		pktbuf[4 + enc_bufs[0].cbBuffer] = pktbuf[0];

		pktbuf[0] = 1;
		pktbuf[1] = 2;
		store_be16(pktbuf + 2, len);

		if (enc_bufs[0].cbBuffer)
			memcpy(pktbuf + 4, enc_bufs[0].pvBuffer, enc_bufs[0].cbBuffer);

		if (enc_bufs[2].cbBuffer)
			memcpy(pktbuf + 5 + enc_bufs[0].cbBuffer, enc_bufs[2].pvBuffer, enc_bufs[2].cbBuffer);

		free(enc_bufs[0].pvBuffer);
		free(enc_bufs[2].pvBuffer);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending SSPI protection negotiation of %u bytes\n"), len + 4);

		i = vpninfo->ssl_write(vpninfo, (void *)pktbuf, len + 4);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send SSPI protection response to proxy: %s\n"),
				     strerror(-i));
			goto err;
		}

		i = vpninfo->ssl_read(vpninfo, (void *)pktbuf, 4);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to receive SSPI protection response from proxy: %s\n"),
				     strerror(-i));
			goto err;
		}

		len = load_be16(pktbuf + 2);

		i = vpninfo->ssl_read(vpninfo, (void *)pktbuf, len);
		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to receive SSPI protection response from proxy: %s\n"),
				     strerror(-i));
			goto err;
		}
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Got SSPI protection response of %d bytes: %02x %02x %02x %02x\n"),
			     len, pktbuf[0], pktbuf[1], pktbuf[2], pktbuf[3]);

		enc_desc.cBuffers = 2;

		enc_bufs[0].BufferType = SECBUFFER_STREAM;
		enc_bufs[0].cbBuffer = len;
		enc_bufs[0].pvBuffer = pktbuf;

		enc_bufs[1].BufferType = SECBUFFER_DATA;
		enc_bufs[1].cbBuffer = 0;
		enc_bufs[1].pvBuffer = NULL;

		status = DecryptMessage(&auth_state->sspi_ctx, &enc_desc, 0, NULL);
		if (status != SEC_E_OK) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("DecryptMessage failed: %lx\n"), status);
			goto err;
		}
		if (enc_bufs[1].cbBuffer != 1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid SSPI protection response from proxy (%lu bytes)\n"),
				     enc_bufs[1].cbBuffer);
			FreeContextBuffer(enc_bufs[1].pvBuffer);
			goto err;
		}

		i = *(char *)enc_bufs[1].pvBuffer;
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
	cleanup_gssapi_auth(vpninfo, &vpninfo->proxy_auth[AUTH_TYPE_GSSAPI]);
	vpninfo->proxy_auth[AUTH_TYPE_GSSAPI].state = AUTH_UNSEEN;
	free(pktbuf);

	return ret;
}
