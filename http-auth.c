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
#include <stdarg.h>

#include "openconnect-internal.h"

/* Ick. Yet another wheel to reinvent. But although we could pull it
   in from OpenSSL, we can't from GnuTLS */

static inline int b64_char(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

void *openconnect_base64_decode(int *ret_len, const char *in)
{
	unsigned char *buf;
	int b[4];
	int len = strlen(in);

	if (len & 3) {
		*ret_len = -EINVAL;
		return NULL;
	}
	len = (len * 3) / 4;
	buf = malloc(len);
	if (!buf) {
		*ret_len = -ENOMEM;
		return NULL;
	}

	len = 0;
	while (*in) {
		if (!in[1] || !in[2] || !in[3])
			goto err;
	        b[0] = b64_char(in[0]);
		b[1] = b64_char(in[1]);
		if (b[0] < 0 || b[1] < 0)
			goto err;
		buf[len++] = (b[0] << 2) | (b[1] >> 4);

		if (in[2] == '=') {
			if (in[3] != '=' || in[4] != 0)
				goto err;
			break;
		}
		b[2] = b64_char(in[2]);
		if (b[2] < 0)
			goto err;
		buf[len++] = (b[1] << 4) | (b[2] >> 2);
		if (in[3] == '=') {
			if (in[4] != 0)
				goto err;
			break;
		}
		b[3] = b64_char(in[3]);
		if (b[3] < 0)
			goto err;
		buf[len++] = (b[2] << 6) | b[3];
		in += 4;
	}
	*ret_len = len;
	return buf;

 err:
	free(buf);
	*ret_len = EINVAL;
	return NULL;
}

static const char b64_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

void buf_append_base64(struct oc_text_buf *buf, const void *bytes, int len)
{
	const unsigned char *in = bytes;
	int hibits;

	if (!buf || buf->error)
		return;

	if (buf_ensure_space(buf, (4 * (len + 2) / 3) + 1))
		return;

	while (len > 0) {
		buf->data[buf->pos++] = b64_table[in[0] >> 2];
		hibits = (in[0] << 4) & 0x30;
		if (len == 1) {
			buf->data[buf->pos++] = b64_table[hibits];
			buf->data[buf->pos++] = '=';
			buf->data[buf->pos++] = '=';
			break;
		}
		buf->data[buf->pos++] = b64_table[hibits | (in[1] >> 4)];
		hibits = (in[1] << 2) & 0x3c;
		if (len == 2) {
			buf->data[buf->pos++] = b64_table[hibits];
			buf->data[buf->pos++] = '=';
			break;
		}
		buf->data[buf->pos++] = b64_table[hibits | (in[2] >> 6)];
		buf->data[buf->pos++] = b64_table[in[2] & 0x3f];
		in += 3;
		len -= 3;
	}
	buf->data[buf->pos] = 0;
}

static int basic_authorization(struct openconnect_info *vpninfo, int proxy,
			       struct http_auth_state *auth_state,
			       struct oc_text_buf *hdrbuf)
{
	struct oc_text_buf *text;
	const char *user, *pass;

	if (proxy) {
		user = vpninfo->proxy_user;
		pass = vpninfo->proxy_pass;
	} else {
		/* Need to parse this out of the URL */
		return -EINVAL;
	}

	if (!user || !pass)
		return -EINVAL;

	if (auth_state->state == AUTH_IN_PROGRESS) {
		auth_state->state = AUTH_FAILED;
		return -EAGAIN;
	}

	text = buf_alloc();
	buf_append(text, "%s:%s", user, pass);
	if (buf_error(text))
		return buf_free(text);

	buf_append(hdrbuf, "%sAuthorization: Basic ", proxy ? "Proxy-" : "");
	buf_append_base64(hdrbuf, text->data, text->pos);
	buf_append(hdrbuf, "\r\n");

	memset(text->data, 0, text->pos);
	buf_free(text);

	if (proxy)
		vpn_progress(vpninfo, PRG_INFO, _("Attempting HTTP Basic authentication to proxy\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Attempting HTTP Basic authentication to server '%s'\n"),
			     vpninfo->hostname);

	auth_state->state = AUTH_IN_PROGRESS;
	return 0;
}

#if !defined(HAVE_GSSAPI) && !defined(_WIN32)
static int no_gssapi_authorization(struct openconnect_info *vpninfo,
				   struct http_auth_state *auth_state,
				   struct oc_text_buf *hdrbuf)
{
	/* This comes last so just complain. We're about to bail. */
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without GSSAPI support\n"));
	auth_state->state = AUTH_FAILED;
	return -ENOENT;
}
#endif

struct auth_method {
	int state_index;
	const char *name;
	int (*authorization)(struct openconnect_info *, int, struct http_auth_state *, struct oc_text_buf *);
	void (*cleanup)(struct openconnect_info *, struct http_auth_state *);
} auth_methods[] = {
#if defined(HAVE_GSSAPI) || defined(_WIN32)
	{ AUTH_TYPE_GSSAPI, "Negotiate", gssapi_authorization, cleanup_gssapi_auth },
#endif
	{ AUTH_TYPE_NTLM, "NTLM", ntlm_authorization, cleanup_ntlm_auth },
	{ AUTH_TYPE_DIGEST, "Digest", digest_authorization, NULL },
	{ AUTH_TYPE_BASIC, "Basic", basic_authorization, NULL },
#if !defined(HAVE_GSSAPI) && !defined(_WIN32)
	{ AUTH_TYPE_GSSAPI, "Negotiate", no_gssapi_authorization, NULL }
#endif
};

/* Generate Proxy-Authorization: header for request if appropriate */
int gen_authorization_hdr(struct openconnect_info *vpninfo, int proxy,
			  struct oc_text_buf *buf)
{
	int ret;
	int i;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++) {
		struct http_auth_state *auth_state;
		if (proxy)
			auth_state = &vpninfo->proxy_auth[auth_methods[i].state_index];
		else
			auth_state = &vpninfo->http_auth[auth_methods[i].state_index];

		if (auth_state->state == AUTH_DEFAULT_DISABLED) {
			if (proxy)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Proxy requested Basic authentication which is disabled by default\n"));
			else
				vpn_progress(vpninfo, PRG_ERR,
					     _("Server '%s' requested Basic authentication which is disabled by default\n"),
					       vpninfo->hostname);
			auth_state->state = AUTH_FAILED;
			return -EINVAL;
		}


		if (auth_state->state > AUTH_UNSEEN) {
			ret = auth_methods[i].authorization(vpninfo, proxy, auth_state, buf);
			if (ret == -EAGAIN || !ret)
				return ret;
		}
	}
	vpn_progress(vpninfo, PRG_INFO, _("No more authentication methods to try\n"));

	if (vpninfo->retry_on_auth_fail) {
		/* Try again without the X-Support-HTTP-Auth: header */
		vpninfo->try_http_auth = 0;
		return 0;
	}
	return -ENOENT;
}

/* Returns non-zero if it matched */
static int handle_auth_proto(struct openconnect_info *vpninfo,
			     struct http_auth_state *auth_states,
			     struct auth_method *method, char *hdr)
{
	struct http_auth_state *auth = &auth_states[method->state_index];
	int l = strlen(method->name);

	if (auth->state <= AUTH_FAILED)
		return 0;

	if (strncmp(method->name, hdr, l))
		return 0;
	if (hdr[l] != ' ' && hdr[l] != 0)
		return 0;

	if (auth->state == AUTH_UNSEEN)
		auth->state = AUTH_AVAILABLE;

	free(auth->challenge);
	if (hdr[l])
		auth->challenge = strdup(hdr + l + 1);
	else
		auth->challenge = NULL;

	return 1;
}

int proxy_auth_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val)
{
	int i;

	if (!strcasecmp(hdr, "Proxy-Connection") ||
	    !strcasecmp(hdr, "Connection")) {
		if (!strcasecmp(val, "close"))
			vpninfo->proxy_close_during_auth = 1;
		return 0;
	}

	if (strcasecmp(hdr, "Proxy-Authenticate"))
		return 0;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++) {
		/* Return once we've found a match */
		if (handle_auth_proto(vpninfo, vpninfo->proxy_auth, &auth_methods[i], val))
			return 0;
	}

	return 0;
}

int http_auth_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val)
{
	int i;

	if (!strcasecmp(hdr, "X-HTTP-Auth-Support") &&
	    !strcasecmp(val, "fallback")) {
		vpninfo->retry_on_auth_fail = 1;
		return 0;
	}

	if (strcasecmp(hdr, "WWW-Authenticate"))
		return 0;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++) {
		/* Return once we've found a match */
		if (handle_auth_proto(vpninfo, vpninfo->http_auth, &auth_methods[i], val))
			return 0;
	}

	return 0;
}

void clear_auth_states(struct openconnect_info *vpninfo,
		       struct http_auth_state *auth_states, int reset)
{
	int i;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++) {
		struct http_auth_state *auth = &auth_states[auth_methods[i].state_index];

		/* The 'reset' argument is set when we're connected successfully,
		   to fully reset the state to allow another connection to start
		   again. Otherwise, we need to remember which auth methods have
		   been tried and should not be attempted again. */
		if (reset && auth_methods[i].cleanup)
			auth_methods[i].cleanup(vpninfo, auth);

		free(auth->challenge);
		auth->challenge = NULL;
		/* If it *failed* don't try it again even next time */
		if (auth->state <= AUTH_FAILED)
			continue;
		if (reset || auth->state == AUTH_AVAILABLE)
			auth->state = AUTH_UNSEEN;
	}
}

static int set_authmethods(struct openconnect_info *vpninfo, struct http_auth_state *auth_states,
			   const char *methods)
{
	int i, len;
	const char *p;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++)
		auth_states[auth_methods[i].state_index].state = AUTH_DISABLED;

	while (methods) {
		p = strchr(methods, ',');
		if (p) {
			len = p - methods;
			p++;
		} else
			len = strlen(methods);

		for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++) {
			if (strprefix_match(methods, len, auth_methods[i].name) ||
			    (auth_methods[i].state_index == AUTH_TYPE_GSSAPI &&
			     strprefix_match(methods, len, "gssapi"))) {
				auth_states[auth_methods[i].state_index].state = AUTH_UNSEEN;
				break;
			}
		}
		methods = p;
	}
	return 0;
}

int openconnect_set_http_auth(struct openconnect_info *vpninfo, const char *methods)
{
	return set_authmethods(vpninfo, vpninfo->http_auth, methods);
}

int openconnect_set_proxy_auth(struct openconnect_info *vpninfo, const char *methods)
{
	return set_authmethods(vpninfo, vpninfo->proxy_auth, methods);
}
