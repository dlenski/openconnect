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
#include <ctype.h>

#include "openconnect-internal.h"

#define ALGO_MD5	0
#define ALGO_MD5_SESS	1

static struct oc_text_buf *get_qs(char **str)
{
	struct oc_text_buf *res;
	int escaped = 0;
	char *p = *str;

	if (*p != '\"')
		return NULL;

	res = buf_alloc();

	while (*++p) {
		if (!escaped && *p == '\"') {
			*str = p+1;
			if (buf_error(res))
				break;
			return res;
		}
		if (escaped)
			escaped = 0;
		else if (*p == '\\')
			escaped = 1;
		buf_append_bytes(res, p, 1);
	}
	buf_free(res);
	return NULL;
}

static void buf_append_unq(struct oc_text_buf *buf, char *str)
{
	while (*str) {
		if (*str == '\"' || *str == '\\')
			buf_append(buf, "\\");
		buf_append_bytes(buf, str, 1);
		str++;
	}
}

static void buf_append_md5(struct oc_text_buf *buf, void *data, int len)
{
	unsigned char md5[16];
	int i;

	if (openconnect_md5(md5, data, len)) {
		buf->error = -EIO;
		return;
	}

	for (i = 0; i < 16; i++)
		buf_append(buf, "%02x", md5[i]);
}

int digest_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *hdrbuf)
{
	char *chall;
	int ret = -EINVAL;
	int algo = ALGO_MD5;
	int qop_auth = 0;
	int nc = 1;
	struct oc_text_buf *realm = NULL, *nonce = NULL, *opaque = NULL;
	struct oc_text_buf *a1 = NULL, *a2 = NULL, *kd = NULL;
	struct oc_text_buf *cnonce = NULL;
	unsigned char cnonce_random[32];

	if (!vpninfo->proxy_user || !vpninfo->proxy_pass)
		return -EINVAL;

	if (vpninfo->auth[AUTH_TYPE_DIGEST].state < AUTH_AVAILABLE)
		return -EINVAL;

	if (vpninfo->auth[AUTH_TYPE_DIGEST].state == AUTH_IN_PROGRESS) {
		vpninfo->auth[AUTH_TYPE_DIGEST].state = AUTH_FAILED;
		return -EAGAIN;
	}

	chall = vpninfo->auth[AUTH_TYPE_DIGEST].challenge;
	if (!chall)
		return -EINVAL;

	while (*chall) {
		if (!strncmp(chall, "realm=", 6)) {
			chall += 6;
			realm = get_qs(&chall);
			if (!realm)
				goto err;
		} else if (!strncmp(chall, "nonce=", 6)) {
			chall += 6;
			nonce = get_qs(&chall);
			if (!nonce)
				goto err;
		} else if (!strncmp(chall, "qop=", 4)) {
			chall += 4;
			if (strncmp(chall, "\"auth\"", 6)) {
				/* We don't support "auth-int" */
				goto err;
			}
			qop_auth = 1;
			chall += 6;
		} else if (!strncmp(chall, "opaque=", 7)) {
			chall += 7;
			opaque = get_qs(&chall);
			if (!opaque)
				goto err;
		} else if (!strncmp(chall, "algorithm=", 10)) {
			chall += 10;
			if (!strncmp(chall, "MD5-sess", 8)) {
				algo = ALGO_MD5_SESS;
				chall += 8;
			} else if (!strncmp(chall, "MD5", 3)) {
				algo = ALGO_MD5;
				chall += 3;
			}
		} else {
			char *p = strchr(chall, '=');
			if (!p)
				goto err;
			p++;
			if (*p == '\"') {
				/* Eat and discard a quoted-string */
				int escaped = 0;
				p++;
				do  {
					if (escaped)
						escaped = 0;
					else if (*p == '\\')
						escaped = 1;
					if (!*p)
						goto err;
				} while (escaped || *p != '\"');
				chall = p+1;
			} else {
				/* Not quoted. Just find the next comma (or EOL) */
				p = strchr(p, ',');
				if (!p)
					break;
				chall = p;
			}
		}
		while (isspace(*chall))
			chall++;
		if (!*chall)
			break;
		if (*chall != ',')
			goto err;
		chall++;
		while (isspace(*chall))
			chall++;
		if (!*chall)
			break;
	}
	if (!nonce || !realm)
		goto err;

	if (openconnect_random(&cnonce_random, sizeof(cnonce_random)))
		goto err;
	cnonce = buf_alloc();
	buf_append_base64(cnonce, cnonce_random, sizeof(cnonce_random));

	a1 = buf_alloc();
	buf_append_unq(a1, vpninfo->proxy_user);
	buf_append(a1, ":%s:%s", realm->data, vpninfo->proxy_pass);
	if (buf_error(a1))
		goto err;
	if (algo == ALGO_MD5_SESS) {
		struct oc_text_buf *old_a1 = a1;

		a1 = buf_alloc();
		buf_append_md5(a1, old_a1->data, old_a1->pos);
		buf_free(old_a1);
		buf_append(a1, ":%s:%s\n", nonce->data, cnonce->data);
		if (buf_error(a1))
			goto err;
	}

	a2 = buf_alloc();
	buf_append(a2, "CONNECT:%s:%d", vpninfo->hostname, vpninfo->port);
	if (buf_error(a2))
		goto err;

	kd = buf_alloc();
	buf_append_md5(kd, a1->data, a1->pos);
	buf_append(kd, ":%s:", nonce->data);
	if (qop_auth) {
		buf_append(kd, "%08x:%s:auth:", nc, cnonce->data);
	}
	buf_append_md5(kd, a2->data, a2->pos);

	buf_append(hdrbuf, "Proxy-Authorization: Digest username=\"");
	buf_append_unq(hdrbuf, vpninfo->proxy_user);
	buf_append(hdrbuf, "\", realm=\"%s\", nonce=\"%s\", uri=\"%s:%d\", ",
		   realm->data, nonce->data, vpninfo->hostname, vpninfo->port);
	if (qop_auth)
		buf_append(hdrbuf, "cnonce=\"%s\", nc=%08x, qop=auth, ",
			   cnonce->data, nc);
	if (opaque)
		buf_append(hdrbuf, "opaque=\"%s\", ", opaque->data);
	buf_append(hdrbuf, "response=\"");
	buf_append_md5(hdrbuf, kd->data, kd->pos);
	buf_append(hdrbuf, "\"\r\n");

	ret = 0;

	vpninfo->auth[AUTH_TYPE_DIGEST].state = AUTH_IN_PROGRESS;
	vpn_progress(vpninfo, PRG_INFO,
		     _("Attempting Digest authentication to proxy\n"));
 err:
	buf_free(a1);
	buf_free(a2);
	buf_free(kd);
	buf_free(realm);
	buf_free(nonce);
	buf_free(cnonce);
	buf_free(opaque);
	return ret;
}
