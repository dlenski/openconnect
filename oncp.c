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

/* XX: This is actually a lot of duplication with the CSTP version. */
void oncp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	struct oc_vpn_option *opt;

	buf_append(buf, "Host: %s\r\n", vpninfo->hostname);

	if (vpninfo->cookies) {
		buf_append(buf, "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			buf_append(buf, "%s=%s%s", opt->option,
				      opt->value, opt->next ? "; " : "\r\n");
	}

	buf_append(buf, "Connection: close\r\n");
//	buf_append(buf, "Content-Length: 256\r\n");
	buf_append(buf, "NCP-Version: 3\r\n");
//	buf_append(buf, "Accept-Encoding: gzip\r\n");
}

int oncp_obtain_cookie(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR, _("oNCP authentication not yet implemented\n"));
	return -EOPNOTSUPP;
}
static int parse_cookie(struct openconnect_info *vpninfo)
{
	char *p = vpninfo->cookie;

	/* We currenly expect the "cookie" to be contain multiple cookies:
	 * DSSignInUrl=/; DSID=xxx; DSFirstAccess=xxx; DSLastAccess=xxx
	 * Process those into vpninfo->cookies unless we already had them
	 * (in which case they'll may be newer. */
	while (p && *p) {
		char *semicolon = strchr(p, ';');
		char *equals;

		if (semicolon)
			*semicolon = 0;

		equals = strchr(p, '=');
		if (!equals) {
			vpn_progress(vpninfo, PRG_ERR, _("Invalid cookie '%s'\n"), p);
			return -EINVAL;
		}
		*equals = 0;
		http_add_cookie(vpninfo, p, equals+1, 0);
		*equals = '=';

		p = semicolon;
		if (p) {
			*p = ';';
			p++;
			while (*p && isspace(*p))
				p++;
		}
	}

	return 0;
}

static void buf_append_le16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	b[0] = val & 0xff;
	b[1] = val >> 8;

	buf_append_bytes(buf, b, 2);
}

static void buf_append_tlv(struct oc_text_buf *buf, uint16_t val, uint32_t len, void *data)
{
	unsigned char b[6];

	b[0] = val >> 8;
	b[1] = val;
	b[2] = len >> 24;
	b[3] = len >> 16;
	b[4] = len >> 8;
	b[5] = len;
	buf_append_bytes(buf, b, 6);
	if (len)
		buf_append_bytes(buf, data, len);
}

static void buf_append_tlv_be32(struct oc_text_buf *buf, uint16_t val, uint32_t data)
{
	unsigned char d[4];

	d[0] = data >> 24;
	d[1] = data >> 16;
	d[2] = data >> 8;
	d[3] = data;

	buf_append_tlv(buf, val, 4, d);
}

static void buf_hexdump(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	char linebuf[80];
	int i;

	for (i = 0; i < buf->pos; i++) {
		if (i % 16 == 0) {
			if (i)
				vpn_progress(vpninfo, PRG_DEBUG, "%s\n", linebuf);
			sprintf(linebuf, "%04x:", i);
		}
		sprintf(linebuf + strlen(linebuf), " %02x", (unsigned char)buf->data[i]);
	}
	vpn_progress(vpninfo, PRG_DEBUG, "%s\n", linebuf);
}

static const char authpkt_head[] = { 0x00, 0x04, 0x00, 0x00, 0x00 };
static const char authpkt_tail[] = { 0xbb, 0x01, 0x00, 0x00, 0x00, 0x00 };

#define GRP_ATTR(g, a) (((g) << 16) | (a))
#define TLV_BE32(data) ((data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3])

/* We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers. */

static const char *add_option(struct openconnect_info *vpninfo, const char *opt,
			      const char *val, int val_len)
{
	struct oc_vpn_option *new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->option = strdup(opt);
	if (!new->option) {
		free(new);
		return NULL;
	}
	if (val_len >= 0)
		new->value = strndup(val, val_len);
	else
		new->value = strdup(val);
	if (!new->value) {
		free(new->option);
		free(new);
		return NULL;
	}
	new->next = vpninfo->cstp_options;
	vpninfo->cstp_options = new;

	return new->value;
}

static int process_attr(struct openconnect_info *vpninfo, int group, int attr,
			unsigned char *data, int attrlen)
{
	char buf[80];
	int i;

	switch(GRP_ATTR(group, attr)) {
	case GRP_ATTR(6, 2):
		if (attrlen != 4) {
		badlen:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected length %d for TLV %d/%d\n"),
				     attrlen, group, attr);
			return -EINVAL;
			goto badlen;
		}
		vpninfo->ip_info.mtu = TLV_BE32(data);
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received MTU %d from server\n"),
			     vpninfo->ip_info.mtu);
		break;

	case GRP_ATTR(2, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS server %s\n"), buf);

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.dns[i]) {
				vpninfo->ip_info.dns[i] = add_option(vpninfo, "DNS", buf, -1);
				break;
			}
		}
		break;

	case GRP_ATTR(2, 2):
		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS search domain %.*s"),
			     attrlen, (char *)data);
		vpninfo->ip_info.domain = add_option(vpninfo, "search", (char *)data, attrlen);
		break;

	case GRP_ATTR(1, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal IP address %s\n"), buf);
		vpninfo->ip_info.addr = add_option(vpninfo, "ipaddr", buf, -1);
		break;

	case GRP_ATTR(1, 2):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received netmask %s\n"), buf);
		vpninfo->ip_info.addr = add_option(vpninfo, "netmask", buf, -1);
		break;

	case GRP_ATTR(1, 3):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal gateway address %s\n"), buf);
		/* Hm, what are we supposed to do with this? It's a tunnel;
		   having a gateway is meaningless. */
		add_option(vpninfo, "ipaddr", buf, -1);
		break;

		/* ESP SPI is (7,1) and secret (64 bytes) is (7,2) */
	default:
		buf[0] = 0;
		for (i=0; i < 16 && i < attrlen; i++)
			sprintf(buf + strlen(buf), " %02x", data[i]);
		if (attrlen > 16)
			sprintf(buf + strlen(buf), "...");

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Unknown TLV group %d attr %d len %d:%s\n"),
			       group, attr, attrlen, buf);
	}
	return 0;
}

static void put_len16(struct oc_text_buf *buf, int where)
{
	int len = buf->pos - where;

	buf->data[where - 1] = len;
	buf->data[where - 2] = len >> 8;
}

static void put_len32(struct oc_text_buf *buf, int where)
{
	int len = buf->pos - where;

	buf->data[where - 1] = len;
	buf->data[where - 2] = len >> 8;
	buf->data[where - 3] = len >> 16;
	buf->data[where - 4] = len >> 24;
}


/* We don't know what these are so just hope they never change */
static const unsigned char kmp_head[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char kmp_tail[] = { 0x01, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char kmp_tail_out[] = { 0x01, 0x00, 0x00, 0x00, 0x01,
					      0x00, 0x00, 0x00, 0x00, 0x00 };

int oncp_connect(struct openconnect_info *vpninfo)
{
	int ret, ofs, kmp, kmpend, kmplen, attr, attrlen, group, grouplen, groupend;
	struct oc_text_buf *reqbuf;
	unsigned char bytes[1024];
	/* XXX: We should do what cstp_connect() does to check that configuration
	   hasn't changed on a reconnect. */

	if (!vpninfo->cookies) {
		ret = parse_cookie(vpninfo);
		if (ret)
			return ret;
	}

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

 	buf_append(reqbuf, "POST /dana/js?prot=1&svc=1 HTTP/1.1\r\n");
	oncp_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating oNCP negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}

	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 0, NULL, reqbuf);
	if (ret < 0) {
		/* We'll already have complained about whatever offended us */
		goto out;
	}
	if (ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	/* Now the second request. We should reduce the duplication
	   here but let's not overthink it for now; we should see what
	   the authentication requests are going to look like, and make
	   do_https_request() or a new helper function work for those
	   too. */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;

	buf_truncate(reqbuf);
	buf_append(reqbuf, "POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n");
	oncp_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating oNCP negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 1, NULL, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	/* This is probably some kind of vestigial authentication packet, although
	 * it's mostly obsolete now that the authentication is really done over
	 * HTTP. We only send the hostname. */
	buf_truncate(reqbuf);
	buf_append_le16(reqbuf, sizeof(authpkt_head) + 2 +
			strlen(vpninfo->localname) + sizeof(authpkt_tail));
	buf_append_bytes(reqbuf, authpkt_head, sizeof(authpkt_head));
	buf_append_le16(reqbuf, strlen(vpninfo->localname));
	buf_append(reqbuf, "%s", vpninfo->localname);
	buf_append_bytes(reqbuf, authpkt_tail, sizeof(authpkt_tail));
	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating oNCP negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	buf_hexdump(vpninfo, reqbuf);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	/* Now we expect a three-byte response with what's presumably an
	   error code */
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, 3);
	if (ret < 0)
		goto out;

	if (ret != 3 || bytes[0] != 1 || bytes[1] != 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected response of size %d after hostname packet\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}
	if (bytes[2]) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Server response to hostname packet is error 0x%02x\n"),
			     bytes[2]);
		ret = -EINVAL;
		goto out;
	}

	/* And then a KMP message 301 with the IP configuration */
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;

	if (ret < 0x16 || bytes[0] + (bytes[1] << 8) + 2 != ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid packet waiting for KMP 301\n"));
		ret = -EINVAL;
		goto out;
	}

	ofs = 2;

	while (ofs < ret) {
		/* Check the KMP message header. */
		if (ofs + 20 > ret || memcmp(bytes + ofs, kmp_head, sizeof(kmp_head)) ||
		    memcmp(bytes + ofs + 8, kmp_tail, sizeof(kmp_tail))) {
		eparse:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse server response\n"));
			ret = -EINVAL;
			goto out;
		}
		kmp = bytes[ofs + 7] + (bytes[ofs + 6] << 8);
		kmplen = bytes[ofs + 19] + (bytes[ofs + 18] << 8);
		if (ofs + kmplen > ret)
			goto eparse;
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Got KMP message %d of size %d\n"),
			     kmp, kmplen);
		ofs += 0x14;
		kmpend = ofs + kmplen;
		if (kmp != 301)
			goto eparse;

		while (ofs < kmpend) {
			if (ofs + 6 > kmpend)
				goto eparse;
			group = (bytes[ofs] << 8) + bytes[ofs+1];
			grouplen = (bytes[ofs+2] << 24) + (bytes[ofs+3] << 16) +
				(bytes[ofs+4] << 8) + bytes[ofs+5];
			ofs += 6;
			groupend = ofs + grouplen;

			while (ofs < groupend) {
				if (ofs + 6 > groupend)
					goto eparse;
				attr = (bytes[ofs] << 8) + bytes[ofs+1];
				attrlen = (bytes[ofs+2] << 24) + (bytes[ofs+3] << 16) +
					(bytes[ofs+4] << 8) + bytes[ofs+5];
				ofs += 6;
				if (attrlen + ofs > groupend)
					goto eparse;
				if (process_attr(vpninfo, group, attr, bytes + ofs, attrlen))
					goto eparse;
				ofs += attrlen;
			}
		}
	}

	buf_truncate(reqbuf);
	buf_append_le16(reqbuf, 0); /* Length. We'll fix it later. */
	buf_append_bytes(reqbuf, kmp_head, sizeof(kmp_head));
	buf_append_le16(reqbuf, 303); /* KMP message 303 */
	buf_append_bytes(reqbuf, kmp_tail_out, sizeof(kmp_tail_out));
	buf_append_le16(reqbuf, 0); /* KMP message length */
	kmp = reqbuf->pos;
	buf_append_tlv(reqbuf, 6, 0, NULL); /* TLV group 6 */
	group = reqbuf->pos;
	buf_append_tlv_be32(reqbuf, 2, vpninfo->ip_info.mtu);
	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating oNCP negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	put_len32(reqbuf, group);
	put_len16(reqbuf, kmp);
	put_len16(reqbuf, 2);

	buf_hexdump(vpninfo,reqbuf);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);

 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	buf_free(reqbuf);
	return ret;
}

int oncp_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	return 0;
}
