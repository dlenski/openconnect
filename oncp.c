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

/*
 * Grateful thanks to Tiebing Zhang, who did much of the hard work
 * of analysing and decoding the protocol.
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
#include <sys/types.h>

#include "openconnect-internal.h"

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
			while (*p && isspace((int)(unsigned char)*p))
				p++;
		}
	}

	return 0;
}

static void buf_append_be16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	store_be16(b, val);

	buf_append_bytes(buf, b, 2);
}

static void buf_append_le16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	store_le16(b, val);

	buf_append_bytes(buf, b, 2);
}

static void buf_append_tlv(struct oc_text_buf *buf, uint16_t val, uint32_t len, void *data)
{
	unsigned char b[6];

	store_be16(b, val);
	store_be32(b + 2, len);
	buf_append_bytes(buf, b, 6);
	if (len)
		buf_append_bytes(buf, data, len);
}

static void buf_append_tlv_be32(struct oc_text_buf *buf, uint16_t val, uint32_t data)
{
	unsigned char d[4];

	store_be32(d, data);

	buf_append_tlv(buf, val, 4, d);
}

static void buf_hexdump(struct openconnect_info *vpninfo, unsigned char *d, int len)
{
	char linebuf[80];
	int i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			if (i)
				vpn_progress(vpninfo, PRG_DEBUG, "%s\n", linebuf);
			sprintf(linebuf, "%04x:", i);
		}
		sprintf(linebuf + strlen(linebuf), " %02x", d[i]);
	}
	vpn_progress(vpninfo, PRG_DEBUG, "%s\n", linebuf);
}

static const char authpkt_head[] = { 0x00, 0x04, 0x00, 0x00, 0x00 };
static const char authpkt_tail[] = { 0xbb, 0x01, 0x00, 0x00, 0x00, 0x00 };

#define GRP_ATTR(g, a) (((g) << 16) | (a))

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
		vpninfo->ip_info.mtu = load_be32(data);
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
		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS search domain %.*s\n"),
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
		vpninfo->ip_info.netmask = add_option(vpninfo, "netmask", buf, -1);
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

	case GRP_ATTR(3, 3): {
		struct oc_split_include *inc;
		if (attrlen != 8)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d/%d.%d.%d.%d",
			 data[0], data[1], data[2], data[3],
			 data[4], data[5], data[6], data[7]);
		vpn_progress(vpninfo, PRG_DEBUG, _("Received split include route %s\n"), buf);
		if (!data[4] && !data[5] && !data[6] && !data[7])
			break;
		inc = malloc(sizeof(*inc));
		if (inc) {
			inc->route = add_option(vpninfo, "split-include", buf, -1);
			if (inc->route) {
				inc->next = vpninfo->ip_info.split_includes;
				vpninfo->ip_info.split_includes = inc;
			} else
				free(inc);
		}
		break;
	}
	case GRP_ATTR(4, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received WINS server %s\n"), buf);

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.nbns[i]) {
				vpninfo->ip_info.nbns[i] = add_option(vpninfo, "WINS", buf, -1);
				break;
			}
		}
		break;

	case GRP_ATTR(8, 1): {
		const char *enctype;

		if (attrlen != 1)
			goto badlen;
		if (data[0] == 0x02)
			enctype = "AES-128";
		else if (data[0] == 0x05)
			enctype = "AES-256";
		else
			enctype = "unknown";
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP encryption: 0x%02x (%s)\n"),
			      data[0], enctype);
		vpninfo->esp_enc = data[0];
		break;
	}

	case GRP_ATTR(8, 2): {
		const char *mactype;

		if (attrlen != 1)
			goto badlen;
		if (data[0] == 0x01)
			mactype = "MD5";
		else if (data[0] == 0x02)
			mactype = "SHA1";
		else
			mactype = "unknown";
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP HMAC: 0x%02x (%s)\n"),
			      data[0], mactype);
		vpninfo->esp_hmac = data[0];
		break;
	}

	case GRP_ATTR(8, 3):
		if (attrlen != 1)
			goto badlen;
		vpninfo->esp_compr = data[0];
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP compression: %d\n"), data[0]);
		break;

	case GRP_ATTR(8, 4):
		if (attrlen != 2)
			goto badlen;
		i = load_be16(data);
		udp_sockaddr(vpninfo, i);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP port: %d\n"), i);
		break;

	case GRP_ATTR(8, 5):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_lifetime_bytes = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP key lifetime: %u bytes\n"),
			     vpninfo->esp_lifetime_bytes);
		break;

	case GRP_ATTR(8, 6):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_lifetime_seconds = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP key lifetime: %u seconds\n"),
			     vpninfo->esp_lifetime_seconds);
		break;

	case GRP_ATTR(8, 9):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_ssl_fallback = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP to SSL fallback: %u seconds\n"),
			     vpninfo->esp_ssl_fallback);
		break;

	case GRP_ATTR(8, 10):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_replay_protect = load_be32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP replay protection: %d\n"),
			     load_be32(data));
		break;

	case GRP_ATTR(7, 1):
		if (attrlen != 4)
			goto badlen;
		memcpy(&vpninfo->esp_out.spi, data, 4);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP SPI (outbound): %x\n"),
			     load_be32(data));
		break;

	case GRP_ATTR(7, 2):
		if (attrlen != 0x40)
			goto badlen;
		memcpy(vpninfo->esp_out.secrets, data, 0x40);
		vpn_progress(vpninfo, PRG_DEBUG, _("%d bytes of ESP secrets\n"),
			     attrlen);
		break;

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

	store_be16(buf->data + where - 2, len);
}

static void put_len32(struct oc_text_buf *buf, int where)
{
	int len = buf->pos - where;

	store_be32(buf->data + where - 4, len);
}


/* We don't know what these are so just hope they never change */
static const unsigned char kmp_head[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char kmp_tail[] = { 0x01, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char kmp_tail_out[] = { 0x01, 0x00, 0x00, 0x00, 0x01,
					      0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char data_hdr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					  0x01, 0x2c, 0x01, 0x00, 0x00, 0x00,
					  0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const unsigned char esp_kmp_hdr[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2e,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, /* KMP header */
	0x00, 0x56, /* KMP length */
	0x00, 0x07, 0x00, 0x00, 0x00, 0x50, /* TLV group 7 */
	0x00, 0x01, 0x00, 0x00, 0x00, 0x04, /* Attr 1 (SPI) */
};
/* Followed by 4 bytes of SPI */
static const unsigned char esp_kmp_part2[] = {
	0x00, 0x02, 0x00, 0x00, 0x00, 0x40, /* Attr 2 (secrets) */
};
/* And now 0x40 bytes of random secret for encryption and HMAC key */


static const struct pkt esp_enable_pkt = {
	.next = NULL,
	{ .oncp.hdr = {
		0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x2f, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x0d
	} },
	.data = {
		0x00, 0x06, 0x00, 0x00, 0x00, 0x07, /* Group 6, len 7 */
		0x00, 0x01, 0x00, 0x00, 0x00, 0x01, /* Attr 1, len 1 */
		0x01
	},
	.len = 13
};

int queue_esp_control(struct openconnect_info *vpninfo, int enable)
{
	struct pkt *new = malloc(sizeof(*new) + 13);
	if (!new)
		return -ENOMEM;

	memcpy(new, &esp_enable_pkt, sizeof(*new) + 13);
	new->data[12] = enable;
	queue_packet(&vpninfo->oncp_control_queue, new);
	return 0;
}

static int check_kmp_header(struct openconnect_info *vpninfo, unsigned char *bytes, int pktlen)
{
	if (pktlen < 20 || memcmp(bytes, kmp_head, sizeof(kmp_head)) ||
	    memcmp(bytes + 8, kmp_tail, sizeof(kmp_tail))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse KMP header\n"));
		return -EINVAL;
	}
	return load_be16(bytes + 6);
}

static int parse_conf_pkt(struct openconnect_info *vpninfo, unsigned char *bytes, int pktlen, int kmp)
{
	int kmplen, kmpend, grouplen, groupend, group, attr, attrlen;
	int ofs = 0;

	kmplen = load_be16(bytes + ofs + 18);
	kmpend = ofs + kmplen;
	if (kmpend > pktlen) {
	eparse:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse KMP message\n"));
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Got KMP message %d of size %d\n"),
		     kmp, kmplen);
	ofs += 0x14;

	while (ofs < kmpend) {
		if (ofs + 6 > kmpend)
			goto eparse;
		group = load_be16(bytes + ofs);
		grouplen = load_be32(bytes + ofs + 2);
		ofs += 6;
		groupend = ofs + grouplen;
		if (groupend > pktlen)
			goto eparse;

		if (kmp == 302 && group != 7 && group != 8) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Received non-ESP TLVs (group %d) in ESP negotiation KMP\n"),
				     group);
			return -EINVAL;
		}

		while (ofs < groupend) {
			if (ofs + 6 > groupend)
				goto eparse;
			attr = load_be16(bytes + ofs);
			attrlen = load_be32(bytes + ofs + 2);
			ofs += 6;
			if (attrlen + ofs > groupend)
				goto eparse;
			if (process_attr(vpninfo, group, attr, bytes + ofs, attrlen))
				goto eparse;
			ofs += attrlen;
		}
	}
	return 0;
}

int oncp_connect(struct openconnect_info *vpninfo)
{
	int ret, len, kmp, group;
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

	/* The server is fairly weird. It sends Connection: close which would
	 * indicate an HTTP 1.0-style body, but doesn't seem to actually close
	 * the connection. So tell process_http_response() it was a CONNECT
	 * request, since we don't care about the body anyway, and then close
	 * the connection for ourselves. */
	ret = process_http_response(vpninfo, 1, NULL, reqbuf);
	openconnect_close_https(vpninfo, 0);
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
	buf_hexdump(vpninfo, (void *)reqbuf->data, reqbuf->pos);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret != reqbuf->pos) {
		if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write in oNCP negotiation\n"));
			ret = -EIO;
		}
		goto out;
	}

	/* Now we expect a three-byte response with what's presumably an
	   error code */
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, 3);
	if (ret < 0)
		goto out;
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Read %d bytes of SSL record\n"), ret);
	
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
	len = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (len < 0) {
		ret = len;
		goto out;
	}
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Read %d bytes of SSL record\n"), len);

	if (len < 0x16 || load_le16(bytes) + 2 != len) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid packet waiting for KMP 301\n"));
		buf_hexdump(vpninfo, bytes, len);
		ret = -EINVAL;
		goto out;
	}

	ret = check_kmp_header(vpninfo, bytes + 2, len);
	if (ret < 0)
		goto out;

	/* We expect KMP message 301 here */
	if (ret != 301) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Expected KMP message 301 from server but got %d\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	ret = parse_conf_pkt(vpninfo, bytes + 2, len, ret);
	if (ret)
		goto out;

	buf_truncate(reqbuf);
	buf_append_le16(reqbuf, 0); /* Length. We'll fix it later. */
	buf_append_bytes(reqbuf, kmp_head, sizeof(kmp_head));
	buf_append_be16(reqbuf, 303); /* KMP message 303 */
	buf_append_bytes(reqbuf, kmp_tail_out, sizeof(kmp_tail_out));
	buf_append_be16(reqbuf, 0); /* KMP message length */
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

#if defined(ESP_GNUTLS) || defined(ESP_OPENSSL)
	if (!setup_esp_keys(vpninfo)) {
		struct esp *esp = &vpninfo->esp_in[vpninfo->current_esp_in];
		/* Since we'll want to do this in the oncp_mainloop too, where it's easier
		 * *not* to have an oc_text_buf and build it up manually, and since it's
		 * all fixed size and fairly simple anyway, just hard-code the packet */
		buf_append_bytes(reqbuf, esp_kmp_hdr, sizeof(esp_kmp_hdr));
		buf_append_bytes(reqbuf, &esp->spi, sizeof(esp->spi));
		buf_append_bytes(reqbuf, esp_kmp_part2, sizeof(esp_kmp_part2));
		buf_append_bytes(reqbuf, &esp->secrets, sizeof(esp->secrets));
		if (buf_error(reqbuf)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error negotiating ESP keys\n"));
			ret = buf_error(reqbuf);
			goto out;
		}
	}
#endif
	/* Length at the start of the packet is little-endian */
	store_le16(reqbuf->data, reqbuf->pos - 2);

	buf_hexdump(vpninfo, (void *)reqbuf->data, reqbuf->pos);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret == reqbuf->pos)
		ret = 0;
	else if (ret >= 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Short write in oNCP negotiation\n"));
		ret = -EIO;
	}
 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}
	buf_free(reqbuf);
	return ret;
}

static int oncp_receive_espkeys(struct openconnect_info *vpninfo, int len)
{
#if defined(ESP_GNUTLS) || defined(ESP_OPENSSL)
	int ret;

	ret = parse_conf_pkt(vpninfo, vpninfo->cstp_pkt->oncp.hdr + 2, len + 20, 301);
	if (!ret && !setup_esp_keys(vpninfo)) {
		struct esp *esp = &vpninfo->esp_in[vpninfo->current_esp_in];
		unsigned char *p = vpninfo->cstp_pkt->oncp.hdr + 2;

		memcpy(p, esp_kmp_hdr, sizeof(esp_kmp_hdr));
		p += sizeof(esp_kmp_hdr);
		memcpy(p, &esp->spi, sizeof(esp->spi));
		p += sizeof(esp->spi);
		memcpy(p, esp_kmp_part2, sizeof(esp_kmp_part2));
		p += sizeof(esp_kmp_part2);
		memcpy(p, esp->secrets, sizeof(esp->secrets));
		p += sizeof(esp->secrets);
		vpninfo->cstp_pkt->len = p - vpninfo->cstp_pkt->data;
		store_le16(vpninfo->cstp_pkt->oncp.hdr,
			   (p - vpninfo->cstp_pkt->oncp.hdr - 2));

		queue_packet(&vpninfo->oncp_control_queue, vpninfo->cstp_pkt);
		vpninfo->cstp_pkt = NULL;

		print_esp_keys(vpninfo, _("new incoming"), esp);
		print_esp_keys(vpninfo, _("new outgoing"), &vpninfo->esp_out);
	}
	return ret;
#else
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Ignoring ESP keys since ESP support not available in this build\n"));
	return 0;
#endif
}

static int oncp_receive_data(struct openconnect_info *vpninfo, int len, int unreceived)
{
	struct pkt *pkt = vpninfo->cstp_pkt;
	int pktlen;
	int ret;

	while (1) {
		/*
		 * 'len' is the total amount of data remaining in thie SSL record,
		 * of which 'unreceived' has yet to be received.
		 *
		 * We have already got (len - unreceived) bytes in vpninfo->cstp_pkt,
		 * and if unreceived is not zero then we'll have a full MTU, thus
		 * len - unreceived == vpninfo->ip_info.mtu.
		 *
		 * So we know we should have at least one complete IP packet, and
		 * maybe more. Receive the IP packet, copy any remaining bytes into
		 * a newly-allocated 'struct pkt', read any more bytes from the SSL
		 * record that we need to make the above still true, and repeat.
		 */

		/* Ick. Windows doesn't give us 'struct ip', AFAICT. */
		switch(pkt->data[0] >> 4) {
		case 4:
			pktlen = load_be16(pkt->data + 2);
			break;
		case 6:
			pktlen = load_be16(pkt->data + 4);
			break;
		default:
		badlen:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unrecognised data packet starting %02x %02x %02x %02x %02x %02x %02x %02x\n"),
				     pkt->data[0], pkt->data[1], pkt->data[2], pkt->data[3],
				     pkt->data[4], pkt->data[5], pkt->data[6], pkt->data[7]);
			/* Drain the unreceived bytes if we want to continue */
			return -EINVAL;
		}

		/* Should never happen, but would cause an endless loop if it did. */
		if (!pktlen || pktlen > vpninfo->ip_info.mtu)
			goto badlen;

		/* Receive this packet */
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received uncompressed data packet of %d bytes\n"),
			     pktlen);
		pkt->len = pktlen;
		queue_packet(&vpninfo->incoming_queue, pkt);
		vpninfo->cstp_pkt = NULL;

		len -= pktlen;
		if (!len) /* Common case */
			return 0;

		/* Allocate the *next* packet to be received */
		vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + vpninfo->ip_info.mtu);
		if (!vpninfo->cstp_pkt) {
			vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
			/* Drain the unreceived bytes if we want to continue */
			return -ENOMEM;
		}

		/* Copy any extra bytes from the tail of 'pkt', which is already
		 * on the RX queue, into the next packet. */
		if (len - unreceived)
			memcpy(vpninfo->cstp_pkt->data,
			       pkt->data + pktlen,
			       len - unreceived);

		pkt = vpninfo->cstp_pkt;

		if (unreceived) {
			int retried = 0;

			/* The length of the previous packet is the amount by
			 * which we need to replenish the buffer. */
			if (pktlen > unreceived)
				pktlen = unreceived;
		retry:
			/* This is a *blocking* read, since if the crypto library
			 * already started returning the first part of this SSL
			 * record then it damn well ought to have the rest of it
			 * available already. */
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Reading additional %d bytes (of %d still unreceived) from oNCP...\n"),
				     pktlen, unreceived);
			ret = vpninfo->ssl_read(vpninfo, (void *)(pkt->data + (len - unreceived)),
						pktlen);
			if (ret < 0)
				return ret;
			if (ret != pktlen && !retried) {
				/* This can happen when there are *so* many IP packets in a single oNCP
				   packet that it exceeds the 16KiB maximum size of a SSL record. So
				   in that case the above comment about a blocking read is invalid; we
				   *could* end up waiting here. We should actually fix things to be
				   completely asynchronous, storing the 'len' and 'unreceived' variables
				   in the vpninfo structure and getting back into this loop directly
				   from oncp_mainloop(). But I'm not going to lose too much sleep
				   over that just yet. After all, we wouldn't be receiving data here
				   if the ESP was up — we know there's no *other* data transport that
				   the mainloop should be servicing while it's blocked. Perhaps we could
				   be sending packets on *this* TCP connection while we wait for the
				   next SSL record to arrive, though. */
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Short read on (%d < %d) on large KMP message. Trying again in case it crossed SSL record boundary\n"),
					     ret, pktlen);
				unreceived -= ret;
				pktlen -= ret;
				retried = 1;
				goto retry;
			}
			if (ret != pktlen) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Short read for end of large KMP message. Expected %d, got %d bytes\n"),
					     pktlen, ret);
				return -EIO;
			}
			unreceived -= pktlen;
		}
	}
}

int oncp_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int ret;
	int work_done = 0;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while (1) {
		int len = vpninfo->ip_info.mtu;
		int kmp, kmplen, reclen;
		int morecoming;
		int followon; /* 0 for the first time round, 2 later to skip the length word */

		followon = 0;

	next_kmp:
		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + len);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		/*
		 * The first two bytes of each SSL record contain the (little-endian)
		 * length of that record. On the wire it's arguably redundant, but
		 * it's nice to have it here and just be able to read() from the SSL
		 * "stream" in the knowledge that a single read call will never cross
		 * record boundaries.
		 *
		 * An SSL record may contain multiple KMP messages. And a KMP message
		 * of type 300 (data) can evidently contain multiple IP packets with
		 * nothing to split them apart except the length field in the IP
		 * packet itself.
		 *
		 * But the *common* case is that we read a full SSL record which
		 * contains a single KMP message 300, which contains a single IP
		 * packet. So receive it into the appropriate place in a struct pkt
		 * so that we can just pass it up the stack. And cope with the rest
		 * as corner cases.
		 */

		len = ssl_nonblock_read(vpninfo, vpninfo->cstp_pkt->oncp.hdr + followon,
					22 - followon);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len == 3 && !followon &&
		    vpninfo->cstp_pkt->oncp.hdr[0] == 0 &&
		    vpninfo->cstp_pkt->oncp.hdr[1] == 0 &&
		    vpninfo->cstp_pkt->oncp.hdr[2] == 1) {
			/* This protocol is entirely fucked up. They appear to
			 * send 00 00 01 to indicate the session expired. */
			vpn_progress(vpninfo, PRG_ERR,
				     _("VPN session expired\n"));
			vpninfo->quit_reason = "VPN session expired\n";
			return -EPIPE;
		}
		if (len != 22 - followon) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read KMP header from SSL stream; only %d bytes available of %d\n"),
				     len, 22 - followon);
			buf_hexdump(vpninfo, vpninfo->cstp_pkt->oncp.hdr + followon, len - followon);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		if (!followon) {
			/* This is the length of the packet (little-endian) */
			reclen = load_le16(vpninfo->cstp_pkt->oncp.hdr);
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Incoming oNCP packet of size %d\n"), reclen);
		}
		if (reclen < 20) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Packet too small (%d bytes) to contain KMP message header\n"),
				     reclen);
			vpninfo->quit_reason = "Failed to packetise stream";
			return 1;
		}

		kmp = load_be16(vpninfo->cstp_pkt->oncp.hdr + 8);
		kmplen = load_be16(vpninfo->cstp_pkt->oncp.hdr + 20);
		if (kmplen + 20 > reclen) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("KMP message larger than packet (%d > %d)\n"),
				     kmplen + 20, reclen);
			vpninfo->quit_reason = "KMP message too large";
			return 1;
		}
		/* Now read as much of the first KMP message from the packet
		 * as fits into the MTU. */
		if (kmplen > vpninfo->ip_info.mtu) {
			len = vpninfo->ip_info.mtu;
			morecoming = kmplen - len;
		} else {
			len = kmplen;
			morecoming = 0;
		}
		if (len) {
			/* This is a *blocking* read, since if the crypto library
			 * already started returning the first part of this SSL
			 * record then it damn well ought to have the rest of it
			 * available already. */
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Reading additional %d bytes from oNCP...\n"),
				     len);
			ret = vpninfo->ssl_read(vpninfo, (void *)vpninfo->cstp_pkt->data, len);
			if (ret != len) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Short read of KMP message. Expected %d, got %d bytes\n"),
					     len, ret);
				/* Just to set up the debugging hex dump of it... */
				morecoming = len - ret;
				goto unknown_pkt;
			}
		}
		vpn_progress(vpninfo, PRG_DEBUG, _("Incoming KMP message %d of size %d\n"),
			     kmp, kmplen);

		vpninfo->ssl_times.last_rx = time(NULL);
		switch (kmp) {
		case 300:
			ret = oncp_receive_data(vpninfo, kmplen, morecoming);
			if (ret) {
				vpninfo->quit_reason = "Failed to read KMP data message";
				return 1;
			}
			work_done = 1;
			break;

		case 302:
			if (morecoming)
				goto unknown_pkt;
			ret = oncp_receive_espkeys(vpninfo, kmplen);
			work_done = 1;
			break;

		default:
		unknown_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown KMP message %d of size %d:\n"), kmp, kmplen);
			buf_hexdump(vpninfo, vpninfo->cstp_pkt->oncp.hdr,
				    kmplen + 22 - morecoming);
			if (morecoming)
				vpn_progress(vpninfo, PRG_DEBUG,
					     _(".... + %d more bytes unreceived\n"),
					     morecoming);
			vpninfo->quit_reason = "Unknown packet received";
			return 1;
		}

		reclen -= kmplen + 20;
		if (reclen) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Still %d bytes left in this packet. Looping...\n"),
				     reclen);
			followon = 2;
			goto next_kmp;
		}
	}

	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		vpn_progress(vpninfo, PRG_TRACE, _("Packet outgoing:\n"));
		buf_hexdump(vpninfo, vpninfo->current_ssl_pkt->oncp.hdr,
			    vpninfo->current_ssl_pkt->len + 22);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->oncp.hdr,
					 vpninfo->current_ssl_pkt->len + 22);
		if (ret < 0) {
		do_reconnect:
			/* XXX: Do we have to do this or can we leave it open?
			 * Perhaps we could even reconnect asynchronously while
			 * the ESP is still running? */
			esp_shutdown(vpninfo);
			ret = ssl_reconnect(vpninfo);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
				vpninfo->quit_reason = "oNCP reconnect failed";
				return ret;
			}
			vpninfo->dtls_need_reconnect = 1;
			return 1;
		} else if (!ret) {
#if 0 /* Not for Juniper yet */
			/* -EAGAIN: ssl_nonblock_write() will have added the SSL
			   fd to ->select_wfds if appropriate, so we can just
			   return and wait. Unless it's been stalled for so long
			   that DPD kicks in and we kill the connection. */
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_REKEY:
				goto do_rekey;
			case KA_NONE:
				return work_done;
			default:
				/* This should never happen */
				;
			}
#else
			return work_done;
#endif
		}

		if (ret != vpninfo->current_ssl_pkt->len + 22) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 22, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt == vpninfo->deflate_pkt) {
			free(vpninfo->pending_deflated_pkt);
		} else {
			/* Only set the ESP state to connected and actually start
			   sending packets on it once the enable message has been
			   *sent* over the TCP channel. */
			if (vpninfo->dtls_state == DTLS_CONNECTING &&
			    vpninfo->current_ssl_pkt->len == 13 &&
			    load_be16(&vpninfo->current_ssl_pkt->oncp.hdr[8]) == 0x12f &&
			    vpninfo->current_ssl_pkt->data[12]) {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Sent ESP enable control packet\n"));
				vpninfo->dtls_state = DTLS_CONNECTED;
				work_done = 1;
			}
			free(vpninfo->current_ssl_pkt);
		}
		vpninfo->current_ssl_pkt = NULL;
	}

#if 0 /* Not understood for Juniper yet */
	if (vpninfo->owe_ssl_dpd_response) {
		vpninfo->owe_ssl_dpd_response = 0;
		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_resp_pkt;
		goto handle_outgoing;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		/* Not that this will ever happen; we don't even process
		   the setting when we're asked for it. */
		vpn_progress(vpninfo, PRG_INFO, _("CSTP rekey due\n"));
		if (vpninfo->ssl_times.rekey_method == REKEY_TUNNEL)
			goto do_reconnect;
		else if (vpninfo->ssl_times.rekey_method == REKEY_SSL) {
			ret = cstp_handshake(vpninfo, 0);
			if (ret) {
				/* if we failed rehandshake try establishing a new-tunnel instead of failing */
				vpn_progress(vpninfo, PRG_ERR, _("Rehandshake failed; attempting new-tunnel\n"));
				goto do_reconnect;
			}

			goto do_dtls_reconnect;
		}
		break;

	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("CSTP Dead Peer Detection detected dead peer!\n"));
	do_reconnect:
		ret = cstp_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "CSTP reconnect failed";
			return ret;
		}

	do_dtls_reconnect:
		/* succeeded, let's rekey DTLS, if it is not rekeying
		 * itself. */
		if (vpninfo->dtls_state > DTLS_SLEEPING &&
		    vpninfo->dtls_times.rekey_method == REKEY_NONE) {
			vpninfo->dtls_need_reconnect = 1;
		}

		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP DPD\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED && vpninfo->outgoing_queue)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP Keepalive\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		goto handle_outgoing;

	case KA_NONE:
		;
	}
#endif
	vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->oncp_control_queue);
	if (vpninfo->current_ssl_pkt)
		goto handle_outgoing;

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		/* Little-endian overall record length */
		store_le16(this->oncp.hdr, (this->len + 20));
		memcpy(this->oncp.hdr + 2, data_hdr, 18);
		/* Big-endian length in KMP message header */
		store_be16(this->oncp.hdr + 20, this->len);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending uncompressed data packet of %d bytes\n"),
			     this->len);

		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}
