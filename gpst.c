/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Author: Daniel Lenski <dlenski@gmail.com>
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
#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#if defined(__linux__)
/* For TCP_INFO */
# include <linux/tcp.h>
#endif

#include <assert.h>

#include "openconnect-internal.h"

/*
 * Data packets are encapsulated in the SSL stream as follows:
 *
 * 0000: Magic "\x1a\x2b\x3c\x4d"
 * 0004: Big-endian EtherType (0x0800 for IPv4)
 * 0006: Big-endian 16-bit length (not including 16-byte header)
 * 0008: Always "\x01\0\0\0\0\0\0\0"
 * 0010: data payload
 */

static const struct pkt dpd_pkt = { .gpst.hdr = { 0x1a, 0x2b, 0x3c, 0x4d } };

static void buf_hexdump(struct openconnect_info *vpninfo, int loglevel, unsigned char *d, int len)
{
	char linebuf[80];
	int i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			if (i)
				vpn_progress(vpninfo, loglevel, "%s\n", linebuf);
			sprintf(linebuf, "%04x:", i);
		}
		sprintf(linebuf + strlen(linebuf), " %02x", d[i]);
	}
	vpn_progress(vpninfo, loglevel, "%s\n", linebuf);
}

/* similar to auth.c's xmlnode_get_text, except that *var should be freed by the caller */
static int xmlnode_get_text(xmlNode *xml_node, const char *name, const char **var)
{
	const char *str;

	if (name && !xmlnode_is_named(xml_node, name))
		return -EINVAL;

	str = (const char *)xmlNodeGetContent(xml_node);
	if (!str)
		return -ENOENT;

	*var = str;
	return 0;
}

/* basically a copy of http_add_cookie */
static int set_option(struct openconnect_info *vpninfo, const char *option,
		      const char *value, int replace)
{
	struct oc_vpn_option *new, **this;

	if (*value) {
		new = malloc(sizeof(*new));
		if (!new) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("No memory for allocating options\n"));
			return -ENOMEM;
		}
		new->next = NULL;
		new->option = strdup(option);
		new->value = strdup(value);
		if (!new->option || !new->value) {
			free(new->option);
			free(new->value);
			free(new);
			return -ENOMEM;
		}
	} else {
		/* Kill option; don't replace it */
		new = NULL;
		/* This would be meaningless */
		if (!replace)
			return -EINVAL;
	}
	for (this = &vpninfo->cstp_options; *this; this = &(*this)->next) {
		if (!strcmp(option, (*this)->option)) {
			if (!replace) {
				free(new->value);
				free(new->option);
				free(new);
				return 0;
			}
			/* Replace existing option */
			if (new)
				new->next = (*this)->next;
			else
				new = (*this)->next;

			free((*this)->option);
			free((*this)->value);
			free(*this);
			*this = new;
			break;
		}
	}
	if (new && !*this) {
		*this = new;
		new->next = NULL;
	}
	return 0;
}

static int parse_cookie(struct openconnect_info *vpninfo)
{
	char *p = vpninfo->cookie;

	/* We currently expect the "cookie" to contain multiple options:
	 * USER=xxx; AUTH=xxx; PORTAL=xxx; DOMAIN=xxx
	 * Process those into vpninfo->cstp_options unless we already had them
	 * (in which case they may be newer). */
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
		set_option(vpninfo, p, equals+1, 0);
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

static int set_esp_algo(struct openconnect_info *vpninfo, const char *s, int hmac)
{
	if (hmac && !strcmp(s, "sha1"))		vpninfo->esp_hmac = HMAC_SHA1;
	else if (hmac && !strcmp(s, "md5"))	vpninfo->esp_hmac = HMAC_MD5;
	else if (!strcmp(s, "aes-128-cbc"))	vpninfo->esp_enc = ENC_AES_128_CBC;
	else if (!strcmp(s, "aes-256-cbc"))	vpninfo->esp_enc = ENC_AES_256_CBC;
	else return -ENOENT;
	return 0;
}

static int get_key_bits(xmlNode *xml_node, unsigned char *dest)
{
	int bits = -EINVAL;
	xmlNode *child;
	const char *s, *p;

	for (child = xml_node->children; child; child=child->next) {
		if (xmlnode_get_text(child, "bits", &s) == 0) {
			bits = atoi(s);
			free((void *)s);
		} else if (xmlnode_get_text(child, "val", &s) == 0) {
			for (p=s; *p && *(p+1); p+=2)
				*dest++ = unhex(p);
			free((void *)s);
		}
	}
	return (bits >> 3); /* we expect output in bytes */
}

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int gpst_parse_config_xml(struct openconnect_info *vpninfo, char *response)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *member;
	const char *err = NULL, *s;
	int success, ii;

	if (!response) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc)
		goto bad_xml;

	xml_node = xmlDocGetRootElement(xml_doc);
	if (!xml_node || !xmlnode_is_named(xml_node, "response"))
		goto bad_xml;
	success = !xmlnode_match_prop(xml_node, "status", "success");
	xml_node = xml_node->children;

	for (; xml_node; xml_node=xml_node->next) {
		xmlnode_get_text(xml_node, "error", &err);
		xmlnode_get_text(xml_node, "ip-address", &vpninfo->ip_info.addr);
		xmlnode_get_text(xml_node, "netmask", &vpninfo->ip_info.netmask);

		if (!xmlnode_get_text(xml_node, "ssl-tunnel-url", &s)) {
			set_option(vpninfo, "tunnel", s, 1);
			free((void *)s);
		} else if (!xmlnode_get_text(xml_node, "mtu", &s)) {
			vpninfo->ip_info.mtu = atoi(s);
			free((void *)s);
		} else if (xmlnode_is_named(xml_node, "dns")) {
			for (ii=0, member = xml_node->children; member && ii<3; member=member->next)
				if (!xmlnode_get_text(member, "member", &vpninfo->ip_info.dns[ii]))
					ii++;
		} else if (xmlnode_is_named(xml_node, "wins")) {
			for (ii=0, member = xml_node->children; member && ii<3; member=member->next)
				if (!xmlnode_get_text(member, "member", &vpninfo->ip_info.nbns[ii]))
					ii++;
		} if (xmlnode_is_named(xml_node, "dns-suffix")) {
			for (ii=0, member = xml_node->children; member && ii<1; member=member->next)
				if (!xmlnode_get_text(member, "member", &vpninfo->ip_info.domain))
					ii++;
		} else if (xmlnode_is_named(xml_node, "access-routes")) {
			for (member = xml_node->children; member; member=member->next) {
				if (!xmlnode_get_text(member, "member", &s)) {
					struct oc_split_include *inc = malloc(sizeof(*inc));
					if (!inc)
						continue;
					inc->route = s;
					inc->next = vpninfo->ip_info.split_includes;
					vpninfo->ip_info.split_includes = inc;
				}
			}
		} else if (xmlnode_is_named(xml_node, "ipsec")) {
#ifdef HAVE_ESP
			unsigned char in_mackey[0x40], out_mackey[0x40];
			int in_enclen=0, out_enclen=0, in_maclen=0, out_maclen=0;
			for (member = xml_node->children; member; member=member->next) {
				s = NULL;
				if (!xmlnode_get_text(member, "udp-port", &s))		udp_sockaddr(vpninfo, atoi(s));
				else if (!xmlnode_get_text(member, "enc-algo", &s)) 	set_esp_algo(vpninfo, s, 0);
				else if (!xmlnode_get_text(member, "hmac-algo", &s))	set_esp_algo(vpninfo, s, 1);
				else if (!xmlnode_get_text(member, "c2s-spi", &s))	vpninfo->esp_out.spi = htonl(strtoul(s, NULL, 16));
				else if (!xmlnode_get_text(member, "s2c-spi", &s))	vpninfo->esp_in[0].spi = htonl(strtoul(s, NULL, 16));
				else if (xmlnode_is_named(member, "ekey-c2s"))		out_enclen = get_key_bits(member, vpninfo->esp_out.secrets);
				else if (xmlnode_is_named(member, "ekey-s2c"))		in_enclen = get_key_bits(member, vpninfo->esp_in[0].secrets);
				else if (xmlnode_is_named(member, "akey-c2s"))		out_maclen = get_key_bits(member, out_mackey);
				else if (xmlnode_is_named(member, "akey-s2c"))		in_maclen = get_key_bits(member, in_mackey);
				free((void *)s);
			}
			if (in_enclen && in_maclen)
				memcpy(vpninfo->esp_in[0].secrets + in_enclen, in_mackey, in_maclen);
			if (out_enclen && out_maclen)
				memcpy(vpninfo->esp_out.secrets + out_enclen, out_mackey, out_maclen);
			if (vpninfo->dtls_state != DTLS_DISABLED
			    && setup_esp_keys(vpninfo, FALSE)) {
				vpn_progress(vpninfo, PRG_ERR, "Failed to setup ESP keys.\n");
				vpninfo->dtls_state = DTLS_NOSECRET;
			}
#else
			vpn_progress(vpninfo, PRG_DEBUG, _("Ignoring ESP keys since ESP support not available in this build\n"));
#endif
		}
	}

	/* No IPv6 support for SSL VPN:
	 * https://live.paloaltonetworks.com/t5/Learning-Articles/IPv6-Support-on-the-Palo-Alto-Networks-Firewall/ta-p/52994 */
	openconnect_disable_ipv6(vpninfo);

	/* Set 10-second DPD/keepalive (same as Windows client) unless
	 * overridden with --force-dpd */
	if (!vpninfo->ssl_times.dpd)
		vpninfo->ssl_times.dpd = 10;
	vpninfo->ssl_times.keepalive = vpninfo->ssl_times.dpd;

	xmlFreeDoc(xml_doc);
	if (success)
		return 0;
	else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error fetching configuration: %s\n"), err);
		return strcasestr(err ? : "", "auth") ? -EPERM : -EINVAL;
	}

bad_xml:
	if (xml_doc)
		xmlFreeDoc(xml_doc);
	vpn_progress(vpninfo, PRG_ERR,
			 _("Failed to parse server response\n"));
	vpn_progress(vpninfo, PRG_DEBUG,
			 _("Response was: %s\n"), response);
	return -EINVAL;
}

static int gpst_get_config(struct openconnect_info *vpninfo)
{
	char *orig_path, *orig_ua;
	int result, ii;
	struct oc_vpn_option *opt;
	struct oc_text_buf *request_body = buf_alloc();
	const char *old_addr = vpninfo->ip_info.addr, *old_netmask = vpninfo->ip_info.netmask;
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL;

	/* Clear old options which will be overwritten */
	vpninfo->ip_info.addr = vpninfo->ip_info.netmask = NULL;
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->ip_info.domain = NULL;

	for (ii = 0; ii < 3; ii++)
		vpninfo->ip_info.dns[ii] = vpninfo->ip_info.nbns[ii] = NULL;
	free_split_routes(vpninfo);

	/* submit getconfig request */
	buf_append(request_body, "client-type=1&protocol-version=p1&app-version=3.0.1-10");
	append_opt(request_body, "os-version", vpninfo->platname);
	append_opt(request_body, "clientos", vpninfo->platname);
	append_opt(request_body, "hmac-algo", "sha1,md5");
	append_opt(request_body, "enc-algo", "aes-128-cbc,aes-256-cbc");
	if (old_addr)
		append_opt(request_body, "preferred-ip", old_addr);
	for (opt = vpninfo->cstp_options; opt; opt = opt->next) {
		if (!strcmp(opt->option, "USER"))
			append_opt(request_body, "user", opt->value);
		else if (!strcmp(opt->option, "AUTH"))
			append_opt(request_body, "authcookie", opt->value);
		else if (!strcmp(opt->option, "PORTAL"))
			append_opt(request_body, "portal", opt->value);
	}

	orig_path = vpninfo->urlpath;
	orig_ua = vpninfo->useragent;
	vpninfo->useragent = (char *)"PAN GlobalProtect";
	vpninfo->urlpath = (char *)"ssl-vpn/getconfig.esp";
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	vpninfo->urlpath = orig_path;
	vpninfo->useragent = orig_ua;

	if (result < 0)
		goto out;

	/* parse getconfig result */
	result = gpst_parse_config_xml(vpninfo, xml_buf);
	if (result)
		return result;

	if (!vpninfo->ip_info.mtu) {
		/* FIXME: GP gateway config always seems to be <mtu>0</mtu> */
		vpninfo->ip_info.mtu = vpninfo->reqmtu ? : vpninfo->basemtu ? : 1500;
		vpn_progress(vpninfo, PRG_ERR,
			     _("No MTU received. Set to %d\n"), vpninfo->ip_info.mtu);
		/* return -EINVAL; */
	}
	if (!vpninfo->ip_info.addr) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No IP address received. Aborting\n"));
		result = -EINVAL;
		goto out;
	}
	if (old_addr) {
		if (strcmp(old_addr, vpninfo->ip_info.addr)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP address (%s != %s)\n"),
				     vpninfo->ip_info.addr, old_addr);
			result = -EINVAL;
			goto out;
		}
	}
	if (old_netmask) {
		if (strcmp(old_netmask, vpninfo->ip_info.netmask)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP netmask (%s != %s)\n"),
				     vpninfo->ip_info.netmask, old_netmask);
			result = -EINVAL;
			goto out;
		}
	}

out:
	buf_free(request_body);
	free(xml_buf);
	return 0;
}

int gpst_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	char buf[256];

	ret = parse_cookie(vpninfo);
	if (ret)
		return ret;

	/* Get configuration */
	ret = gpst_get_config(vpninfo);
	if (ret)
		return ret;

	/* Connect to SSL VPN tunnel */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET %s?user=", tunnel);
	buf_append_urlencoded(reqbuf, username);
	buf_append(reqbuf, "&authcookie=%s HTTP/1.1\r\n\r\n", authcookie);

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	buf_free(reqbuf);

	if ((ret = vpninfo->ssl_read(vpninfo, buf, 12)) < 0) {
		if (ret == -EINTR)
			return ret;
		vpn_progress(vpninfo, PRG_ERR,
		             _("Error fetching GET-tunnel HTTPS response.\n"));
		return -EINVAL;
	}

	if (!strncmp(buf, "START_TUNNEL", 12)) {
		ret = 0;
	} else if (ret==0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Gateway disconnected immediately after GET-tunnel request.\n"));
		ret = -EPIPE;
	} else {
		if (ret==12) {
			ret = vpninfo->ssl_gets(vpninfo, buf+12, 244);
			ret = (ret>0 ? ret : 0) + 12;
		}
		vpn_progress(vpninfo, PRG_ERR,
		             _("Got inappropriate HTTP GET-tunnel response: %.*s\n"), ret, buf);
		ret = -EINVAL;
	}

	if (ret < 0)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
		vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
	}


	return ret;
}

int gpst_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int ret;
	int work_done = 0;
	uint16_t ethertype;
	uint32_t one, zero, magic;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	while (1) {
		int len = MAX(16384, vpninfo->ip_info.mtu);
		int payload_len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + len);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, vpninfo->cstp_pkt->gpst.hdr, len + 16);
		if (!len)
			break;
		if (len < 0) {
			vpn_progress(vpninfo, PRG_ERR, _("Packet receive error: %s\n"), strerror(-len));
			goto do_reconnect;
		}
		if (len < 16) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		/* check packet header */
		magic = load_be32(vpninfo->cstp_pkt->gpst.hdr);
		ethertype = load_be16(vpninfo->cstp_pkt->gpst.hdr + 4);
		payload_len = load_be16(vpninfo->cstp_pkt->gpst.hdr + 6);
		one = load_le32(vpninfo->cstp_pkt->gpst.hdr + 8);
		zero = load_le32(vpninfo->cstp_pkt->gpst.hdr + 12);

		if (magic != 0x1a2b3c4d)
			goto unknown_pkt;

		if (len != 16 + payload_len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected packet length. SSL_read returned %d (includes 16 header bytes) but header payload_len is %d\n"),
			             len, payload_len);
			buf_hexdump(vpninfo, PRG_ERR, vpninfo->cstp_pkt->gpst.hdr, 16);
			continue;
		}

		vpninfo->ssl_times.last_rx = time(NULL);
		switch (ethertype) {
		case 0:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Got GPST DPD/keepalive response\n"));

			if (one != 0 || zero != 0) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Expected 0000000000000000 as last 8 bytes of DPD/keepalive packet header, but got:\n"));
				buf_hexdump(vpninfo, PRG_DEBUG, vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}
			continue;
		case 0x0800:
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received data packet of %d bytes\n"),
				     payload_len);
			vpninfo->cstp_pkt->len = payload_len;
			queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			work_done = 1;

			if (one != 1 || zero != 0) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Expected 0100000000000000 as last 8 bytes of data packet header, but got:\n"));
				buf_hexdump(vpninfo, PRG_ERR, vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}
			continue;
		}

	unknown_pkt:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown packet. Header dump follows:\n"));
		buf_hexdump(vpninfo, PRG_ERR, vpninfo->cstp_pkt->gpst.hdr, 16);
		vpninfo->quit_reason = "Unknown packet received";
		return 1;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->gpst.hdr,
					 vpninfo->current_ssl_pkt->len + 16);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_NONE:
				return work_done;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len + 16) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 16, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt != &dpd_pkt)
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("GPST Dead Peer Detection detected dead peer!\n"));
	do_reconnect:
		ret = ssl_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "GPST reconnect failed";
			return ret;
		}
		return 1;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send GPST DPD/keepalive request\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;
	}


	/* Service outgoing packet queue */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		/* store header */
		store_be32(this->gpst.hdr, 0x1a2b3c4d);
		store_be16(this->gpst.hdr + 4, 0x0800); /* IPv4 EtherType */
		store_be16(this->gpst.hdr + 6, this->len);
		store_le32(this->gpst.hdr + 8, 1);
		store_le32(this->gpst.hdr + 12, 0);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending data packet of %d bytes\n"),
			     this->len);

		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}
