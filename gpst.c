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

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int gpst_parse_config_xml(struct openconnect_info *vpninfo, char *response)
{
	struct oc_text_buf *cookie = buf_alloc();
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *member;
	int ret, ii, mtu;

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
	if (!xmlnode_is_named(xml_node, "response"))
		goto bad_xml;
	if (!strcmp(xmlGetProp(xml_node, "status"),"error")) {
		xmlFreeDoc(xml_doc);
		return -EPERM;
	}
	if (strcmp(xmlGetProp(xml_node, "status"),"success"))
		goto bad_xml;
	xml_node = xml_node->children;

	for (; xml_node; xml_node=xml_node->next) {
		if (xmlnode_is_named(xml_node, "ip-address")) {
			vpninfo->ip_info.addr = xmlNodeGetContent(xml_node);
		} else if (xmlnode_is_named(xml_node, "netmask")) {
			vpninfo->ip_info.netmask = xmlNodeGetContent(xml_node);
		} else if (xmlnode_is_named(xml_node, "ssl-tunnel-url")) {
			vpninfo->urlpath = xmlNodeGetContent(xml_node);
		} else if (xmlnode_is_named(xml_node, "mtu")) {
			mtu = atoi(xmlNodeGetContent(xml_node));
			if (mtu==0) {
				vpn_progress(vpninfo, PRG_ERR, "Replacing MTU of 0 with 1500\n");
				mtu = 1500;
			}
			vpninfo->ip_info.mtu = mtu;
		} else if (xmlnode_is_named(xml_node, "dns")) {
			for (ii=0, member = xml_node->children; member && ii<3; member=member->next) {
				if (xmlnode_is_named(member, "member"))
					vpninfo->ip_info.dns[ii++] = xmlNodeGetContent(member);
			}
		} else if (xmlnode_is_named(xml_node, "wins")) {
			for (ii=0, member = xml_node->children; member && ii<3; member=member->next) {
				if (xmlnode_is_named(member, "member"))
					vpninfo->ip_info.nbns[ii++] = xmlNodeGetContent(member);
			}
		} else if (xmlnode_is_named(xml_node, "dns-suffix")) {
			member = xml_node->children;
			for (ii=0, member = xml_node->children; member && ii<1; member=member->next) {
				if (xmlnode_is_named(member, "member")) {
					vpninfo->ip_info.domain = xmlNodeGetContent(member);
					ii++;
				}
			}
		} else if (xmlnode_is_named(xml_node, "access-routes")) {
			for (ii=0, member = xml_node->children; member; member=member->next) {
				if (xmlnode_is_named(member, "member")) {
					struct oc_split_include *s = calloc(1, sizeof(struct oc_split_include)), *t;
					s->route = xmlNodeGetContent(member);

					if ((t = vpninfo->ip_info.split_includes) == NULL) {
						vpninfo->ip_info.split_includes = s;
					} else {
						while(t->next)
							t = t->next;
						t->next = s;
					}
				}
			}
		}
	}

	/* No IPv6 support for GlobalProtect yet */
	openconnect_disable_ipv6(vpninfo);

	xmlFreeDoc(xml_doc);
	return 0;

bad_xml:
	if (xml_doc)
		xmlFreeDoc(xml_doc);
	vpn_progress(vpninfo, PRG_ERR,
			 _("Failed to parse server response\n"));
	vpn_progress(vpninfo, PRG_DEBUG,
			 _("Response was:%s\n"), response);
	return -EINVAL;
}

static int gpst_get_config(struct openconnect_info *vpninfo)
{
	char *orig_path, *orig_ua;
	int result;
	struct oc_vpn_option *cookie;
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL;

	/* submit getconfig request */
	buf_append(request_body, "client-type=1&protocol-version=p1&app-version=3.0.1-10&app-version=3.0.1-10&os-version=Windows");
	append_opt(request_body, "hmac-algo", "sha1,md5");
	append_opt(request_body, "enc-algo", "aes-128-cb,aes-256-cbc");
	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strcmp(cookie->option, "USER"))
			append_opt(request_body, "user", cookie->value);
		else if (!strcmp(cookie->option, "AUTH"))
			append_opt(request_body, "authcookie", cookie->value);
		else if (!strcmp(cookie->option, "PORTAL"))
			append_opt(request_body, "portal", cookie->value);
	}

	orig_path = vpninfo->urlpath;
	orig_ua = vpninfo->useragent;
	vpninfo->useragent = "PAN GlobalProtect";
	vpninfo->urlpath = "ssl-vpn/getconfig.esp";
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	vpninfo->urlpath = orig_path;
	vpninfo->useragent = orig_ua;

	buf_free(request_body);

	if (result < 0)
		return -EINVAL;

	/* parse getconfig result */
	result = gpst_parse_config_xml(vpninfo, xml_buf);

	return result;
}

static int parse_cookie(struct openconnect_info *vpninfo)
{
	char *p = vpninfo->cookie;

	/* We currenly expect the "cookie" to contain multiple cookies. At a minimum:
	 * USER=xxx; AUTH=xxx
	 * Process those into vpninfo->cookies unless we already had them
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

int gpst_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	struct oc_vpn_option *cookie;
	const char *username = NULL, *authcookie = NULL;
	char buf[256];

	/* XXX: We should do what cstp_connect() does to check that configuration
	   hasn't changed on a reconnect. */

	ret = parse_cookie(vpninfo);
	if (ret)
		return ret;

	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strcmp(cookie->option, "USER"))
			username = cookie->value;
		else if (!strcmp(cookie->option, "AUTH"))
			authcookie = cookie->value;
	}

	/* Get configuration */
	ret = gpst_get_config(vpninfo);
	if (ret)
		return ret;

	/* Connect to SSL VPN tunnel */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET %s?user=", vpninfo->urlpath);
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

 out:
	if (ret < 0)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
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
		int len = 65536;
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
		if (ethertype != 0x800) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Expected EtherType 0x800 for IPv4, but got 0x%04x"), ethertype);
			goto unknown_pkt;
		}
		if (len != 16 + payload_len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected packet length. SSL_read returned %d (includes 16 header bytes) but header payload_len is %d\n"),
			             len, payload_len);
			goto unknown_pkt;
		}
		if (one != 1 || zero != 0) {
			vpn_progress(vpninfo, PRG_ERR,
			             _("Expected 0100000000000000 as last 8 bytes of packet header\n"));
			goto unknown_pkt;
		}

		vpninfo->ssl_times.last_rx = time(NULL);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Got data packet of %d bytes\n"),
			     payload_len);
		//buf_hexdump(vpninfo, PRG_TRACE, vpninfo->cstp_pkt->gpst.hdr, len);

		vpninfo->cstp_pkt->len = payload_len;
		queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
		vpninfo->cstp_pkt = NULL;
		work_done = 1;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		vpn_progress(vpninfo, PRG_TRACE, _("Outgoing data packet of %d bytes\n"), vpninfo->current_ssl_pkt->len);
		//buf_hexdump(vpninfo, PRG_TRACE, vpninfo->current_ssl_pkt->gpst.hdr,
		//	    vpninfo->current_ssl_pkt->len + 16);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->gpst.hdr,
					 vpninfo->current_ssl_pkt->len + 16);
		if (ret < 0) {
			vpn_progress(vpninfo, PRG_ERR, _("Write error: %s\n"), strerror(-ret));
		do_reconnect:
			ret = ssl_reconnect(vpninfo);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
				vpninfo->quit_reason = "GPST reconnect failed";
				return ret;
			}
			return 1;
		} else if (!ret) {
			return work_done;
		}

		if (ret != vpninfo->current_ssl_pkt->len + 16) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 16, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
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

unknown_pkt:
	vpn_progress(vpninfo, PRG_ERR,
		     _("Unknown packet. Header dump follows:\n"));
	buf_hexdump(vpninfo, PRG_ERR, vpninfo->cstp_pkt->gpst.hdr, 16);
	vpninfo->quit_reason = "Unknown packet received";
	return 1;
}
