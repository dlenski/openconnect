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

int gpst_xml_or_error(struct openconnect_info *vpninfo, int result, char *response,
		      int (*xml_cb)(struct openconnect_info *, xmlNode *xml_node))
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	int errlen;
	const char *err;

	/* custom error codes returned by /ssl-vpn/login.esp and maybe others */
	if (result == -512)
		vpn_progress(vpninfo, PRG_ERR, _("Invalid username or password.\n"));
	else if (result == -513)
		vpn_progress(vpninfo, PRG_ERR, _("Invalid client certificate.\n"));

	if (result < 0)
		return result;

	if (!response) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	/* is it XML? */
	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL,
				XML_PARSE_NOERROR);
	if (!xml_doc) {
		/* nope, but maybe it looks like this JavaScript-y blob:
		   var respStatus = "Error";
		   var respMsg = "<want this part>";
		   thisForm.inputStr.value = ""; */
		if ((err = strstr(response, "respMsg = \"")) != NULL) {
			err += 11;
			errlen = strchrnul(err, ';') - err - 1;
			vpn_progress(vpninfo, PRG_ERR,
				     _("%.*s\n"), errlen, err);
			goto out;
		}
		goto bad_xml;
	}

        xml_node = xmlDocGetRootElement(xml_doc);

	/* is it <response status="error"><error>..</error></response> ? */
	if (xmlnode_is_named(xml_node, "response")
	    && !xmlnode_match_prop(xml_node, "status", "error")) {
		for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
			if (!xmlnode_get_text(xml_node, "error", &err)) {
				vpn_progress(vpninfo, PRG_ERR, _("%s\n"), err);
				free((void *)err);
				goto out;
			}
		}
		goto bad_xml;
	}

	if (xml_cb)
		result = xml_cb(vpninfo, xml_node);

	if (result == -EINVAL)
		goto bad_xml;

	xmlFreeDoc(xml_doc);
	return result;

bad_xml:
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to parse server response\n"));
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Response was:%s\n"), response);
out:
	if (xml_doc)
		xmlFreeDoc(xml_doc);
	return -EINVAL;
}

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int gpst_parse_config_xml(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	xmlNode *member;
	const char *s;
	int ii;

	if (!xml_node || !xmlnode_is_named(xml_node, "response"))
		return -EINVAL;

	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		xmlnode_get_text(xml_node, "ip-address", &vpninfo->ip_info.addr);
		xmlnode_get_text(xml_node, "netmask", &vpninfo->ip_info.netmask);

		if (!xmlnode_get_text(xml_node, "mtu", &s)) {
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

	return 0;
}

static int gpst_get_config(struct openconnect_info *vpninfo)
{
	char *orig_path, *orig_ua;
	int result, ii;
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
	buf_append(request_body, "&%s", vpninfo->cookie);

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
	result = gpst_xml_or_error(vpninfo, result, xml_buf, gpst_parse_config_xml);
	if (result)
		return result;

	if (!vpninfo->ip_info.mtu) {
		/* FIXME: GP gateway config always seems to be <mtu>0</mtu> */
		vpninfo->ip_info.mtu = 1500;
		vpn_progress(vpninfo, PRG_ERR,
			     _("No MTU received. Guessed %d\n"), vpninfo->ip_info.mtu);
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

static int gpst_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	char buf[256];

	/* Connect to SSL VPN tunnel */
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Connecting to GPST tunnel over HTTPS...\n"));

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET /ssl-tunnel-connect.sslvpn?%s HTTP/1.1\r\n\r\n", vpninfo->cookie);

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
		vpninfo->ssl_times.last_rekey = vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
	}

	return ret;
}

int gpst_setup(struct openconnect_info *vpninfo)
{
	int ret;

	/* Get configuration */
	ret = gpst_get_config(vpninfo);
	if (ret)
		return ret;

	ret = gpst_connect(vpninfo);
	vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);

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
			dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->gpst.hdr, 16);
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
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', vpninfo->cstp_pkt->gpst.hdr + 8, 8);
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
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}
			continue;
		}

	unknown_pkt:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown packet. Header dump follows:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->gpst.hdr, 16);
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
