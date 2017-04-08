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

/* Strange initialisers here to work around GCC PR#10676 (which was
 * fixed in GCC 4.6 but it takes a while for some systems to catch
 * up. */
static const struct pkt dpd_pkt = {
	.next = NULL,
	{ .gpst.hdr = { 0x1a, 0x2b, 0x3c, 0x4d } }
};

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

/* Parse this JavaScript-y mess:

	"var respStatus = \"Challenge|Error\";\n"
	"var respMsg = \"<prompt>\";\n"
	"thisForm.inputStr.value = "<inputStr>";\n"
*/
static int parse_javascript(char *buf, char **prompt, char **inputStr)
{
	const char *start, *end = buf;
	int status;

	const char *pre_status = "var respStatus = \"",
	           *pre_prompt = "var respMsg = \"",
	           *pre_inputStr = "thisForm.inputStr.value = \"";

	/* Status */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_status, strlen(pre_status)))
		goto err;

	start = end+strlen(pre_status);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"')
		goto err;

	if (!strncmp(start, "Challenge", 8))    status = 0;
	else if (!strncmp(start, "Error", 5))   status = 1;
	else                                    goto err;

	/* Prompt */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_prompt, strlen(pre_prompt)))
		goto err;

	start = end+strlen(pre_prompt);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"')
		goto err;

	if (prompt)
		*prompt = strndup(start, end-start-2);

	/* inputStr */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_inputStr, strlen(pre_inputStr)))
		goto err2;

	start = end+strlen(pre_inputStr);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"')
		goto err2;

	if (inputStr)
		*inputStr = strndup(start, end-start-2);

	while (isspace(*end))
		end++;
	if (*end != '\0')
		goto err3;

	return status;

err3:
	if (inputStr) free((void *)*inputStr);
err2:
	if (prompt) free((void *)*prompt);
err:
	return -EINVAL;
}

int gpst_xml_or_error(struct openconnect_info *vpninfo, int result, char *response,
					  int (*xml_cb)(struct openconnect_info *, xmlNode *xml_node),
					  char **prompt, char **inputStr)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	const char *err = NULL;

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
		/* is it Javascript? */
		char *p, *i;
		result = parse_javascript(response, &p, &i);
		switch (result) {
		case 1:
			vpn_progress(vpninfo, PRG_ERR, _("%s\n"), p);
			break;
		case 0:
			vpn_progress(vpninfo, PRG_INFO, _("Challenge: %s\n"), p);
			if (prompt && inputStr) {
				*prompt=p;
				*inputStr=i;
				return -EAGAIN;
			}
			break;
		default:
			goto bad_xml;
		}
		free((char *)p);
		free((char *)i);
		goto out;
	}

	xml_node = xmlDocGetRootElement(xml_doc);

	/* is it <response status="error"><error>..</error></response> ? */
	if (xmlnode_is_named(xml_node, "response")
	    && !xmlnode_match_prop(xml_node, "status", "error")) {
		for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
			if (!xmlnode_get_text(xml_node, "error", &err))
				goto out;
		}
		goto bad_xml;
	}

	if (xml_cb)
		result = xml_cb(vpninfo, xml_node);

	if (result == -EINVAL) {
	bad_xml:
		vpn_progress(vpninfo, PRG_ERR,
					 _("Failed to parse server response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Response was:%s\n"), response);
	}

out:
	if (err) {
		if (!strcmp(err, "GlobalProtect gateway does not exist")
		    || !strcmp(err, "GlobalProtect portal does not exist")) {
			vpn_progress(vpninfo, PRG_DEBUG, "%s\n", err);
			result = -EEXIST;
		} else {
			vpn_progress(vpninfo, PRG_ERR, "%s\n", err);
			result = -EINVAL;
		}
		free((void *)err);
	}
	if (xml_doc)
		xmlFreeDoc(xml_doc);
	return result;
}

#define ESP_OVERHEAD (4 /* SPI */ + 4 /* sequence number */ + \
         20 /* biggest supported MAC (SHA1) */ + 16 /* biggest supported IV (AES-128) */ + \
	 1 /* pad length */ + 1 /* next header */ + \
         16 /* max padding */ )
#define UDP_HEADER_SIZE 8
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40

static int calculate_mtu(struct openconnect_info *vpninfo)
{
	int mtu = vpninfo->reqmtu, base_mtu = vpninfo->basemtu;

#if defined(__linux__) && defined(TCP_INFO)
	if (!mtu || !base_mtu) {
		struct tcp_info ti;
		socklen_t ti_size = sizeof(ti);

		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_INFO,
				&ti, &ti_size)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("TCP_INFO rcv mss %d, snd mss %d, adv mss %d, pmtu %d\n"),
				     ti.tcpi_rcv_mss, ti.tcpi_snd_mss, ti.tcpi_advmss, ti.tcpi_pmtu);

			if (!base_mtu) {
				base_mtu = ti.tcpi_pmtu;
			}

			if (!base_mtu) {
				if (ti.tcpi_rcv_mss < ti.tcpi_snd_mss)
					base_mtu = ti.tcpi_rcv_mss - 13;
				else
					base_mtu = ti.tcpi_snd_mss - 13;
			}
		}
	}
#endif
#ifdef TCP_MAXSEG
	if (!base_mtu) {
		int mss;
		socklen_t mss_size = sizeof(mss);
		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_MAXSEG,
				&mss, &mss_size)) {
			vpn_progress(vpninfo, PRG_DEBUG, _("TCP_MAXSEG %d\n"), mss);
			base_mtu = mss - 13;
		}
	}
#endif
	if (!base_mtu) {
		/* Default */
		base_mtu = 1406;
	}

	if (base_mtu < 1280)
		base_mtu = 1280;

	if (!mtu) {
		/* remove IP/UDP and ESP overhead from base MTU to calculate tunnel MTU */
		mtu = base_mtu - ESP_OVERHEAD - UDP_HEADER_SIZE;
		if (vpninfo->peer_addr->sa_family == AF_INET6)
			mtu -= IPV6_HEADER_SIZE;
		else
			mtu -= IPV4_HEADER_SIZE;
	}
	return mtu;
}

static int set_esp_algo(struct openconnect_info *vpninfo, const char *s, int hmac)
{
	if (hmac) {
		if (!strcmp(s, "sha1"))		{ vpninfo->esp_hmac = HMAC_SHA1; return 20; }
		if (!strcmp(s, "md5"))		{ vpninfo->esp_hmac = HMAC_MD5; return 16; }
	} else {
		if (!strcmp(s, "aes128") || !strcmp(s, "aes-128-cbc"))
		                                { vpninfo->esp_enc = ENC_AES_128_CBC; return 16; }
		if (!strcmp(s, "aes-256-cbc"))	{ vpninfo->esp_enc = ENC_AES_256_CBC; return 32; }
	}
	vpn_progress(vpninfo, PRG_ERR, _("Unknown ESP %s algorithm: %s"), hmac ? "MAC" : "encryption", s);
	return -ENOENT;
}

static int get_key_bits(xmlNode *xml_node, unsigned char *dest, int keybytes)
{
	int bits = -1;
	xmlNode *child;
	const char *s, *p;

	for (child = xml_node->children; child; child=child->next) {
		if (xmlnode_get_text(child, "bits", &s) == 0) {
			bits = atoi(s);
			free((void *)s);
		} else if (xmlnode_get_text(child, "val", &s) == 0) {
			for (p=s; *p && *(p+1) && p<s+(keybytes<<1); p+=2)
				*dest++ = unhex(p);
			free((void *)s);
		}
	}
	return (bits == (keybytes<<3)) ? 0 : -EINVAL;
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

	/* Clear old options which will be overwritten */
	vpninfo->ip_info.addr = vpninfo->ip_info.netmask = NULL;
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->ip_info.domain = NULL;

	for (ii = 0; ii < 3; ii++)
		vpninfo->ip_info.dns[ii] = vpninfo->ip_info.nbns[ii] = NULL;
	free_split_routes(vpninfo);

	/* Parse config */
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
		} else if (xmlnode_is_named(xml_node, "dns-suffix")) {
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
			int c = (vpninfo->current_esp_in ^= 1);
			int enclen=0, maclen=0;
			for (member = xml_node->children; member; member=member->next) {
				s = NULL;
				if (!xmlnode_get_text(member, "udp-port", &s))		udp_sockaddr(vpninfo, atoi(s));
				else if (!xmlnode_get_text(member, "enc-algo", &s)) 	enclen = set_esp_algo(vpninfo, s, 0);
				else if (!xmlnode_get_text(member, "hmac-algo", &s))	maclen = set_esp_algo(vpninfo, s, 1);
				else if (!xmlnode_get_text(member, "c2s-spi", &s))	vpninfo->esp_out.spi = htonl(strtoul(s, NULL, 16));
				else if (!xmlnode_get_text(member, "s2c-spi", &s))	vpninfo->esp_in[c].spi = htonl(strtoul(s, NULL, 16));
				/* FIXME: this won't work if ekey or akey tags appears before algo tags */
				else if (xmlnode_is_named(member, "ekey-c2s"))		get_key_bits(member, vpninfo->esp_out.secrets, enclen);
				else if (xmlnode_is_named(member, "ekey-s2c"))		get_key_bits(member, vpninfo->esp_in[c].secrets, enclen);
				else if (xmlnode_is_named(member, "akey-c2s"))		get_key_bits(member, vpninfo->esp_out.secrets+enclen, maclen);
				else if (xmlnode_is_named(member, "akey-s2c"))		get_key_bits(member, vpninfo->esp_in[c].secrets+enclen, maclen);
				free((void *)s);
			}
			if (vpninfo->dtls_state != DTLS_DISABLED) {
				if (setup_esp_keys(vpninfo, 0))
					vpn_progress(vpninfo, PRG_ERR, "Failed to setup ESP keys.\n");
				else
					vpninfo->dtls_times.last_rekey = time(NULL);
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
	vpninfo->ssl_times.keepalive = vpninfo->esp_ssl_fallback = vpninfo->ssl_times.dpd;

	return 0;
}

static int gpst_get_config(struct openconnect_info *vpninfo)
{
	char *orig_path, *orig_ua;
	int result;
	struct oc_text_buf *request_body = buf_alloc();
	const char *old_addr = vpninfo->ip_info.addr, *old_netmask = vpninfo->ip_info.netmask;
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL;

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
	vpninfo->urlpath = strdup("ssl-vpn/getconfig.esp");
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;
	vpninfo->useragent = orig_ua;

	if (result < 0)
		goto out;

	/* parse getconfig result */
	result = gpst_xml_or_error(vpninfo, result, xml_buf, gpst_parse_config_xml, NULL, NULL);
	if (result)
		return result;

	if (!vpninfo->ip_info.mtu) {
		/* FIXME: GP gateway config always seems to be <mtu>0</mtu> */
		vpninfo->ip_info.mtu = calculate_mtu(vpninfo);
		vpn_progress(vpninfo, PRG_ERR,
			     _("No MTU received. Calculated %d\n"), vpninfo->ip_info.mtu);
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
	return result;
}

static int gpst_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	char buf[256];

	/* Connect to SSL VPN tunnel */
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Connecting to HTTPS tunnel endpoint ...\n"));

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
		vpninfo->dtls_state = DTLS_NOSECRET;
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

	/* We do NOT actually start the HTTPS tunnel yet if we want to
	 * use ESP, because the ESP tunnel won't work if the HTTPS tunnel
	 * is connected! >:-(
	 */
	if (vpninfo->dtls_state == DTLS_DISABLED || vpninfo->dtls_state == DTLS_NOSECRET)
		ret = gpst_connect(vpninfo);
	else {
		/* We want to prevent the mainloop timers from frantically
		 * calling the GPST mainloop.
		 */
		vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);

		/* Using (abusing?) last_rekey as the time when the SSL tunnel
		 * was brought up.
		 */
		vpninfo->ssl_times.last_rekey = 0;
	}

	return ret;
}

int gpst_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int ret;
	int work_done = 0;
	uint16_t ethertype;
	uint32_t one, zero, magic;

	/* Starting the HTTPS tunnel kills ESP, so we avoid starting
	 * it if the ESP tunnel is connected or connecting.
	 */
	switch (vpninfo->dtls_state) {
	case DTLS_CONNECTING:
		openconnect_close_https(vpninfo, 0); /* don't keep stale HTTPS socket */
		vpn_progress(vpninfo, PRG_INFO,
			     _("ESP tunnel connected; exiting HTTPS mainloop.\n"));
		vpninfo->dtls_state = DTLS_CONNECTED;
	case DTLS_CONNECTED:
		return 0;
	case DTLS_SECRET:
	case DTLS_SLEEPING:
		if (time(NULL) < vpninfo->dtls_times.last_rekey + 5) {
			/* Allow 5 seconds after configuration for ESP to start */
			if (*timeout > 5000)
				*timeout = 5000;
			return 0;
		} else if (!vpninfo->ssl_times.last_rekey) {
			/* ... before we switch to HTTPS instead */
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to connect ESP tunnel; using HTTPS instead.\n"));
			if (gpst_connect(vpninfo)) {
				vpninfo->quit_reason = "GPST connect failed";
				return 1;
			}
		}
		break;
	case DTLS_NOSECRET:
		/* HTTPS tunnel already started, or getconfig.esp did not provide any ESP keys */
	case DTLS_DISABLED:
		/* ESP is disabled */
		;
	}

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
		esp_setup(vpninfo, vpninfo->dtls_attempt_period);
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
