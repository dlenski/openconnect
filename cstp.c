/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
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
#ifdef HAVE_LZ4
#include <lz4.h>
#ifndef HAVE_LZ4_COMPRESS_DEFAULT
#define LZ4_compress_default LZ4_compress_limitedOutput
#endif
#endif

#if defined(__linux__)
/* For TCP_INFO */
# include <linux/tcp.h>
#endif

#include "openconnect-internal.h"

/*
 * Data packets are encapsulated in the SSL stream as follows:
 *
 * 0000: Magic "STF\x1"
 * 0004: Big-endian 16-bit length (not including 8-byte header)
 * 0006: Byte packet type (see openconnect-internal.h)
 * 0008: data payload
 */

static const char data_hdr[8] = {
	'S', 'T', 'F', 1,
	0, 0,		/* Length */
	AC_PKT_DATA,	/* Type */
	0		/* Unknown */
};

/* Strange initialisers here to work around GCC PR#10676 (which was
 * fixed in GCC 4.6 but it takes a while for some systems to catch
 * up. */
static const struct pkt keepalive_pkt = {
	.next = NULL,
	{ .cstp.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_KEEPALIVE, 0 } }
};

static const struct pkt dpd_pkt = {
	.next = NULL,
	{ .cstp.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_DPD_OUT, 0 } }
};

static const struct pkt dpd_resp_pkt = {
	.next = NULL,
	{ .cstp.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_DPD_RESP, 0 } }
};

#define UDP_HEADER_SIZE 8
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40

/* Calculate MTU to request. Old servers simply use the X-CSTP-MTU: header,
 * which represents the tunnel MTU, while new servers do calculations on the
 * X-CSTP-Base-MTU: header which represents the link MTU between client
 * and server.
 *
 * If possible, the legacy MTU value should be the TCP MSS less 5 bytes of
 * TLS and 8 bytes of CSTP overhead. We can get the MSS from either the
 * TCP_INFO or TCP_MAXSEG sockopts.
 *
 * The base MTU comes from the TCP_INFO sockopt under Linux, but I don't know
 * how to work it out on other systems. So leave it blank and do things the
 * legacy way there. Contributions welcome...
 *
 * If we don't even have TCP_MAXSEG, then default to sending a legacy MTU of
 * 1406 which is what we always used to do.
 */
static void calculate_mtu(struct openconnect_info *vpninfo, int *base_mtu, int *mtu)
{
	*mtu = vpninfo->reqmtu;
	*base_mtu = vpninfo->basemtu;

#if defined(__linux__) && defined(TCP_INFO)
	if (!*mtu || !*base_mtu) {
		struct tcp_info ti;
		socklen_t ti_size = sizeof(ti);

		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_INFO,
				&ti, &ti_size)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("TCP_INFO rcv mss %d, snd mss %d, adv mss %d, pmtu %d\n"),
				     ti.tcpi_rcv_mss, ti.tcpi_snd_mss, ti.tcpi_advmss, ti.tcpi_pmtu);

			if (!*base_mtu) {
				*base_mtu = ti.tcpi_pmtu;
			}

			if (!*base_mtu) {
				if (ti.tcpi_rcv_mss < ti.tcpi_snd_mss)
					*base_mtu = ti.tcpi_rcv_mss - 13;
				else
					*base_mtu = ti.tcpi_snd_mss - 13;
			}
		}
	}
#endif
#ifdef TCP_MAXSEG
	if (!*base_mtu) {
		int mss;
		socklen_t mss_size = sizeof(mss);
		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_MAXSEG,
				&mss, &mss_size)) {
			vpn_progress(vpninfo, PRG_DEBUG, _("TCP_MAXSEG %d\n"), mss);
			*base_mtu = mss - 13;
		}
	}
#endif
	if (!*base_mtu) {
		/* Default */
		*base_mtu = 1406;
	}

	if (*base_mtu < 1280)
		*base_mtu = 1280;

	if (!*mtu) {
		/* remove IP/UDP and DTLS overhead from base MTU to calculate tunnel MTU */
		*mtu = *base_mtu - DTLS_OVERHEAD - UDP_HEADER_SIZE;
		if (vpninfo->peer_addr->sa_family == AF_INET6)
			*mtu -= IPV6_HEADER_SIZE;
		else
			*mtu -= IPV4_HEADER_SIZE;
	}
}

static void append_compr_types(struct oc_text_buf *buf, const char *proto, int avail)
{
	if (avail) {
		char sep = ' ';
		buf_append(buf, "X-%s-Accept-Encoding:", proto);
		if (avail & COMPR_LZ4) {
			buf_append(buf, "%coc-lz4", sep);
			sep = ',';
		}
		if (avail & COMPR_LZS) {
			buf_append(buf, "%clzs", sep);
			sep = ',';
		}
		if (avail & COMPR_DEFLATE) {
			buf_append(buf, "%cdeflate", sep);
			sep = ',';
		}
		buf_append(buf, "\r\n");
	}
}

static void append_mobile_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	if (vpninfo->mobile_platform_version) {
		buf_append(buf, "X-AnyConnect-Identifier-ClientVersion: %s\r\n",
			   openconnect_version_str);
		buf_append(buf, "X-AnyConnect-Identifier-Platform: %s\r\n",
			   vpninfo->platname);
		buf_append(buf, "X-AnyConnect-Identifier-PlatformVersion: %s\r\n",
			   vpninfo->mobile_platform_version);
		buf_append(buf, "X-AnyConnect-Identifier-DeviceType: %s\r\n",
			   vpninfo->mobile_device_type);
		buf_append(buf, "X-AnyConnect-Identifier-Device-UniqueID: %s\r\n",
			   vpninfo->mobile_device_uniqueid);
	}
}

static int parse_hex_val(const char *str, unsigned char *storage, unsigned int max_storage_len, int *changed)
{
	int len = strlen(str);
	unsigned i;

	if (len % 2 == 1 || len > 2*max_storage_len) {
		return -EINVAL;
	}

	for (i = 0; i < len; i += 2) {
		unsigned char c = unhex(str + i);
		if (storage[i/2] != c) {
			storage[i/2] = c;
			*changed = 1;
		}
	}

	return len/2;
}

static int start_cstp_connection(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *reqbuf;
	char buf[65536];
	int i;
	int dtls_secret_set = 0;
	int retried = 0, sessid_found = 0;
	struct oc_vpn_option **next_dtls_option = &vpninfo->dtls_options;
	struct oc_vpn_option **next_cstp_option = &vpninfo->cstp_options;
	struct oc_vpn_option *old_cstp_opts = vpninfo->cstp_options;
	struct oc_vpn_option *old_dtls_opts = vpninfo->dtls_options;
	const char *old_addr = vpninfo->ip_info.addr;
	const char *old_netmask = vpninfo->ip_info.netmask;
	const char *old_addr6 = vpninfo->ip_info.addr6;
	const char *old_netmask6 = vpninfo->ip_info.netmask6;
	int base_mtu = 0, mtu = 0;

	/* Clear old options which will be overwritten */
	vpninfo->ip_info.addr = vpninfo->ip_info.netmask = NULL;
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->cstp_options = vpninfo->dtls_options = NULL;
	vpninfo->ip_info.domain = vpninfo->ip_info.proxy_pac = NULL;
	vpninfo->banner = NULL;

	for (i = 0; i < 3; i++)
		vpninfo->ip_info.dns[i] = vpninfo->ip_info.nbns[i] = NULL;
	free_split_routes(vpninfo);

 retry:
	calculate_mtu(vpninfo, &base_mtu, &mtu);
	vpninfo->cstp_basemtu = base_mtu;

	reqbuf = buf_alloc();
	buf_append(reqbuf, "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n");
	if (vpninfo->port != 443)
		buf_append(reqbuf, "Host: %s:%d\r\n", vpninfo->hostname, vpninfo->port);
	else
		buf_append(reqbuf, "Host: %s\r\n", vpninfo->hostname);
	buf_append(reqbuf, "User-Agent: %s\r\n", vpninfo->useragent);
	buf_append(reqbuf, "Cookie: webvpn=%s\r\n", vpninfo->cookie);
	buf_append(reqbuf, "X-CSTP-Version: 1\r\n");
	buf_append(reqbuf, "X-CSTP-Hostname: %s\r\n", vpninfo->localname);

	append_mobile_headers(vpninfo, reqbuf);
	append_compr_types(reqbuf, "CSTP", vpninfo->req_compr);

	buf_append(reqbuf, "X-CSTP-Base-MTU: %d\r\n", base_mtu);
	if (mtu)
		buf_append(reqbuf, "X-CSTP-MTU: %d\r\n", mtu);
	buf_append(reqbuf, "X-CSTP-Address-Type: %s\r\n",
			       vpninfo->disable_ipv6 ? "IPv4" : "IPv6,IPv4");
	if (!vpninfo->disable_ipv6)
		buf_append(reqbuf, "X-CSTP-Full-IPv6-Capability: true\r\n");
#ifdef HAVE_DTLS
	if (vpninfo->dtls_state != DTLS_DISABLED) {
		/* The X-DTLS-Master-Secret is only used for the legacy protocol negotation
		 * which required the client to send explicitly the secret. In the PSK-NEGOTIATE
		 * method, the master secret is implicitly agreed on */
		buf_append(reqbuf, "X-DTLS-Master-Secret: ");
		for (i = 0; i < sizeof(vpninfo->dtls_secret); i++) {
			buf_append(reqbuf, "%02X", vpninfo->dtls_secret[i]);
			dtls_secret_set |= vpninfo->dtls_secret[i];
		}
		if (!dtls_secret_set) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("CRITICAL ERROR: DTLS master secret is uninitialised. Please report this.\n"));
			buf_free(reqbuf);
			return -EINVAL;
		}
		buf_append(reqbuf, "\r\nX-DTLS-CipherSuite: ");
		if (vpninfo->dtls_ciphers)
			buf_append(reqbuf, "%s", vpninfo->dtls_ciphers);
		else
			append_dtls_ciphers(vpninfo, reqbuf);
		buf_append(reqbuf, "\r\n");

		append_compr_types(reqbuf, "DTLS", vpninfo->req_compr & ~COMPR_DEFLATE);
	}
#endif
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating HTTPS CONNECT request\n"));
		return buf_free(reqbuf);
	}

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	buf_free(reqbuf);

	/* FIXME: Use process_http_response() instead of reimplementing it. It has
	   a header callback function, and can cope with CONNECT requests. */
	if ((i = vpninfo->ssl_gets(vpninfo, buf, 65536)) < 0) {
		if (i == -EINTR)
			return i;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error fetching HTTPS response\n"));
		if (!retried) {
			retried = 1;
			openconnect_close_https(vpninfo, 0);

			if (openconnect_open_https(vpninfo)) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to open HTTPS connection to %s\n"),
					     vpninfo->hostname);
				return -EIO;
			}
			goto retry;
		}
		return -EINVAL;
	}

	if (strncmp(buf, "HTTP/1.1 200 ", 13)) {
		if (!strncmp(buf, "HTTP/1.1 503 ", 13)) {
			/* "Service Unavailable. Why? */
			const char *reason = "<unknown>";
			while ((i = vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)))) {
				if (!strncmp(buf, "X-Reason: ", 10)) {
					reason = buf + 10;
					break;
				}
			}
			vpn_progress(vpninfo, PRG_ERR,
				     _("VPN service unavailable; reason: %s\n"),
				     reason);
			return -EINVAL;
		}
		vpn_progress(vpninfo, PRG_ERR,
			     _("Got inappropriate HTTP CONNECT response: %s\n"),
			     buf);
		if (!strncmp(buf, "HTTP/1.1 401 ", 13))
			return -EPERM;
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_INFO, _("Got CONNECT response: %s\n"), buf);

	/* We may have advertised it, but we only do it if the server agrees */
	vpninfo->cstp_compr = vpninfo->dtls_compr = 0;
	mtu = 0;

	while ((i = vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)))) {
		struct oc_vpn_option *new_option;
		char *colon;

		if (i < 0)
			return i;

		colon = strchr(buf, ':');
		if (!colon)
			continue;

		*colon = 0;
		colon++;
		if (*colon == ' ')
			colon++;

		if (strncmp(buf, "X-DTLS-", 7) &&
		    strncmp(buf, "X-CSTP-", 7))
			continue;

		new_option = malloc(sizeof(*new_option));
		if (!new_option) {
			vpn_progress(vpninfo, PRG_ERR, _("No memory for options\n"));
			return -ENOMEM;
		}
		new_option->option = strdup(buf);
		new_option->value = strdup(colon);
		new_option->next = NULL;

		if (!new_option->option || !new_option->value) {
			vpn_progress(vpninfo, PRG_ERR, _("No memory for options\n"));
			free(new_option->option);
			free(new_option->value);
			free(new_option);
			return -ENOMEM;
		}

		/* This contains the whole document, including the webvpn cookie. */
		if (!strcasecmp(buf, "X-CSTP-Post-Auth-XML"))
			vpn_progress(vpninfo, PRG_DEBUG, "%s: %s\n", buf, _("<elided>"));
		else
			vpn_progress(vpninfo, PRG_DEBUG, "%s: %s\n", buf, colon);

		if (!strncmp(buf, "X-DTLS-", 7)) {
			*next_dtls_option = new_option;
			next_dtls_option = &new_option->next;

			if (!strcmp(buf + 7, "MTU")) {
				int dtlsmtu = atol(colon);
				if (dtlsmtu > mtu)
					mtu = dtlsmtu;
			} else if (!strcmp(buf + 7, "Session-ID")) {
				int dtls_sessid_changed = 0;
				int vsize;

				vsize = parse_hex_val(colon, vpninfo->dtls_session_id, sizeof(vpninfo->dtls_session_id), &dtls_sessid_changed);
				if (vsize != 32) {
					vpn_progress(vpninfo, PRG_ERR,
					     _("X-DTLS-Session-ID not 64 characters; is: \"%s\"\n"),
					     	colon);
					vpninfo->dtls_attempt_period = 0;
					return -EINVAL;
				}

				sessid_found = 1;

				if (dtls_sessid_changed && vpninfo->dtls_state > DTLS_SLEEPING)
					vpninfo->dtls_need_reconnect = 1;
			} else if (!strcmp(buf + 7, "App-ID")) {
				int dtls_appid_changed = 0;
				int vsize;

				vsize = parse_hex_val(colon, vpninfo->dtls_app_id, sizeof(vpninfo->dtls_app_id), &dtls_appid_changed);
				if (vsize <= 0) {
					vpn_progress(vpninfo, PRG_ERR,
					     _("X-DTLS-Session-ID is invalid; is: \"%s\"\n"),
					     	colon);
					vpninfo->dtls_attempt_period = 0;
					return -EINVAL;
				}

				vpninfo->dtls_app_id_size = vsize;
				sessid_found = 1;

				if (dtls_appid_changed && vpninfo->dtls_state > DTLS_SLEEPING)
					vpninfo->dtls_need_reconnect = 1;
			} else if (!strcmp(buf + 7, "Content-Encoding")) {
				if (!strcmp(colon, "lzs"))
					vpninfo->dtls_compr = COMPR_LZS;
				else if (!strcmp(colon, "oc-lz4"))
					vpninfo->dtls_compr = COMPR_LZ4;
				else {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Unknown DTLS-Content-Encoding %s\n"),
						     colon);
					return -EINVAL;
				}
			}
			continue;
		}
		/* CSTP options... */
		*next_cstp_option = new_option;
		next_cstp_option = &new_option->next;


		if (!strcmp(buf + 7, "Keepalive")) {
			vpninfo->ssl_times.keepalive = atol(colon);
		} else if (!strcmp(buf + 7, "DPD")) {
			int j = atol(colon);
			if (j && (!vpninfo->ssl_times.dpd || j < vpninfo->ssl_times.dpd))
				vpninfo->ssl_times.dpd = j;
		} else if (!strcmp(buf + 7, "Rekey-Time")) {
			vpninfo->ssl_times.rekey = atol(colon);
		} else if (!strcmp(buf + 7, "Rekey-Method")) {
			if (!strcmp(colon, "new-tunnel"))
				vpninfo->ssl_times.rekey_method = REKEY_TUNNEL;
			else if (!strcmp(colon, "ssl"))
				vpninfo->ssl_times.rekey_method = REKEY_SSL;
			else
				vpninfo->ssl_times.rekey_method = REKEY_NONE;
		} else if (!strcmp(buf + 7, "Content-Encoding")) {
			if (!strcmp(colon, "deflate"))
				vpninfo->cstp_compr = COMPR_DEFLATE;
			else if (!strcmp(colon, "lzs"))
				vpninfo->cstp_compr = COMPR_LZS;
			else if (!strcmp(colon, "oc-lz4"))
				vpninfo->cstp_compr = COMPR_LZ4;
			else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unknown CSTP-Content-Encoding %s\n"),
					     colon);
				return -EINVAL;
			}
		} else if (!strcmp(buf + 7, "Base-MTU")) {
			vpninfo->cstp_basemtu = atol(colon);
		} else if (!strcmp(buf + 7, "MTU")) {
			int cstpmtu = atol(colon);
			if (cstpmtu > mtu)
				mtu = cstpmtu;
		} else if (!strcmp(buf + 7, "DynDNS")) {
			if (!strcmp(colon, "true"))
				vpninfo->is_dyndns = 1;
		} else if (!strcmp(buf + 7, "Address-IP6")) {
			vpninfo->ip_info.netmask6 = new_option->value;
		} else if (!strcmp(buf + 7, "Address")) {
			if (strchr(new_option->value, ':')) {
				if (!vpninfo->disable_ipv6)
					vpninfo->ip_info.addr6 = new_option->value;
			} else
				vpninfo->ip_info.addr = new_option->value;
		} else if (!strcmp(buf + 7, "Netmask")) {
			if (strchr(new_option->value, ':')) {
				if (!vpninfo->disable_ipv6)
					vpninfo->ip_info.netmask6 = new_option->value;
			} else
				vpninfo->ip_info.netmask = new_option->value;
		} else if (!strcmp(buf + 7, "DNS")) {
			int j;
			for (j = 0; j < 3; j++) {
				if (!vpninfo->ip_info.dns[j]) {
					vpninfo->ip_info.dns[j] = new_option->value;
					break;
				}
			}
		} else if (!strcmp(buf + 7, "NBNS")) {
			int j;
			for (j = 0; j < 3; j++) {
				if (!vpninfo->ip_info.nbns[j]) {
					vpninfo->ip_info.nbns[j] = new_option->value;
					break;
				}
			}
		} else if (!strcmp(buf + 7, "Default-Domain")) {
			vpninfo->ip_info.domain = new_option->value;
		} else if (!strcmp(buf + 7, "MSIE-Proxy-PAC-URL")) {
			vpninfo->ip_info.proxy_pac = new_option->value;
		} else if (!strcmp(buf + 7, "Banner")) {
			vpninfo->banner = new_option->value;
		} else if (!strcmp(buf + 7, "Split-DNS")) {
			struct oc_split_include *dns = malloc(sizeof(*dns));
			if (!dns)
				continue;
			dns->route = new_option->value;
			dns->next = vpninfo->ip_info.split_dns;
			vpninfo->ip_info.split_dns = dns;
		} else if (!strcmp(buf + 7, "Split-Include") || !strcmp(buf + 7, "Split-Include-IP6")) {
			struct oc_split_include *inc = malloc(sizeof(*inc));
			if (!inc)
				continue;
			inc->route = new_option->value;
			inc->next = vpninfo->ip_info.split_includes;
			vpninfo->ip_info.split_includes = inc;
		} else if (!strcmp(buf + 7, "Split-Exclude") || !strcmp(buf + 7, "Split-Exclude-IP6")) {
			struct oc_split_include *exc = malloc(sizeof(*exc));
			if (!exc)
				continue;
			exc->route = new_option->value;
			exc->next = vpninfo->ip_info.split_excludes;
			vpninfo->ip_info.split_excludes = exc;
		}
	}

	if (!mtu) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No MTU received. Aborting\n"));
		return -EINVAL;
	}
	vpninfo->ip_info.mtu = mtu;

	if (!vpninfo->ip_info.addr && !vpninfo->ip_info.addr6 &&
	    !vpninfo->ip_info.netmask6) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No IP address received. Aborting\n"));
		return -EINVAL;
	}
	if (mtu < 1280 &&
	    (vpninfo->ip_info.addr6 || vpninfo->ip_info.netmask6)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("IPv6 configuration received but MTU %d is too small.\n"),
			     mtu);
	}
	if (old_addr) {
		if (strcmp(old_addr, vpninfo->ip_info.addr)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP address (%s != %s)\n"),
				     vpninfo->ip_info.addr, old_addr);
			return -EINVAL;
		}
	}
	if (old_netmask) {
		if (strcmp(old_netmask, vpninfo->ip_info.netmask)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP netmask (%s != %s)\n"),
				     vpninfo->ip_info.netmask, old_netmask);
			return -EINVAL;
		}
	}
	if (old_addr6) {
		if (strcmp(old_addr6, vpninfo->ip_info.addr6)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different IPv6 address (%s != %s)\n"),
				     vpninfo->ip_info.addr6, old_addr6);
			return -EINVAL;
		}
	}
	if (old_netmask6) {
		if (strcmp(old_netmask6, vpninfo->ip_info.netmask6)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different IPv6 netmask (%s != %s)\n"),
				     vpninfo->ip_info.netmask6, old_netmask6);
			return -EINVAL;
		}
	}

	free_optlist(old_dtls_opts);
	free_optlist(old_cstp_opts);
	vpn_progress(vpninfo, PRG_INFO, _("CSTP connected. DPD %d, Keepalive %d\n"),
		     vpninfo->ssl_times.dpd, vpninfo->ssl_times.keepalive);
	vpn_progress(vpninfo, PRG_DEBUG, _("CSTP Ciphersuite: %s\n"),
		     openconnect_get_cstp_cipher(vpninfo));

	monitor_fd_new(vpninfo, ssl);

	monitor_read_fd(vpninfo, ssl);
	monitor_except_fd(vpninfo, ssl);

	if (!sessid_found)
		vpninfo->dtls_attempt_period = 0;

	if (vpninfo->ssl_times.rekey <= 0)
		vpninfo->ssl_times.rekey_method = REKEY_NONE;

	vpninfo->ssl_times.last_rekey = vpninfo->ssl_times.last_rx =
		vpninfo->ssl_times.last_tx = time(NULL);
	return 0;
}


int cstp_connect(struct openconnect_info *vpninfo)
{
	int ret;
	int deflate_bufsize = 0;
	int compr_type;

	/* This needs to be done before openconnect_setup_dtls() because it's
	   sent with the CSTP CONNECT handshake. Even if we don't end up doing
	   DTLS. */
	if (vpninfo->dtls_state == DTLS_NOSECRET) {
		if (openconnect_random(vpninfo->dtls_secret, sizeof(vpninfo->dtls_secret)))
			return -EINVAL;
		/* The application will later call openconnect_setup_dtls() */
		vpninfo->dtls_state = DTLS_SECRET;
	}

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	ret = start_cstp_connection(vpninfo);
	if (ret)
		goto out;

	/* Allow for the theoretical possibility of having *different*
	 * compression type for CSTP and DTLS. Although all we've seen
	 * in practice is that one is enabled and the other isn't. */
	compr_type = vpninfo->cstp_compr | vpninfo->dtls_compr;

	/* This will definitely be smaller than zlib's */
	if (compr_type & (COMPR_LZS|COMPR_LZ4))
		deflate_bufsize = vpninfo->ip_info.mtu;

	/* If deflate compression is enabled (which is CSTP-only), it needs its
	 * context to be allocated. */
	if (compr_type & COMPR_DEFLATE) {
		vpninfo->deflate_adler32 = 1;
		vpninfo->inflate_adler32 = 1;

		if (inflateInit2(&vpninfo->inflate_strm, -12) ||
		    deflateInit2(&vpninfo->deflate_strm, Z_DEFAULT_COMPRESSION,
				 Z_DEFLATED, -12, 9, Z_DEFAULT_STRATEGY)) {
			vpn_progress(vpninfo, PRG_ERR, _("Compression setup failed\n"));
			ret = -ENOMEM;
			goto out;
		}

		/* Add four bytes for the adler32 */
		deflate_bufsize = deflateBound(&vpninfo->deflate_strm,
					       vpninfo->ip_info.mtu) + 4;
	}

	/* If *any* compression is enabled, we'll need a deflate_pkt to compress into */
	if (deflate_bufsize > vpninfo->deflate_pkt_size) {
		free(vpninfo->deflate_pkt);
		vpninfo->deflate_pkt = malloc(sizeof(struct pkt) + deflate_bufsize);
		if (!vpninfo->deflate_pkt) {
			vpninfo->deflate_pkt_size = 0;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Allocation of deflate buffer failed\n"));
			ret = -ENOMEM;
			goto out;
		}

		vpninfo->deflate_pkt_size = deflate_bufsize;
		memset(vpninfo->deflate_pkt, 0, sizeof(struct pkt));
		memcpy(vpninfo->deflate_pkt->cstp.hdr, data_hdr, 8);
		vpninfo->deflate_pkt->cstp.hdr[6] = AC_PKT_COMPRESSED;
	}

 out:
	if (ret < 0)
		openconnect_close_https(vpninfo, 0);

	return ret;
}

static int cstp_reconnect(struct openconnect_info *vpninfo)
{
	if (vpninfo->cstp_compr == COMPR_DEFLATE) {
		/* Requeue the original packet that was deflated */
		if (vpninfo->current_ssl_pkt == vpninfo->deflate_pkt) {
			vpninfo->current_ssl_pkt = NULL;
			queue_packet(&vpninfo->outgoing_queue, vpninfo->pending_deflated_pkt);
			vpninfo->pending_deflated_pkt = NULL;
		}
		inflateEnd(&vpninfo->inflate_strm);
		deflateEnd(&vpninfo->deflate_strm);
	}

	return ssl_reconnect(vpninfo);
}

int decompress_and_queue_packet(struct openconnect_info *vpninfo, int compr_type,
				unsigned char *buf, int len)
{
	/* Some servers send us packets that are larger than
	   negotiated MTU after decompression. We reserve some extra
	   space to handle that */
	int receive_mtu = MAX(16384, vpninfo->ip_info.mtu);
	struct pkt *new = malloc(sizeof(struct pkt) + receive_mtu);
	const char *comprname = "";

	if (!new)
		return -ENOMEM;

	new->next = NULL;

	if (compr_type == COMPR_DEFLATE) {
		uint32_t pkt_sum;

		comprname = "deflate";

		vpninfo->inflate_strm.next_in = buf;
		vpninfo->inflate_strm.avail_in = len - 4;

		vpninfo->inflate_strm.next_out = new->data;
		vpninfo->inflate_strm.avail_out = receive_mtu;
		vpninfo->inflate_strm.total_out = 0;

		if (inflate(&vpninfo->inflate_strm, Z_SYNC_FLUSH)) {
			vpn_progress(vpninfo, PRG_ERR, _("inflate failed\n"));
			free(new);
			return -EINVAL;
		}

		new->len = vpninfo->inflate_strm.total_out;

		vpninfo->inflate_adler32 = adler32(vpninfo->inflate_adler32,
						   new->data, new->len);

		pkt_sum = load_be32(buf + len - 4);

		if (vpninfo->inflate_adler32 != pkt_sum)
			vpninfo->quit_reason = "Compression (inflate) adler32 failure";

	} else if (compr_type == COMPR_LZS) {
		comprname = "LZS";

		new->len = lzs_decompress(new->data, receive_mtu, buf, len);
		if (new->len < 0) {
			len = new->len;
			if (len == 0)
				len = -EINVAL;
			vpn_progress(vpninfo, PRG_ERR, _("LZS decompression failed: %s\n"),
				     strerror(-len));
			free(new);
			return len;
		}
#ifdef HAVE_LZ4
	} else if (compr_type == COMPR_LZ4) {
		comprname = "LZ4";
		new->len = LZ4_decompress_safe((void *)buf, (void *)new->data, len, receive_mtu);
		if (new->len <= 0) {
			len = new->len;
			if (len == 0)
				len = -EINVAL;
			vpn_progress(vpninfo, PRG_ERR, _("LZ4 decompression failed\n"));
			free(new);
			return len;
		}
#endif
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown compression type %d\n"), compr_type);
		free(new);
		return -EINVAL;
	}
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Received %s compressed data packet of %d bytes (was %d)\n"),
		     comprname, new->len, len);

	queue_packet(&vpninfo->incoming_queue, new);
	return 0;
}

int compress_packet(struct openconnect_info *vpninfo, int compr_type, struct pkt *this)
{
	int ret;

	if (compr_type == COMPR_DEFLATE) {
		vpninfo->deflate_strm.next_in = this->data;
		vpninfo->deflate_strm.avail_in = this->len;
		vpninfo->deflate_strm.next_out = (void *)vpninfo->deflate_pkt->data;
		vpninfo->deflate_strm.avail_out = vpninfo->deflate_pkt_size - 4;
		vpninfo->deflate_strm.total_out = 0;

		ret = deflate(&vpninfo->deflate_strm, Z_SYNC_FLUSH);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("deflate failed %d\n"), ret);
			/* Things are going to go horribly wrong if we try to do any
			   more compression. Give up entirely. */
			vpninfo->cstp_compr = 0;
			return -EIO;
		}

		/* Add ongoing adler32 to tail of compressed packet */
		vpninfo->deflate_adler32 = adler32(vpninfo->deflate_adler32,
						   this->data, this->len);

		store_be32(&vpninfo->deflate_pkt->data[vpninfo->deflate_strm.total_out],
			   vpninfo->deflate_adler32);

		vpninfo->deflate_pkt->len = vpninfo->deflate_strm.total_out + 4;
		return 0;
	} else if (compr_type == COMPR_LZS) {
		if (this->len < 40)
			return -EFBIG;

		ret = lzs_compress(vpninfo->deflate_pkt->data, this->len,
				   this->data, this->len);
		if (ret < 0)
			return ret;

		vpninfo->deflate_pkt->len = ret;
		return 0;
#ifdef HAVE_LZ4
	} else if (compr_type == COMPR_LZ4) {
		if (this->len < 40)
			return -EFBIG;

		ret = LZ4_compress_default((void*)this->data, (void*)vpninfo->deflate_pkt->data,
					   this->len, this->len);
		if (ret <= 0) {
			if (ret == 0)
				ret = -EFBIG;
			return ret;
		}

		vpninfo->deflate_pkt->len = ret;
		return 0;
#endif
	} else
		return -EINVAL;

	return 0;
}

int cstp_mainloop(struct openconnect_info *vpninfo, int *timeout)
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
		/* Some servers send us packets that are larger than
		   negotiated MTU. We reserve some extra space to
		   handle that */
		int receive_mtu = MAX(16384, vpninfo->deflate_pkt_size ? : vpninfo->ip_info.mtu);
		int len, payload_len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, vpninfo->cstp_pkt->cstp.hdr, receive_mtu + 8);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len < 8) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		if (vpninfo->cstp_pkt->cstp.hdr[0] != 'S' || vpninfo->cstp_pkt->cstp.hdr[1] != 'T' ||
		    vpninfo->cstp_pkt->cstp.hdr[2] != 'F' || vpninfo->cstp_pkt->cstp.hdr[3] != 1 ||
		    vpninfo->cstp_pkt->cstp.hdr[7])
			goto unknown_pkt;

		payload_len = load_be16(vpninfo->cstp_pkt->cstp.hdr + 4);
		if (len != 8 + payload_len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected packet length. SSL_read returned %d but packet is\n"),
				     len);
			vpn_progress(vpninfo, PRG_ERR,
				     "%02x %02x %02x %02x %02x %02x %02x %02x\n",
				     vpninfo->cstp_pkt->cstp.hdr[0], vpninfo->cstp_pkt->cstp.hdr[1],
				     vpninfo->cstp_pkt->cstp.hdr[2], vpninfo->cstp_pkt->cstp.hdr[3],
				     vpninfo->cstp_pkt->cstp.hdr[4], vpninfo->cstp_pkt->cstp.hdr[5],
				     vpninfo->cstp_pkt->cstp.hdr[6], vpninfo->cstp_pkt->cstp.hdr[7]);
			continue;
		}
		vpninfo->ssl_times.last_rx = time(NULL);
		switch (vpninfo->cstp_pkt->cstp.hdr[6]) {
		case AC_PKT_DPD_OUT:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Got CSTP DPD request\n"));
			vpninfo->owe_ssl_dpd_response = 1;
			continue;

		case AC_PKT_DPD_RESP:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Got CSTP DPD response\n"));
			continue;

		case AC_PKT_KEEPALIVE:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Got CSTP Keepalive\n"));
			continue;

		case AC_PKT_DATA:
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received uncompressed data packet of %d bytes\n"),
				     payload_len);
			vpninfo->cstp_pkt->len = payload_len;
			queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			work_done = 1;
			continue;

		case AC_PKT_DISCONN: {
			int i;
			if (payload_len >= 2) {
				for (i = 1; i < payload_len; i++) {
					if (!isprint(vpninfo->cstp_pkt->data[i]))
						vpninfo->cstp_pkt->data[i] = '.';
				}
				vpninfo->cstp_pkt->data[payload_len] = 0;
				vpn_progress(vpninfo, PRG_ERR,
					     _("Received server disconnect: %02x '%s'\n"),
					     vpninfo->cstp_pkt->data[0], vpninfo->cstp_pkt->data + 1);
			} else {
				vpn_progress(vpninfo, PRG_ERR, _("Received server disconnect\n"));
			}
			vpninfo->quit_reason = "Server request";
			return -EPIPE;
		}
		case AC_PKT_COMPRESSED:
			if (!vpninfo->cstp_compr) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Compressed packet received in !deflate mode\n"));
				goto unknown_pkt;
			}
			decompress_and_queue_packet(vpninfo, vpninfo->cstp_compr,
						    vpninfo->cstp_pkt->data, payload_len);
			work_done = 1;
			continue;

		case AC_PKT_TERM_SERVER:
			vpn_progress(vpninfo, PRG_ERR, _("received server terminate packet\n"));
			vpninfo->quit_reason = "Server request";
			return -EPIPE;
		}

	unknown_pkt:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown packet %02x %02x %02x %02x %02x %02x %02x %02x\n"),
			     vpninfo->cstp_pkt->cstp.hdr[0], vpninfo->cstp_pkt->cstp.hdr[1],
			     vpninfo->cstp_pkt->cstp.hdr[2], vpninfo->cstp_pkt->cstp.hdr[3],
			     vpninfo->cstp_pkt->cstp.hdr[4], vpninfo->cstp_pkt->cstp.hdr[5],
			     vpninfo->cstp_pkt->cstp.hdr[6], vpninfo->cstp_pkt->cstp.hdr[7]);
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
					 vpninfo->current_ssl_pkt->cstp.hdr,
					 vpninfo->current_ssl_pkt->len + 8);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
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
		}

		if (ret != vpninfo->current_ssl_pkt->len + 8) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 8, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt == vpninfo->deflate_pkt) {
			free(vpninfo->pending_deflated_pkt);
			vpninfo->pending_deflated_pkt = NULL;
		} else if (vpninfo->current_ssl_pkt != &dpd_pkt &&
			 vpninfo->current_ssl_pkt != &dpd_resp_pkt &&
			 vpninfo->current_ssl_pkt != &keepalive_pkt)
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

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
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP Keepalive\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		goto handle_outgoing;

	case KA_NONE:
		;
	}

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		if (vpninfo->cstp_compr) {
			ret = compress_packet(vpninfo, vpninfo->cstp_compr, this);
			if (ret < 0)
				goto uncompr;

			store_be16(vpninfo->deflate_pkt->cstp.hdr + 4, vpninfo->deflate_pkt->len);

			/* DTLS compression may have screwed with this */
			vpninfo->deflate_pkt->cstp.hdr[7] = 0;

			vpn_progress(vpninfo, PRG_TRACE,
				     _("Sending compressed data packet of %d bytes (was %d)\n"),
				     vpninfo->deflate_pkt->len, this->len);

			vpninfo->pending_deflated_pkt = this;
			vpninfo->current_ssl_pkt = vpninfo->deflate_pkt;
		} else {
		uncompr:
			memcpy(this->cstp.hdr, data_hdr, 8);
			store_be16(this->cstp.hdr + 4, this->len);

			vpn_progress(vpninfo, PRG_TRACE,
				     _("Sending uncompressed data packet of %d bytes\n"),
				     this->len);

			vpninfo->current_ssl_pkt = this;
		}
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int cstp_bye(struct openconnect_info *vpninfo, const char *reason)
{
	unsigned char *bye_pkt;
	int reason_len;

	/* already lost connection? */
#if defined(OPENCONNECT_OPENSSL)
	if (!vpninfo->https_ssl)
		return 0;
#elif defined(OPENCONNECT_GNUTLS)
	if (!vpninfo->https_sess)
		return 0;
#endif

	reason_len = strlen(reason);
	bye_pkt = malloc(reason_len + 9);
	if (!bye_pkt)
		return -ENOMEM;

	memcpy(bye_pkt, data_hdr, 8);
	memcpy(bye_pkt + 9, reason, reason_len);

	store_be16(bye_pkt + 4, reason_len + 1);
	bye_pkt[6] = AC_PKT_DISCONN;
	bye_pkt[8] = 0xb0;

	vpn_progress(vpninfo, PRG_INFO,
		     _("Send BYE packet: %s\n"), reason);

	ssl_nonblock_write(vpninfo, bye_pkt, reason_len + 9);
	free(bye_pkt);

	return 0;
}

void cstp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	http_common_headers(vpninfo, buf);

	buf_append(buf, "Accept: */*\r\n");
	buf_append(buf, "Accept-Encoding: identity\r\n");
	buf_append(buf, "X-Transcend-Version: 1\r\n");
	if (vpninfo->xmlpost) {
		buf_append(buf, "X-Aggregate-Auth: 1\r\n");
		buf_append(buf, "X-AnyConnect-Platform: %s\r\n",
			   vpninfo->platname);
	}
	if (vpninfo->try_http_auth)
		buf_append(buf, "X-Support-HTTP-Auth: true\r\n");

	append_mobile_headers(vpninfo, buf);
}
