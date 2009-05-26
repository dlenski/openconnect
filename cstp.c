/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008 Intel Corporation.
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "openconnect.h"

/*
 * Data packets are encapsulated in the SSL stream as follows:
 *
 * 0000: Magic "STF\x1"
 * 0004: Big-endian 16-bit length (not including 8-byte header)
 * 0006: Byte packet type (see openconnect.h)
 * 0008: data payload
 */

static char data_hdr[8] = {
	'S', 'T', 'F', 1,
	0, 0,		/* Length */
	AC_PKT_DATA,	/* Type */
	0		/* Unknown */
};

static struct pkt keepalive_pkt = {
	.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_KEEPALIVE, 0 },
};

static struct pkt dpd_pkt = {
	.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_DPD_OUT, 0 },
};

static struct pkt dpd_resp_pkt = {
	.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_DPD_RESP, 0 },
};


static int start_cstp_connection(struct openconnect_info *vpninfo)
{
	char buf[65536];
	int i;
	int retried = 0;
	struct vpn_option **next_dtls_option = &vpninfo->dtls_options;
	struct vpn_option **next_cstp_option = &vpninfo->cstp_options;
	struct vpn_option *old_cstp_opts = vpninfo->cstp_options;
	struct vpn_option *old_dtls_opts = vpninfo->dtls_options;
	const char *old_addr = vpninfo->vpn_addr;
	const char *old_netmask = vpninfo->vpn_netmask;
	struct split_include *inc;

	/* Clear old options which will be overwritten */
	vpninfo->vpn_addr = vpninfo->vpn_netmask = NULL;
	vpninfo->cstp_options = vpninfo->dtls_options = NULL;
	vpninfo->vpn_domain = vpninfo->vpn_proxy_pac = NULL;

	for (i=0; i<3; i++)
		vpninfo->vpn_dns[i] = vpninfo->vpn_nbns[i] = NULL;

	for (inc = vpninfo->split_includes; inc; ) {
		struct split_include *next = inc->next;
		free(inc);
		inc = next;
	}
	for (inc = vpninfo->split_excludes; inc; ) {
		struct split_include *next = inc->next;
		free(inc);
		inc = next;
	}
	vpninfo->split_includes = vpninfo->split_excludes = NULL;
 retry:
	openconnect_SSL_printf(vpninfo->https_ssl, "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n");
	openconnect_SSL_printf(vpninfo->https_ssl, "Host: %s\r\n", vpninfo->hostname);
	openconnect_SSL_printf(vpninfo->https_ssl, "User-Agent: %s\r\n", vpninfo->useragent);
	openconnect_SSL_printf(vpninfo->https_ssl, "Cookie: webvpn=%s\r\n", vpninfo->cookie);
	openconnect_SSL_printf(vpninfo->https_ssl, "X-CSTP-Version: 1\r\n");
	openconnect_SSL_printf(vpninfo->https_ssl, "X-CSTP-Hostname: %s\r\n", vpninfo->localname);
	if (vpninfo->deflate)
		openconnect_SSL_printf(vpninfo->https_ssl, "X-CSTP-Accept-Encoding: deflate;q=1.0\r\n");
	openconnect_SSL_printf(vpninfo->https_ssl, "X-CSTP-MTU: %d\r\n", vpninfo->mtu);
	/* To enable IPv6, send 'IPv6,IPv4'.
	   We don't know how most of that works yet though. */
	openconnect_SSL_printf(vpninfo->https_ssl, "X-CSTP-Address-Type: IPv4\r\n");
	openconnect_SSL_printf(vpninfo->https_ssl, "X-DTLS-Master-Secret: ");
	for (i = 0; i < sizeof(vpninfo->dtls_secret); i++)
		openconnect_SSL_printf(vpninfo->https_ssl, "%02X", vpninfo->dtls_secret[i]);
	openconnect_SSL_printf(vpninfo->https_ssl, "\r\nX-DTLS-CipherSuite: %s\r\n\r\n",
			       vpninfo->dtls_ciphers?:"AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA");

	if (openconnect_SSL_gets(vpninfo->https_ssl, buf, 65536) < 0) {
		vpninfo->progress(vpninfo, PRG_ERR, "Error fetching HTTPS response\n");
		if (!retried) {
			retried = 1;
			openconnect_close_https(vpninfo);

			if (openconnect_open_https(vpninfo)) {
				vpninfo->progress(vpninfo, PRG_ERR,
						  "Failed to open HTTPS connection to %s\n",
						  vpninfo->hostname);
				exit(1);
			}
			goto retry;
		}
		return -EINVAL;
	}

	if (strncmp(buf, "HTTP/1.1 200 ", 13)) {
		if (!strncmp(buf, "HTTP/1.1 503 ", 13)) {
			/* "Service Unavailable. Why? */
			char *reason = "<unknown>";
			while ((i = openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
				if (!strncmp(buf, "X-Reason: ", 10)) {
					reason = buf + 10;
					break;
				}
			}
			vpninfo->progress(vpninfo, PRG_ERR, "VPN service unavailable; reason: %s\n",
					  reason);
			return -EINVAL;
		}
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Got inappropriate HTTP CONNECT response: %s\n",
				  buf);
		if (!strncmp(buf, "HTTP/1.1 401 ", 13))
			exit(2);
		return -EINVAL;
	}

	vpninfo->progress(vpninfo, PRG_INFO,
			  "Got CONNECT response: %s\n", buf);

	/* We may have advertised it, but we only do it if the server agrees */
	vpninfo->deflate = 0;

	while ((i = openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		struct vpn_option *new_option;
		char *colon = strchr(buf, ':');
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
			vpninfo->progress(vpninfo, PRG_ERR, "No memory for options\n");
			return -ENOMEM;
		}
		new_option->option = strdup(buf);
		new_option->value = strdup(colon);
		new_option->next = NULL;

		if (!new_option->option || !new_option->value) {
			vpninfo->progress(vpninfo, PRG_ERR, "No memory for options\n");
			return -ENOMEM;
		}

		vpninfo->progress(vpninfo, PRG_TRACE, "%s: %s\n", buf, colon);

		if (!strncmp(buf, "X-DTLS-", 7)) {
			*next_dtls_option = new_option;
			next_dtls_option = &new_option->next;
			continue;
		}
		/* CSTP options... */
		*next_cstp_option = new_option;
		next_cstp_option = &new_option->next;


		if (!strcmp(buf + 7, "Keepalive")) {
			vpninfo->ssl_times.keepalive = atol(colon);
		} else if (!strcmp(buf + 7, "DPD")) {
			vpninfo->ssl_times.dpd = atol(colon);
		} else if (!strcmp(buf + 7, "Content-Encoding")) {
			if (!strcmp(colon, "deflate"))
				vpninfo->deflate = 1;
			else {
				vpninfo->progress(vpninfo, PRG_ERR,
					"Unknown CSTP-Content-Encoding %s\n",
					colon);
				return -EINVAL;
			}
		} else if (!strcmp(buf + 7, "MTU")) {
			vpninfo->mtu = atol(colon);
		} else if (!strcmp(buf + 7, "Address")) {
			vpninfo->vpn_addr = new_option->value;
		} else if (!strcmp(buf + 7, "Netmask")) {
			vpninfo->vpn_netmask = new_option->value;
		} else if (!strcmp(buf + 7, "DNS")) {
			int j;
			for (j = 0; j < 3; j++) {
				if (!vpninfo->vpn_dns[j]) {
					vpninfo->vpn_dns[j] = new_option->value;
					break;
				}
			}
		} else if (!strcmp(buf + 7, "NBNS")) {
			int j;
			for (j = 0; j < 3; j++) {
				if (!vpninfo->vpn_nbns[j]) {
					vpninfo->vpn_nbns[j] = new_option->value;
					break;
				}
			}
		} else if (!strcmp(buf + 7, "Default-Domain")) {
			vpninfo->vpn_domain = new_option->value;
		} else if (!strcmp(buf + 7, "MSIE-Proxy-PAC-URL")) {
			vpninfo->vpn_proxy_pac = new_option->value;
		} else if (!strcmp(buf + 7, "Split-Include")) {
			struct split_include *inc = malloc(sizeof(*inc));
			if (!inc)
				continue;
			inc->route = new_option->value;
			inc->next = vpninfo->split_includes;
			vpninfo->split_includes = inc;
		} else if (!strcmp(buf + 7, "Split-Exclude")) {
			struct split_include *exc = malloc(sizeof(*exc));
			if (!exc)
				continue;
			exc->route = new_option->value;
			exc->next = vpninfo->split_excludes;
			vpninfo->split_excludes = exc;
		}
	}

	if (!vpninfo->vpn_addr) {
		vpninfo->progress(vpninfo, PRG_ERR, "No IP address received. Aborting\n");
		return -EINVAL;
	}
	if (!vpninfo->vpn_netmask)
		vpninfo->vpn_netmask = "255.255.255.255";
	if (old_addr) {
		if (strcmp(old_addr, vpninfo->vpn_addr)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Reconnect gave different IP address (%s != %s)\n",
				vpninfo->vpn_addr, old_addr);
			return -EINVAL;
		}
	}
	if (old_netmask) {
		if (strcmp(old_netmask, vpninfo->vpn_netmask)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Reconnect gave different netmask (%s != %s)\n",
				vpninfo->vpn_netmask, old_netmask);
			return -EINVAL;
		}
	}

	free(vpninfo->dtls_cipher);
	vpninfo->dtls_cipher = NULL;

	while (old_dtls_opts) {
		struct vpn_option *tmp = old_dtls_opts;
		old_dtls_opts = old_dtls_opts->next;
		free(tmp->value);
		free(tmp->option);
		free(tmp);
	}
	while (old_cstp_opts) {
		struct vpn_option *tmp = old_cstp_opts;
		old_cstp_opts = old_cstp_opts->next;
		free(tmp->value);
		free(tmp->option);
		free(tmp);
	}
	vpninfo->progress(vpninfo, PRG_INFO, "CSTP connected. DPD %d, Keepalive %d\n",
			  vpninfo->ssl_times.dpd, vpninfo->ssl_times.keepalive);

	BIO_set_nbio(SSL_get_rbio(vpninfo->https_ssl), 1);
	BIO_set_nbio(SSL_get_wbio(vpninfo->https_ssl), 1);

	fcntl(vpninfo->ssl_fd, F_SETFL, fcntl(vpninfo->ssl_fd, F_GETFL) | O_NONBLOCK);
	if (vpninfo->select_nfds <= vpninfo->ssl_fd)
		vpninfo->select_nfds = vpninfo->ssl_fd + 1;

	FD_SET(vpninfo->ssl_fd, &vpninfo->select_rfds);
	FD_SET(vpninfo->ssl_fd, &vpninfo->select_efds);

	vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
	return 0;
}


int make_cstp_connection(struct openconnect_info *vpninfo)
{
	int ret;

	if (!vpninfo->https_ssl && (ret = openconnect_open_https(vpninfo)))
		return ret;

	if (vpninfo->deflate) {
		vpninfo->deflate_adler32 = 1;
		vpninfo->inflate_adler32 = 1;

		if (inflateInit2(&vpninfo->inflate_strm, -12) ||
		    deflateInit2(&vpninfo->deflate_strm, Z_DEFAULT_COMPRESSION,
				 Z_DEFLATED, -12, 9, Z_DEFAULT_STRATEGY)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Compression setup failed\n");
			vpninfo->deflate = 0;
		}

		if (!vpninfo->deflate_pkt) {
			vpninfo->deflate_pkt = malloc(sizeof(struct pkt) + 2048);
			if (!vpninfo->deflate_pkt) {
				vpninfo->progress(vpninfo, PRG_ERR, "Allocation of deflate buffer failed\n");
				vpninfo->deflate = 0;
			}
			memset(vpninfo->deflate_pkt, 0, sizeof(struct pkt));
			memcpy(vpninfo->deflate_pkt->hdr, data_hdr, 8);
			vpninfo->deflate_pkt->hdr[6] = AC_PKT_COMPRESSED;
		}
	}

	return start_cstp_connection(vpninfo);
}

static int cstp_reconnect(struct openconnect_info *vpninfo)
{
	int ret;
	int timeout;
	int interval;

	timeout = vpninfo->reconnect_timeout;
	interval = vpninfo->reconnect_interval;

	while ((ret = make_cstp_connection(vpninfo))) {
		if (timeout <= 0)
			return ret;
		vpninfo->progress(vpninfo, PRG_INFO,
				  "sleep %ds, remaining timeout %ds\n",
				  interval, timeout);
		sleep(interval);
		if (killed)
			return 1;
		timeout -= interval;
		interval += vpninfo->reconnect_interval;
		if (interval > RECONNECT_INTERVAL_MAX)
			interval = RECONNECT_INTERVAL_MAX;
	}
	return 0;
}

static int inflate_and_queue_packet(struct openconnect_info *vpninfo, int type, void *buf, int len)
{
	struct pkt *new = malloc(sizeof(struct pkt) + vpninfo->mtu);

	if (!new)
		return -ENOMEM;

	new->type = type;
	new->next = NULL;

	vpninfo->inflate_strm.next_in = buf;
	vpninfo->inflate_strm.avail_in = len - 4;

	vpninfo->inflate_strm.next_out = new->data;
	vpninfo->inflate_strm.avail_out = vpninfo->mtu;
	vpninfo->inflate_strm.total_out = 0;

	if (inflate(&vpninfo->inflate_strm, Z_SYNC_FLUSH)) {
		vpninfo->progress(vpninfo, PRG_ERR, "inflate failed\n");
		free(new);
		return -EINVAL;
	}

	new->len = vpninfo->inflate_strm.total_out;

	vpninfo->inflate_adler32 = adler32(vpninfo->inflate_adler32,
					   new->data, new->len);

	if (vpninfo->inflate_adler32 != ntohl( *(uint32_t *) (buf + len - 4) )) {
		vpninfo->quit_reason = "Compression (inflate) adler32 failure";
	}

	vpninfo->progress(vpninfo, PRG_TRACE,
			  "Received compressed data packet of %ld bytes\n",
			  vpninfo->inflate_strm.total_out);

	queue_packet(&vpninfo->incoming_queue, new);
	return 0;
}

int cstp_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	unsigned char buf[16384];
	int len, ret;
	int work_done = 0;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while ( (len = SSL_read(vpninfo->https_ssl, buf, sizeof(buf))) > 0) {
		int payload_len;

		if (buf[0] != 'S' || buf[1] != 'T' ||
		    buf[2] != 'F' || buf[3] != 1 || buf[7])
			goto unknown_pkt;

		payload_len = (buf[4] << 8) + buf[5];
		if (len != 8 + payload_len) {
			vpninfo->progress(vpninfo, PRG_ERR,
					  "Unexpected packet length. SSL_read returned %d but packet is\n",
					  len);
			vpninfo->progress(vpninfo, PRG_ERR,
					  "%02x %02x %02x %02x %02x %02x %02x %02x\n",
					  buf[0], buf[1], buf[2], buf[3],
					  buf[4], buf[5], buf[6], buf[7]);
			continue;
		}
		vpninfo->ssl_times.last_rx = time(NULL);
		switch(buf[6]) {
		case AC_PKT_DPD_OUT:
			vpninfo->progress(vpninfo, PRG_TRACE,
					  "Got CSTP DPD request\n");
			vpninfo->owe_ssl_dpd_response = 1;
			continue;

		case AC_PKT_DPD_RESP:
			vpninfo->progress(vpninfo, PRG_TRACE,
					  "Got CSTP DPD response\n");
			continue;

		case AC_PKT_KEEPALIVE:
			vpninfo->progress(vpninfo, PRG_TRACE,
					  "Got CSTP Keepalive\n");
			continue;

		case AC_PKT_DATA:
			vpninfo->progress(vpninfo, PRG_TRACE,
					  "Received uncompressed data packet of %d bytes\n",
					  payload_len);
			queue_new_packet(&vpninfo->incoming_queue, AF_INET, buf + 8,
					 payload_len);
			work_done = 1;
			continue;

		case AC_PKT_DISCONN: {
			int i;
			for (i = 0; i < payload_len; i++) {
				if (!isprint(buf[payload_len + 8 + i]))
					buf[payload_len + 8 + i] = '.';
			}
			buf[payload_len + 8] = 0;
			vpninfo->progress(vpninfo, PRG_ERR,
					  "Received server disconnect: %02x '%s'\n", buf[8], buf + 9);
			vpninfo->quit_reason = "Server request";
			return 1;
		}
		case AC_PKT_COMPRESSED:
			if (!vpninfo->deflate) {
				vpninfo->progress(vpninfo, PRG_ERR, "Compressed packet received in !deflate mode\n");
				goto unknown_pkt;
			}
			inflate_and_queue_packet(vpninfo, AF_INET, buf + 8, payload_len);
			work_done = 1;
			continue;

		case AC_PKT_TERM_SERVER:
			vpninfo->progress(vpninfo, PRG_ERR, "received server terminate packet\n");
			vpninfo->quit_reason = "Server request";
			return 1;
		}

	unknown_pkt:
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Unknown packet %02x %02x %02x %02x %02x %02x %02x %02x\n",
				  buf[0], buf[1], buf[2], buf[3],
				  buf[4], buf[5], buf[6], buf[7]);
		vpninfo->quit_reason = "Unknown packet received";
		return 1;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		FD_CLR(vpninfo->ssl_fd, &vpninfo->select_wfds);
		ret = SSL_write(vpninfo->https_ssl,
				vpninfo->current_ssl_pkt->hdr,
				vpninfo->current_ssl_pkt->len + 8);
		if (ret <= 0) {
			ret = SSL_get_error(vpninfo->https_ssl, ret);
			switch (ret) {
			case SSL_ERROR_WANT_WRITE:
				/* Waiting for the socket to become writable -- it's
				   probably stalled, and/or the buffers are full */
				FD_SET(vpninfo->ssl_fd, &vpninfo->select_wfds);

			case SSL_ERROR_WANT_READ:
				if (ka_stalled_dpd_time(&vpninfo->ssl_times, timeout))
					goto peer_dead;
				return work_done;
			default:
				vpninfo->progress(vpninfo, PRG_ERR, "SSL_write failed: %d\n", ret);
				ERR_print_errors_fp(stderr);
				goto do_reconnect;
			}
		}
		if (ret != vpninfo->current_ssl_pkt->len + 8) {
			vpninfo->progress(vpninfo, PRG_ERR, "SSL wrote too few bytes! Asked for %d, sent %d\n",
				vpninfo->current_ssl_pkt->len + 8, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt != vpninfo->deflate_pkt &&
		    vpninfo->current_ssl_pkt != &dpd_pkt &&
		    vpninfo->current_ssl_pkt != &dpd_resp_pkt &&
		    vpninfo->current_ssl_pkt != &keepalive_pkt)
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	if (vpninfo->owe_ssl_dpd_response) {
		vpninfo->owe_ssl_dpd_response = 0;
		vpninfo->current_ssl_pkt = &dpd_resp_pkt;
		goto handle_outgoing;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
		/* Not that this will ever happen; we don't even process
		   the setting when we're asked for it. */
		vpninfo->progress(vpninfo, PRG_ERR, "CSTP rekey due but we don't know how\n");
		time(&vpninfo->ssl_times.last_rekey);
		work_done = 1;
		break;

	case KA_DPD_DEAD:
	peer_dead:
		vpninfo->progress(vpninfo, PRG_ERR, "CSTP Dead Peer Detection detected dead peer!\n");
	do_reconnect:
		openconnect_close_https(vpninfo);

		/* It's already deflated in the old stream. Extremely
		   non-trivial to reconstitute it; just throw it away */
		if (vpninfo->current_ssl_pkt == vpninfo->deflate_pkt)
			vpninfo->current_ssl_pkt = NULL;

		if (cstp_reconnect(vpninfo)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Reconnect failed\n");
			vpninfo->quit_reason = "CSTP reconnect failed";
			return 1;
		}
		/* I think we can leave DTLS to its own devices; when we reconnect
		   with the same master secret, we do seem to get the same sessid */
		return 1;

	case KA_DPD:
		vpninfo->progress(vpninfo, PRG_TRACE, "Send CSTP DPD\n");

		vpninfo->current_ssl_pkt = &dpd_pkt;
		goto handle_outgoing;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_fd == -1 && vpninfo->outgoing_queue)
			break;

		vpninfo->progress(vpninfo, PRG_TRACE, "Send CSTP Keepalive\n");

		vpninfo->current_ssl_pkt = &keepalive_pkt;
		goto handle_outgoing;

	case KA_NONE:
		;
	}

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_fd == -1 && vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		vpninfo->outgoing_queue = this->next;
		vpninfo->outgoing_qlen--;

		if (vpninfo->deflate) {
			unsigned char *adler;
			int ret;

			vpninfo->deflate_strm.next_in = this->data;
			vpninfo->deflate_strm.avail_in = this->len;
			vpninfo->deflate_strm.next_out = (void *)vpninfo->deflate_pkt->data;
			vpninfo->deflate_strm.avail_out = 2040;
			vpninfo->deflate_strm.total_out = 0;

			ret = deflate(&vpninfo->deflate_strm, Z_SYNC_FLUSH);
			if (ret) {
				vpninfo->progress(vpninfo, PRG_ERR, "deflate failed %d\n", ret);
				goto uncompr;
			}

			vpninfo->deflate_pkt->hdr[4] = (vpninfo->deflate_strm.total_out + 4) >> 8;
			vpninfo->deflate_pkt->hdr[5] = (vpninfo->deflate_strm.total_out + 4) & 0xff;

			/* Add ongoing adler32 to tail of compressed packet */
			vpninfo->deflate_adler32 = adler32(vpninfo->deflate_adler32,
							   this->data, this->len);

			adler = &vpninfo->deflate_pkt->data[vpninfo->deflate_strm.total_out];
			*(adler++) =  vpninfo->deflate_adler32 >> 24;
			*(adler++) = (vpninfo->deflate_adler32 >> 16) & 0xff;
			*(adler++) = (vpninfo->deflate_adler32 >> 8) & 0xff;
			*(adler)   =  vpninfo->deflate_adler32 & 0xff;

			vpninfo->deflate_pkt->len = vpninfo->deflate_strm.total_out + 4;

			vpninfo->progress(vpninfo, PRG_TRACE,
					  "Sending compressed data packet of %d bytes\n",
					  this->len);

			vpninfo->current_ssl_pkt = vpninfo->deflate_pkt;
		} else {
		uncompr:
			memcpy(this->hdr, data_hdr, 8);
			this->hdr[4] = this->len >> 8;
			this->hdr[5] = this->len & 0xff;

			vpninfo->progress(vpninfo, PRG_TRACE,
					  "Sending uncompressed data packet of %d bytes\n",
					  this->len);

			vpninfo->current_ssl_pkt = this;
		}
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int cstp_bye(struct openconnect_info *vpninfo, char *reason)
{
	unsigned char *bye_pkt;
	int reason_len;

	/* already lost connection? */
	if (!vpninfo->https_ssl)
		return 0;

	reason_len = strlen(reason);
	bye_pkt = malloc(reason_len + 8);
	if (!bye_pkt)
		return -ENOMEM;

	memcpy(bye_pkt, data_hdr, 8);
	memcpy(bye_pkt + 8, reason, reason_len);

	bye_pkt[4] = reason_len >> 8;
	bye_pkt[5] = reason_len & 0xff;
	bye_pkt[6] = AC_PKT_DISCONN;

	SSL_write(vpninfo->https_ssl, bye_pkt, reason_len + 8);
	free(bye_pkt);

	vpninfo->progress(vpninfo, PRG_INFO,
			  "Send BYE packet: %s\n", reason);

	return 0;
}
