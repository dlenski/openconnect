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

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "openconnect-internal.h"

/*
 * The master-secret is generated randomly by the client. The server
 * responds with a DTLS Session-ID. These, done over the HTTPS
 * connection, are enough to 'resume' a DTLS session, bypassing all
 * the normal setup of a normal DTLS connection.
 *
 * Cisco use a version of the protocol which predates RFC4347, but
 * isn't quite the same as the pre-RFC version of the protocol which
 * was in OpenSSL 0.9.8e -- it includes backports of some later
 * OpenSSL patches.
 *
 * The openssl/ directory of this source tree should contain both a
 * small patch against OpenSSL 0.9.8e to make it support Cisco's
 * snapshot of the protocol, and a larger patch against newer OpenSSL
 * which gives us an option to use the old protocol again.
 *
 * Cisco's server also seems to respond to the official version of the
 * protocol, with a change in the ChangeCipherSpec packet which implies
 * that it does know the difference and isn't just repeating the version
 * number seen in the ClientHello. But although I can make the handshake
 * complete by hacking tls1_mac() to use the _old_ protocol version
 * number when calculating the MAC, the server still seems to be ignoring
 * my subsequent data packets. So we use the old protocol, which is what
 * their clients use anyway.
 */

#if defined(OPENCONNECT_OPENSSL)
#define DTLS_SEND SSL_write
#define DTLS_RECV SSL_read
#elif defined(OPENCONNECT_GNUTLS)
#define DTLS_SEND gnutls_record_send
#define DTLS_RECV gnutls_record_recv
#endif

char *openconnect_bin2hex(const char *prefix, const uint8_t *data, unsigned len)
{
	struct oc_text_buf *buf;
	char *p = NULL;

	buf = buf_alloc();
	buf_append(buf, "%s", prefix);
	buf_append_hex(buf, data, len);

	if (!buf_error(buf)) {
		p = buf->data;
		buf->data = NULL;
	}
	buf_free(buf);

	return p;
}

static int connect_dtls_socket(struct openconnect_info *vpninfo)
{
	int dtls_fd, ret;

	/* Sanity check for the removal of new_dtls_{fd,ssl} */
	if (vpninfo->dtls_fd != -1) {
		vpn_progress(vpninfo, PRG_ERR, _("DTLS connection attempted with an existing fd\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	if (!vpninfo->dtls_addr) {
		vpn_progress(vpninfo, PRG_ERR, _("No DTLS address\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	if (!vpninfo->dtls_cipher) {
		/* We probably didn't offer it any ciphers it liked */
		vpn_progress(vpninfo, PRG_ERR, _("Server offered no DTLS cipher option\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	if (vpninfo->proxy) {
		/* XXX: Theoretically, SOCKS5 proxies can do UDP too */
		vpn_progress(vpninfo, PRG_ERR, _("No DTLS when connected via proxy\n"));
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	dtls_fd = udp_connect(vpninfo);
	if (dtls_fd < 0)
		return -EINVAL;


	ret = start_dtls_handshake(vpninfo, dtls_fd);
	if (ret) {
		closesocket(dtls_fd);
		return ret;
	}

	vpninfo->dtls_state = DTLS_CONNECTING;

	vpninfo->dtls_fd = dtls_fd;
	monitor_fd_new(vpninfo, dtls);
	monitor_read_fd(vpninfo, dtls);
	monitor_except_fd(vpninfo, dtls);

	time(&vpninfo->new_dtls_started);

	return dtls_try_handshake(vpninfo);
}

void dtls_close(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_ssl) {
		dtls_ssl_free(vpninfo);
		closesocket(vpninfo->dtls_fd);
		unmonitor_read_fd(vpninfo, dtls);
		unmonitor_write_fd(vpninfo, dtls);
		unmonitor_except_fd(vpninfo, dtls);
		vpninfo->dtls_ssl = NULL;
		vpninfo->dtls_fd = -1;
	}
}

static int dtls_reconnect(struct openconnect_info *vpninfo)
{
	dtls_close(vpninfo);

	if (vpninfo->dtls_state == DTLS_DISABLED)
		return -EINVAL;

	vpninfo->dtls_state = DTLS_SLEEPING;
	return connect_dtls_socket(vpninfo);
}

int dtls_setup(struct openconnect_info *vpninfo, int dtls_attempt_period)
{
	struct oc_vpn_option *dtls_opt = vpninfo->dtls_options;
	int dtls_port = 0;

	if (vpninfo->dtls_state == DTLS_DISABLED)
		return -EINVAL;

	vpninfo->dtls_attempt_period = dtls_attempt_period;
	if (!dtls_attempt_period)
		return 0;

	while (dtls_opt) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("DTLS option %s : %s\n"),
			     dtls_opt->option, dtls_opt->value);

		if (!strcmp(dtls_opt->option + 7, "Port")) {
			dtls_port = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "Keepalive")) {
			vpninfo->dtls_times.keepalive = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "DPD")) {
			int j = atol(dtls_opt->value);
			if (j && (!vpninfo->dtls_times.dpd || j < vpninfo->dtls_times.dpd))
				vpninfo->dtls_times.dpd = j;
		} else if (!strcmp(dtls_opt->option + 7, "Rekey-Method")) {
			if (!strcmp(dtls_opt->value, "new-tunnel"))
				vpninfo->dtls_times.rekey_method = REKEY_TUNNEL;
			else if (!strcmp(dtls_opt->value, "ssl"))
				vpninfo->dtls_times.rekey_method = REKEY_SSL;
			else
				vpninfo->dtls_times.rekey_method = REKEY_NONE;
		} else if (!strcmp(dtls_opt->option + 7, "Rekey-Time")) {
			vpninfo->dtls_times.rekey = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "CipherSuite")) {
			vpninfo->dtls_cipher = strdup(dtls_opt->value);
		}

		dtls_opt = dtls_opt->next;
	}
	if (!dtls_port) {
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}
	if (vpninfo->dtls_times.rekey <= 0)
		vpninfo->dtls_times.rekey_method = REKEY_NONE;

	if (udp_sockaddr(vpninfo, dtls_port)) {
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}
	if (connect_dtls_socket(vpninfo))
		return -EINVAL;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("DTLS initialised. DPD %d, Keepalive %d\n"),
		     vpninfo->dtls_times.dpd, vpninfo->dtls_times.keepalive);

	return 0;
}

int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int work_done = 0;
	char magic_pkt;

	if (vpninfo->dtls_need_reconnect) {
		vpninfo->dtls_need_reconnect = 0;
		dtls_reconnect(vpninfo);
		return 1;
	}

	if (vpninfo->dtls_state == DTLS_CONNECTING) {
		dtls_try_handshake(vpninfo);
		return 0;
	}

	if (vpninfo->dtls_state == DTLS_SLEEPING) {
		int when = vpninfo->new_dtls_started + vpninfo->dtls_attempt_period - time(NULL);

		if (when <= 0) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Attempt new DTLS connection\n"));
			connect_dtls_socket(vpninfo);
		} else if ((when * 1000) < *timeout) {
			*timeout = when * 1000;
		}
		return 0;
	}

	while (1) {
		int len = vpninfo->ip_info.mtu;
		unsigned char *buf;

		if (!vpninfo->dtls_pkt) {
			vpninfo->dtls_pkt = malloc(sizeof(struct pkt) + len);
			if (!vpninfo->dtls_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		buf = vpninfo->dtls_pkt->data - 1;
		len = DTLS_RECV(vpninfo->dtls_ssl, buf, len + 1);
		if (len <= 0)
			break;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received DTLS packet 0x%02x of %d bytes\n"),
			     buf[0], len);

		vpninfo->dtls_times.last_rx = time(NULL);

		switch (buf[0]) {
		case AC_PKT_DATA:
			vpninfo->dtls_pkt->len = len - 1;
			queue_packet(&vpninfo->incoming_queue, vpninfo->dtls_pkt);
			vpninfo->dtls_pkt = NULL;
			work_done = 1;
			break;

		case AC_PKT_DPD_OUT:
			vpn_progress(vpninfo, PRG_DEBUG, _("Got DTLS DPD request\n"));

			/* FIXME: What if the packet doesn't get through? */
			magic_pkt = AC_PKT_DPD_RESP;
			if (DTLS_SEND(vpninfo->dtls_ssl, &magic_pkt, 1) != 1)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to send DPD response. Expect disconnect\n"));
			continue;

		case AC_PKT_DPD_RESP:
			vpn_progress(vpninfo, PRG_DEBUG, _("Got DTLS DPD response\n"));
			break;

		case AC_PKT_KEEPALIVE:
			vpn_progress(vpninfo, PRG_DEBUG, _("Got DTLS Keepalive\n"));
			break;

		case AC_PKT_COMPRESSED:
			if (!vpninfo->dtls_compr) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Compressed DTLS packet received when compression not enabled\n"));
				goto unknown_pkt;
			}
			decompress_and_queue_packet(vpninfo, vpninfo->dtls_compr,
						    vpninfo->dtls_pkt->data, len - 1);
			break;
		default:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown DTLS packet type %02x, len %d\n"),
				     buf[0], len);
			if (1) {
				/* Some versions of OpenSSL have bugs with receiving out-of-order
				 * packets. Not only do they wrongly decide to drop packets if
				 * two packets get swapped in transit, but they also _fail_ to
				 * drop the packet in non-blocking mode; instead they return
				 * the appropriate length of garbage. So don't abort... for now. */
				break;
			} else {
			unknown_pkt:
				vpninfo->quit_reason = "Unknown packet received";
				return 1;
			}

		}
	}

	switch (keepalive_action(&vpninfo->dtls_times, timeout)) {
	case KA_REKEY: {
		int ret;

		vpn_progress(vpninfo, PRG_INFO, _("DTLS rekey due\n"));

		if (vpninfo->dtls_times.rekey_method == REKEY_SSL) {
			time(&vpninfo->new_dtls_started);
			vpninfo->dtls_state = DTLS_CONNECTING;
			ret = dtls_try_handshake(vpninfo);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("DTLS Rehandshake failed; reconnecting.\n"));
				return connect_dtls_socket(vpninfo);
			}
		}

		return 1;
	}

	case KA_DPD_DEAD:
		vpn_progress(vpninfo, PRG_ERR, _("DTLS Dead Peer Detection detected dead peer!\n"));
		/* Fall back to SSL, and start a new DTLS connection */
		dtls_reconnect(vpninfo);
		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send DTLS DPD\n"));

		magic_pkt = AC_PKT_DPD_OUT;
		if (DTLS_SEND(vpninfo->dtls_ssl, &magic_pkt, 1) != 1)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send DPD request. Expect disconnect\n"));

		/* last_dpd will just have been set */
		vpninfo->dtls_times.last_tx = vpninfo->dtls_times.last_dpd;
		work_done = 1;
		break;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->outgoing_queue.head)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send DTLS Keepalive\n"));

		magic_pkt = AC_PKT_KEEPALIVE;
		if (DTLS_SEND(vpninfo->dtls_ssl, &magic_pkt, 1) != 1)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send keepalive request. Expect disconnect\n"));
		time(&vpninfo->dtls_times.last_tx);
		work_done = 1;
		break;

	case KA_NONE:
		;
	}

	/* Service outgoing packet queue */
	unmonitor_write_fd(vpninfo, dtls);
	while (vpninfo->outgoing_queue.head) {
		struct pkt *this = dequeue_packet(&vpninfo->outgoing_queue);
		struct pkt *send_pkt = this;
		int ret;

		/* If TOS optname is set, we want to copy the TOS/TCLASS header
		   to the outer UDP packet */
		if (vpninfo->dtls_tos_optname) {
			int valid=1;
			int tos;

			switch(this->data[0] >> 4) {
				case 4:
					tos = this->data[1];
					break;
				case 6:
					tos = (load_be16(this->data) >> 4) & 0xff;
					break;
				default:
					vpn_progress(vpninfo, PRG_ERR,
						     _("Unknown packet (len %d) received: %02x %02x %02x %02x...\n"),
						     this->len, this->data[0], this->data[1], this->data[2], this->data[3]);
					valid = 0;
			}

			/* set the actual value */
			if (valid && tos != vpninfo->dtls_tos_current) {
				vpn_progress(vpninfo, PRG_DEBUG, _("TOS this: %d, TOS last: %d\n"),
					     tos, vpninfo->dtls_tos_current);
				if (setsockopt(vpninfo->dtls_fd, vpninfo->dtls_tos_proto,
					       vpninfo->dtls_tos_optname, (void *)&tos, sizeof(tos)))
					vpn_perror(vpninfo, _("UDP setsockopt"));
				else
					vpninfo->dtls_tos_current = tos;
			}
		}

		/* One byte of header */
		this->cstp.hdr[7] = AC_PKT_DATA;

		/* We can compress into vpninfo->deflate_pkt unless CSTP
		 * currently has a compressed packet pending — which it
		 * shouldn't if DTLS is active. */
		if (vpninfo->dtls_compr &&
		    vpninfo->current_ssl_pkt != vpninfo->deflate_pkt &&
		    !compress_packet(vpninfo, vpninfo->dtls_compr, this)) {
				send_pkt = vpninfo->deflate_pkt;
				send_pkt->cstp.hdr[7] = AC_PKT_COMPRESSED;
		}

#ifdef OPENCONNECT_OPENSSL
		ret = SSL_write(vpninfo->dtls_ssl, &send_pkt->cstp.hdr[7], send_pkt->len + 1);
		if (ret <= 0) {
			ret = SSL_get_error(vpninfo->dtls_ssl, ret);

			if (ret == SSL_ERROR_WANT_WRITE) {
				monitor_write_fd(vpninfo, dtls);
				requeue_packet(&vpninfo->outgoing_queue, this);
			} else if (ret != SSL_ERROR_WANT_READ) {
				/* If it's a real error, kill the DTLS connection and
				   requeue the packet to be sent over SSL */
				vpn_progress(vpninfo, PRG_ERR,
					     _("DTLS got write error %d. Falling back to SSL\n"),
					     ret);
				openconnect_report_ssl_errors(vpninfo);
				dtls_reconnect(vpninfo);
				requeue_packet(&vpninfo->outgoing_queue, this);
				work_done = 1;
			}
			return work_done;
		}
#else /* GnuTLS */
		ret = gnutls_record_send(vpninfo->dtls_ssl, &send_pkt->cstp.hdr[7], send_pkt->len + 1);
		if (ret <= 0) {
			if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("DTLS got write error: %s. Falling back to SSL\n"),
					     gnutls_strerror(ret));
				dtls_reconnect(vpninfo);
				work_done = 1;
			} else {
				/* Wake me up when it becomes writeable */
				monitor_write_fd(vpninfo, dtls);
			}

			requeue_packet(&vpninfo->outgoing_queue, this);
			return work_done;
		}
#endif
		time(&vpninfo->dtls_times.last_tx);
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sent DTLS packet of %d bytes; DTLS send returned %d\n"),
			     this->len, ret);
		free(this);
	}

	return work_done;
}

#define MTU_ID_SIZE 4
#define MTU_MAX_TRIES 10
#define MTU_TIMEOUT_MS 2400

/* Performs a binary search to detect MTU.
 * @buf: is preallocated with MTU size
 * @id: a unique ID for our DPD exchange
 *
 * Returns: new MTU or 0
 */
static int detect_mtu_ipv4(struct openconnect_info *vpninfo, unsigned char *buf)
{
	int max, min, cur, ret, orig_min;
	int tries = 0; /* Number of loops in bin search - includes resends */
	char id[MTU_ID_SIZE];

	cur = max = vpninfo->ip_info.mtu;
	orig_min = min = vpninfo->ip_info.mtu/2;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Initiating IPv4 MTU detection (min=%d, max=%d)\n"), min, max);

	while (max > min) {
		/* Common case will be that the negotiated MTU is correct.
		   So try that first. Then search lower values. */
		if (!tries)
			cur = max;
		else
			cur = (min + max + 1) / 2;

	next_rnd:
		/* Generate unique ID */
		if (openconnect_random(id, sizeof(id)) < 0)
			goto fail;

	next_nornd:
		if (tries++ >= MTU_MAX_TRIES) {
			if (orig_min == min) {
				/* Hm, we never got *anything* back successfully? */
				vpn_progress(vpninfo, PRG_ERR,
					     _("Too long time in MTU detect loop; assuming negotiated MTU.\n"));
				goto fail;
			} else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Too long time in MTU detect loop; MTU set to %d.\n"), min);
				return min;
			}
		}

		buf[0] = AC_PKT_DPD_OUT;
		memcpy(&buf[1], id, sizeof(id));

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending MTU DPD probe (%u bytes, min=%u, max=%u)\n"), cur, min, max);
		ret = openconnect_dtls_write(vpninfo, buf, cur+1);
		if (ret != cur+1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send DPD request (%d %d)\n"), cur, ret);
			/* If it didn't even manage to send, it took basically zero time.
			   So don't count it as a 'try' for the purpose of our timeout. */
			max = --cur;
			tries--;
			goto next_rnd;
		}

	reread:
		memset(buf, 0, sizeof(id)+1);

		ret = openconnect_dtls_read(vpninfo, buf, cur+1, MTU_TIMEOUT_MS);
		if (ret > 0 && (buf[0] != AC_PKT_DPD_RESP || memcmp(&buf[1], id, sizeof(id)) != 0)) {
			vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received unexpected packet (%.2x) in MTU detection; skipping.\n"), (unsigned)buf[0]);
			goto reread;
		}

		/* Timeout. Either it was too large, or it just got lost. Try again
		 * with a smaller value, but don't actually reduce 'max' because we
		 * don't *know* it was too large. */
		if (ret == -ETIMEDOUT) {
			int next = (min + cur + 1) / 2;

			if (next < cur && next > min) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Timeout while waiting for DPD response; trying %d\n"),
					     next);
				cur = next;
				/* We don't set 'max' because we don't *know* it won't get through */
				goto next_rnd;
			} else {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Timeout while waiting for DPD response; resending probe.\n"));
				goto next_nornd;
			}
		}

		if (ret <= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to recv DPD request (%d)\n"), cur);
			goto fail;
		}

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received MTU DPD probe (%u bytes of %u)\n"), ret, cur);

		/* If we reached the max, success */
		if (cur == max)
			break;

		min = cur;
	}

	return cur;
 fail:
 	return 0;
}

#if defined(IPPROTO_IPV6)

/* This symbol is missing in glibc < 2.22 (bug 18643). */
#if defined(__linux__) && !defined(HAVE_IPV6_PATHMTU)
# define HAVE_IPV6_PATHMTU 1
# define IPV6_PATHMTU 61
#endif

/* Verifies whether current MTU is ok, or detects new MTU using IPv6's ICMP6 messages
 * @buf: is preallocated with MTU size
 * @id: a unique ID for our DPD exchange
 *
 * Returns: new MTU or 0
 */
static int detect_mtu_ipv6(struct openconnect_info *vpninfo, unsigned char *buf)
{
	int max, cur, ret;
	int max_resends = 5; /* maximum number of resends */
	char id[MTU_ID_SIZE];
	unsigned re_use_rnd_val = 0;

	cur = max = vpninfo->ip_info.mtu;

	vpn_progress(vpninfo, PRG_DEBUG,
	     _("Initiating IPv6 MTU detection\n"));

	while(max_resends-- > 0) {
		/* generate unique ID */
		if (!re_use_rnd_val) {
			if (openconnect_random(id, sizeof(id)) < 0)
				goto fail;
		} else {
			re_use_rnd_val = 0;
		}

		buf[0] = AC_PKT_DPD_OUT;
		memcpy(&buf[1], id, sizeof(id));

		vpn_progress(vpninfo, PRG_TRACE,
		     _("Sending MTU DPD probe (%u bytes)\n"), cur);
		ret = openconnect_dtls_write(vpninfo, buf, cur+1);
		if (ret != cur+1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send DPD request (%d)\n"), cur);
			goto mtu6_fail;
		}

 reread:
		memset(buf, 0, sizeof(id)+1);
		ret = openconnect_dtls_read(vpninfo, buf, cur+1, MTU_TIMEOUT_MS);

		/* timeout, probably our original request was lost,
		 * let's resend the DPD */
		if (ret == -ETIMEDOUT) {
			vpn_progress(vpninfo, PRG_DEBUG,
			     _("Timeout while waiting for DPD response; resending probe.\n"));
			re_use_rnd_val = 1;
			continue;
		}

		/* something unexpected was received, let's ignore it */
		if (ret > 0 && (buf[0] != AC_PKT_DPD_RESP || memcmp(&buf[1], id, sizeof(id)) != 0)) {
			vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received unexpected packet (%.2x) in MTU detection; skipping.\n"), (unsigned)buf[0]);
			goto reread;
		}

		vpn_progress(vpninfo, PRG_TRACE,
		     _("Received MTU DPD probe (%u bytes)\n"), cur);

		/* we received what we expected, move on */
		break;
	}

#ifdef HAVE_IPV6_PATHMTU
	/* If we received back our DPD packet, do nothing; otherwise,
	 * attempt to get MTU from the ICMP6 packet we received */
	if (ret <= 0) {
		struct ip6_mtuinfo mtuinfo;
		socklen_t len = sizeof(mtuinfo);
		max = 0;
		vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to recv DPD request (%d)\n"), cur);
 mtu6_fail:
		if (getsockopt(vpninfo->dtls_fd, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo, &len) >= 0) {
			max = mtuinfo.ip6m_mtu;
			if (max >= 0 && max < cur) {
				cur = dtls_set_mtu(vpninfo, max) - /*ipv6*/40 - /*udp*/20 - /*oc dtls*/1;
			}
		}
	}
#else
 mtu6_fail:
#endif

	return cur;
 fail:
	return 0;
}
#endif

void dtls_detect_mtu(struct openconnect_info *vpninfo)
{
	int mtu = vpninfo->ip_info.mtu;
	int prev_mtu = vpninfo->ip_info.mtu;
	unsigned char *buf;

	if (vpninfo->ip_info.mtu < 1+MTU_ID_SIZE)
		return;

	/* detect MTU */
	buf = calloc(1, 1 + vpninfo->ip_info.mtu);
	if (!buf) {
		vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
		return;
	}

	if (vpninfo->peer_addr->sa_family == AF_INET) { /* IPv4 */
		mtu = detect_mtu_ipv4(vpninfo, buf);
		if (mtu == 0)
			goto skip_mtu;
#if defined(IPPROTO_IPV6)
	} else if (vpninfo->peer_addr->sa_family == AF_INET6) { /* IPv6 */
		mtu = detect_mtu_ipv6(vpninfo, buf);
		if (mtu == 0)
			goto skip_mtu;
#endif
	}

	vpninfo->ip_info.mtu = mtu;
	if (prev_mtu != vpninfo->ip_info.mtu) {
		vpn_progress(vpninfo, PRG_INFO,
		     _("Detected MTU of %d bytes (was %d)\n"), vpninfo->ip_info.mtu, prev_mtu);
	} else {
		vpn_progress(vpninfo, PRG_DEBUG,
		     _("No change in MTU after detection (was %d)\n"), prev_mtu);
	}

 skip_mtu:
	free(buf);
}

