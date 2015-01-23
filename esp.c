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

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "openconnect-internal.h"

/* Eventually we're going to have to have more than one incoming ESP
   context at a time, to allow for the overlap period during a rekey.
   So pass the 'esp' even though for now it's redundant. */
int verify_packet_seqno(struct openconnect_info *vpninfo,
			struct esp *esp, uint32_t seq)
{
	/*
	 * For incoming, esp->seq is the next *expected* packet, being
	 * the sequence number *after* the latest we have received.
	 *
	 * Since it must always be true that packet esp->seq-1 has been
	 * received, so there's no need to explicitly record that.
	 *
	 * So the backlog bitmap covers the 32 packets prior to that,
	 * with the LSB representing packet (esp->seq - 2), and the MSB
	 * representing (esp->seq - 33). A received packet is represented
	 * by a zero bit, and a missing packet is represented by a one.
	 *
	 * Thus we can allow out-of-order reception of packets that are
	 * within a reasonable interval of the latest packet received.
	 */

	if (seq == esp->seq) {
		/* The common case. This is the packet we expected next. */
		esp->seq_backlog <<= 1;
		esp->seq++;
		return 0;
	} else if (seq + 33 < esp->seq) {
		/* Too old. We can't know if it's a replay. */
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Discarding ancient ESP packet with seq %u (expected %u)\n"),
			     seq, esp->seq);
		return -EINVAL;
	} else if (seq < esp->seq) {
		/* Within the backlog window, so we remember whether we've seen it or not. */
		uint32_t mask = 1 << (esp->seq - seq - 2);

		if (esp->seq_backlog & mask) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Accepting out-of-order ESP packet with seq %u (expected %u)\n"),
				     seq, esp->seq);
			esp->seq_backlog &= ~mask;
			return 0;
		}
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Discarding replayed ESP packet with seq %u\n"),
			     seq);
		return -EINVAL;
	} else {
		/* The packet we were expecting has gone missing; this one is newer. */
		int delta = seq - esp->seq;

		if (delta >= 32) {
			/* We jumped a long way into the future. We have not seen
			 * any of the previous 32 packets so set the backlog bitmap
			 * to all ones. */
			esp->seq_backlog = 0xffffffff;
		} else if (delta == 31) {
			/* Avoid undefined behaviour that shifting by 32 would incur.
			 * The (clear) top bit represents the packet which is currently
			 * esp->seq - 1, which we know was already received. */
			esp->seq_backlog = 0x7fffffff;
		} else {
			/* We have missed (delta) packets. Shift the backlog by that
			 * amount *plus* the one we would have shifted it anyway if
			 * we'd received the packet we were expecting. The zero bit
			 * representing the packet which is currently esp->seq - 1,
			 * which we know has been received, ends up at bit position
			 * (1<<delta). Then we set all the bits lower than that, which
			 * represent the missing packets. */
			esp->seq_backlog <<= delta + 1;
			esp->seq_backlog |= (1<<delta) - 1;
		}
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Accepting later-than-expected ESP packet with seq %u (expected %u)\n"),
			     seq, esp->seq);
		esp->seq = seq + 1;
		return 0;
	}
}

int print_esp_keys(struct openconnect_info *vpninfo, const char *name, struct esp *esp)
{
	int i;
	const char *enctype, *mactype;
	char enckey[256], mackey[256];
	int enclen, maclen;

	switch(vpninfo->esp_enc) {
	case 0x02:
		enctype = "AES-128-CBC (RFC3602)";
		enclen = 16;
		break;
	case 0x05:
		enctype = "AES-256-CBC (RFC3602)";
		enclen = 32;
		break;
	default:
		return -EINVAL;
	}
	switch(vpninfo->esp_hmac) {
	case 0x01:
		mactype = "HMAC-MD5-96 (RFC2403)";
		maclen = 16;
		break;
	case 0x02:
		mactype = "HMAC-SHA-1-96 (RFC2404)";
		maclen = 20;
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < enclen; i++)
		sprintf(enckey + (2 * i), "%02x", esp->secrets[i]);
	for (i = 0; i < maclen; i++)
		sprintf(mackey + (2 * i), "%02x", esp->secrets[enclen + i]);

	vpn_progress(vpninfo, PRG_TRACE,
		     _("Parameters for %s ESP: SPI 0x%08x\n"),
		     name, ntohl(esp->spi));
	vpn_progress(vpninfo, PRG_TRACE,
		     _("ESP encryption type %s key 0x%s\n"),
		     enctype, enckey);
	vpn_progress(vpninfo, PRG_TRACE,
		     _("ESP authentication type %s key 0x%s\n"),
		     mactype, mackey);
	return 0;
}

static int esp_send_probes(struct openconnect_info *vpninfo)
{
	struct pkt *pkt;
	int pktlen;

	pkt = malloc(sizeof(*pkt) + 1 + vpninfo->pkt_trailer);
	if (!pkt)
		return -ENOMEM;

	pkt->len = 1;
	pkt->data[0] = 0;
	pktlen = encrypt_esp_packet(vpninfo, pkt);
	send(vpninfo->dtls_fd, &pkt->esp, pktlen, 0);

	pkt->len = 1;
	pkt->data[0] = 0;
	pktlen = encrypt_esp_packet(vpninfo, pkt);
	send(vpninfo->dtls_fd, &pkt->esp, pktlen, 0);

	free(pkt);
	time(&vpninfo->new_dtls_started);

	return 0;
};

int esp_setup(struct openconnect_info *vpninfo, int dtls_attempt_period)
{
	int fd;

	if (vpninfo->dtls_state == DTLS_DISABLED ||
	    vpninfo->dtls_state == DTLS_NOSECRET)
		return -EINVAL;

	fd = udp_connect(vpninfo);
	if (fd < 0)
		return fd;

	print_esp_keys(vpninfo, _("incoming"), &vpninfo->esp_in);
	print_esp_keys(vpninfo, _("outgoing"), &vpninfo->esp_out);

	/* We are not connected until we get an ESP packet back */
	vpninfo->dtls_state = DTLS_SLEEPING;
	vpninfo->dtls_fd = fd;
	monitor_fd_new(vpninfo, dtls);
	monitor_read_fd(vpninfo, dtls);
	monitor_except_fd(vpninfo, dtls);

	esp_send_probes(vpninfo);

	return 0;
}

int esp_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int work_done = 0;
	int ret;

	while (1) {
		int len = vpninfo->ip_info.mtu + vpninfo->pkt_trailer;
		struct pkt *pkt;

		if (!vpninfo->dtls_pkt) {
			vpninfo->dtls_pkt = malloc(sizeof(struct pkt) + len);
			if (!vpninfo->dtls_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}
		pkt = vpninfo->dtls_pkt;
		len = recv(vpninfo->dtls_fd, &pkt->esp, len + sizeof(pkt->esp), 0);
		if (len <= 0)
			break;

		vpn_progress(vpninfo, PRG_TRACE, _("Received ESP packet of %d bytes\n"),
			     len);
		work_done = 1;

		if (len <= sizeof(pkt->esp) + 12)
			continue;

		len -= sizeof(pkt->esp) + 12;
		pkt->len = len;

		if (decrypt_esp_packet(vpninfo, pkt))
			continue;

		if (pkt->data[len - 1] != 0x04 && pkt->data[len - 1] != 0x29) {
			/* 0x05 is LZO compressed. */
			vpn_progress(vpninfo, PRG_ERR,
				     _("Received ESP packet with unrecognised payload type %02x\n"),
				     pkt->data[len-1]);
			continue;
		}

		if (len <= 2 + pkt->data[len - 2]) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid padding length %02x in ESP\n"),
				     pkt->data[len - 2]);
			continue;
		}
		/* XXX: Actually check the padding bytes too. */
		pkt->len = len - 2 - pkt->data[len - 2];

		if (pkt->len  == 1 && pkt->data[0] == 0) {
			if (vpninfo->dtls_state == DTLS_SLEEPING) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("ESP session established with server\n"));
				vpninfo->dtls_state = DTLS_CONNECTING;
			}
			continue;
		}
		queue_packet(&vpninfo->incoming_queue, pkt);
		vpninfo->dtls_pkt = NULL;
	}

	if (vpninfo->dtls_state != DTLS_CONNECTED)
		return 0;

	unmonitor_write_fd(vpninfo, dtls);
	while (vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		int len;

		vpninfo->outgoing_queue = this->next;
		vpninfo->outgoing_qlen--;

		len = encrypt_esp_packet(vpninfo, this);
		if (len > 0) {
			ret = send(vpninfo->dtls_fd, &this->esp, len, 0);
			if (ret < 0) {
				/* Not that this is likely to happen with UDP, but... */
				if (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK) {
					monitor_write_fd(vpninfo, dtls);
					/* XXX: Keep the packet somewhere? */
					free(this);
					return work_done;
				} else {
					/* A real error in sending. Fall back to TCP? */
					vpn_progress(vpninfo, PRG_ERR,
						     _("Failed to send ESP packet: %s\n"),
						     strerror(errno));
				}
			} else
				vpn_progress(vpninfo, PRG_TRACE, _("Sent ESP packet of %d bytes\n"),
					     len);
		} else {
			/* XXX: Fall back to TCP transport? */
		}
		free(this);
		work_done = 1;
	}

	return work_done;
}

void esp_close(struct openconnect_info *vpninfo)
{
}

void esp_shutdown(struct openconnect_info *vpninfo)
{
}
