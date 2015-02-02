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
#include "lzo.h"

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
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Accepting expected ESP packet with seq %u\n"),
			     seq);
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
		     name, (unsigned)ntohl(esp->spi));
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

	if (vpninfo->dtls_fd == -1) {
		int fd = udp_connect(vpninfo);
		if (fd < 0)
			return fd;

		/* We are not connected until we get an ESP packet back */
		vpninfo->dtls_state = DTLS_SLEEPING;
		vpninfo->dtls_fd = fd;
		monitor_fd_new(vpninfo, dtls);
		monitor_read_fd(vpninfo, dtls);
		monitor_except_fd(vpninfo, dtls);
	}

	pkt = malloc(sizeof(*pkt) + 1 + vpninfo->pkt_trailer);
	if (!pkt)
		return -ENOMEM;

	pkt->len = 1;
	pkt->data[0] = 0;
	pktlen = encrypt_esp_packet(vpninfo, pkt);
	send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0);

	pkt->len = 1;
	pkt->data[0] = 0;
	pktlen = encrypt_esp_packet(vpninfo, pkt);
	send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0);

	free(pkt);

	vpninfo->dtls_times.last_tx = time(&vpninfo->new_dtls_started);

	return 0;
};

int esp_setup(struct openconnect_info *vpninfo, int dtls_attempt_period)
{
	if (vpninfo->dtls_state == DTLS_DISABLED ||
	    vpninfo->dtls_state == DTLS_NOSECRET)
		return -EINVAL;

	if (vpninfo->esp_ssl_fallback)
		vpninfo->dtls_times.dpd = vpninfo->esp_ssl_fallback;
	else
		vpninfo->dtls_times.dpd = dtls_attempt_period;

	vpninfo->dtls_attempt_period = dtls_attempt_period;

	print_esp_keys(vpninfo, _("incoming"), &vpninfo->esp_in[vpninfo->current_esp_in]);
	print_esp_keys(vpninfo, _("outgoing"), &vpninfo->esp_out);

	esp_send_probes(vpninfo);

	return 0;
}

int esp_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	struct esp *esp = &vpninfo->esp_in[vpninfo->current_esp_in];
	struct esp *old_esp = &vpninfo->esp_in[vpninfo->current_esp_in ^ 1];
	struct pkt *this;
	int work_done = 0;
	int ret;

	if (vpninfo->dtls_state == DTLS_SLEEPING) {
		int when = vpninfo->new_dtls_started + vpninfo->dtls_attempt_period - time(NULL);
		if (when <= 0) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Send ESP probes\n"));
			esp_send_probes(vpninfo);
			when = vpninfo->dtls_attempt_period;
		}
		if (*timeout > when * 1000)
			*timeout = when * 1000;
	}
	if (vpninfo->dtls_fd == -1)
		return 0;

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
		len = recv(vpninfo->dtls_fd, (void *)&pkt->esp, len + sizeof(pkt->esp), 0);
		if (len <= 0)
			break;

		vpn_progress(vpninfo, PRG_TRACE, _("Received ESP packet of %d bytes\n"),
			     len);
		work_done = 1;

		if (len <= sizeof(pkt->esp) + 12)
			continue;

		len -= sizeof(pkt->esp) + 12;
		pkt->len = len;

		if (pkt->esp.spi == esp->spi) {
			if (decrypt_esp_packet(vpninfo, esp, pkt))
				continue;
		} else if (pkt->esp.spi == old_esp->spi &&
			   ntohl(pkt->esp.seq) + esp->seq < vpninfo->old_esp_maxseq) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Consider SPI 0x%x, seq %u against outgoing ESP setup\n"),
				     (unsigned)ntohl(old_esp->spi), (unsigned)ntohl(pkt->esp.seq));
			if (decrypt_esp_packet(vpninfo, old_esp, pkt))
				continue;
		} else {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received ESP packet with invalid SPI 0x%08x\n"),
				     (unsigned)ntohl(pkt->esp.spi));
			continue;
		}

		if (pkt->data[len - 1] != 0x04 && pkt->data[len - 1] != 0x29 &&
		    pkt->data[len - 1] != 0x05) {
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
		vpninfo->dtls_times.last_rx = time(NULL);

		if (pkt->len  == 1 && pkt->data[0] == 0) {
			if (vpninfo->dtls_state == DTLS_SLEEPING) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("ESP session established with server\n"));
				queue_esp_control(vpninfo, 1);
				vpninfo->dtls_state = DTLS_CONNECTING;
			}
			continue;
		}
		if (pkt->data[len - 1] == 0x05) {
			struct pkt *newpkt = malloc(sizeof(*pkt) + vpninfo->ip_info.mtu + vpninfo->pkt_trailer);
			int newlen = vpninfo->ip_info.mtu;
			if (!newpkt) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to allocate memory to decrypt ESP packet\n"));
				continue;
			}
			if (av_lzo1x_decode(newpkt->data, &newlen,
					    pkt->data, &pkt->len) || pkt->len) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("LZO decompression of ESP packet failed\n"));
				free(newpkt);
				continue;
			}
			newpkt->len = vpninfo->ip_info.mtu - newlen;
			vpn_progress(vpninfo, PRG_TRACE,
				     _("LZO decompressed %d bytes into %d\n"),
				     len - 2 - pkt->data[len-2], newpkt->len);
			queue_packet(&vpninfo->incoming_queue, newpkt);
		} else {
			queue_packet(&vpninfo->incoming_queue, pkt);
			vpninfo->dtls_pkt = NULL;
		}
	}

	if (vpninfo->dtls_state != DTLS_CONNECTED)
		return 0;

	switch (keepalive_action(&vpninfo->dtls_times, timeout)) {
	case KA_REKEY:
		vpn_progress(vpninfo, PRG_ERR, _("Rekey not implemented for ESP\n"));
		break;

	case KA_DPD_DEAD:
		vpn_progress(vpninfo, PRG_ERR, _("ESP detected dead peer\n"));
		queue_esp_control(vpninfo, 0);
		esp_close(vpninfo);
		esp_send_probes(vpninfo);
		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send ESP probes for DPD\n"));
		esp_send_probes(vpninfo);
		work_done = 1;
		break;

	case KA_KEEPALIVE:
		vpn_progress(vpninfo, PRG_ERR, _("Keepalive not implemented for ESP\n"));
		break;

	case KA_NONE:
		break;
	}
	unmonitor_write_fd(vpninfo, dtls);
	while ((this = dequeue_packet(&vpninfo->outgoing_queue))) {
		int len;

		len = encrypt_esp_packet(vpninfo, this);
		if (len > 0) {
			ret = send(vpninfo->dtls_fd, (void *)&this->esp, len, 0);
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
			} else {
				vpninfo->dtls_times.last_tx = time(NULL);

				vpn_progress(vpninfo, PRG_TRACE, _("Sent ESP packet of %d bytes\n"),
					     len);
			}
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
	/* We close and reopen the socket in case we roamed and our
	   local IP address has changed. */
	if (vpninfo->dtls_fd != -1) {
		closesocket(vpninfo->dtls_fd);
		unmonitor_read_fd(vpninfo, dtls);
		unmonitor_write_fd(vpninfo, dtls);
		unmonitor_except_fd(vpninfo, dtls);
	}
	vpninfo->dtls_state = DTLS_SLEEPING;
}

void esp_shutdown(struct openconnect_info *vpninfo)
{
	destroy_esp_ciphers(&vpninfo->esp_in[0]);
	destroy_esp_ciphers(&vpninfo->esp_in[1]);
	destroy_esp_ciphers(&vpninfo->esp_out);
	esp_close(vpninfo);
}
