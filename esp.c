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
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "openconnect-internal.h"
#include "lzo.h"

int print_esp_keys(struct openconnect_info *vpninfo, const char *name, struct esp *esp)
{
	int i;
	const char *enctype, *mactype;
	char enckey[256], mackey[256];

	switch(vpninfo->esp_enc) {
	case 0x02:
		enctype = "AES-128-CBC (RFC3602)";
		break;
	case 0x05:
		enctype = "AES-256-CBC (RFC3602)";
		break;
	default:
		return -EINVAL;
	}
	switch(vpninfo->esp_hmac) {
	case 0x01:
		mactype = "HMAC-MD5-96 (RFC2403)";
		break;
	case 0x02:
		mactype = "HMAC-SHA-1-96 (RFC2404)";
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < vpninfo->enc_key_len; i++)
		sprintf(enckey + (2 * i), "%02x", esp->enc_key[i]);
	for (i = 0; i < vpninfo->hmac_key_len; i++)
		sprintf(mackey + (2 * i), "%02x", esp->hmac_key[i]);

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

int esp_send_probes(struct openconnect_info *vpninfo)
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
	if (pktlen >= 0)
		send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0);

	pkt->len = 1;
	pkt->data[0] = 0;
	pktlen = encrypt_esp_packet(vpninfo, pkt);
	if (pktlen >= 0)
		send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0);

	free(pkt);

	vpninfo->dtls_times.last_tx = time(&vpninfo->new_dtls_started);

	return 0;
};

static uint16_t csum(uint16_t *buf, int nwords)
{
	uint32_t sum = 0;
	for(sum=0; nwords>0; nwords--)
		sum += ntohs(*buf++);
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return htons((uint16_t)(~sum));
}

int esp_send_probes_gp(struct openconnect_info *vpninfo)
{
	/* The GlobalProtect VPN initiates and maintains the ESP connection
	 * using specially-crafted ICMP ("ping") packets.
	 *
	 * 1) These ping packets have a special magic payload. It must
	 *    include at least the 16 bytes below. The Windows client actually
	 *    sends this 56-byte version, but the remaining bytes don't
	 *    seem to matter:
	 *
	 *    "monitor\x00\x00pan ha 0123456789:;<=>? !\"#$%&\'()*+,-./\x10\x11\x12\x13\x14\x15\x16\x18";
	 *
	 * 2) The ping packets are addressed to the IP supplied in the
	 *    config XML as as <gw-address>. In most cases, this is the
	 *    same as the *external* IP address of the VPN gateway
	 *    (vpninfo->ip_info.gateway_addr), but in some cases it is a
	 *    separate address.
	 *
	 *    Don't blame me. I didn't design this.
	 */
	static char magic[16] = "monitor\x00\x00pan ha ";

	int pktlen, seq;
	struct pkt *pkt = malloc(sizeof(*pkt) + sizeof(struct ip) + ICMP_MINLEN + sizeof(magic) + vpninfo->pkt_trailer);
	struct ip *iph = (void *)pkt->data;
	struct icmp *icmph = (void *)(pkt->data + sizeof(*iph));
	char *pmagic = (void *)(pkt->data + sizeof(*iph) + ICMP_MINLEN);
	if (!pkt)
		return -ENOMEM;

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

	for (seq=1; seq <= (vpninfo->dtls_state==DTLS_CONNECTED ? 1 : 3); seq++) {
		memset(pkt, 0, sizeof(*pkt) + sizeof(*iph) + ICMP_MINLEN + sizeof(magic));
		pkt->len = sizeof(struct ip) + ICMP_MINLEN + sizeof(magic);

		/* IP Header */
		iph->ip_hl = 5;
		iph->ip_v = 4;
		iph->ip_len = htons(sizeof(*iph) + ICMP_MINLEN + sizeof(magic));
		iph->ip_id = htons(0x4747); /* what the Windows client uses */
		iph->ip_off = htons(IP_DF); /* don't fragment, frag offset = 0 */
		iph->ip_ttl = 64; /* hops */
		iph->ip_p = 1; /* ICMP */
		iph->ip_src.s_addr = inet_addr(vpninfo->ip_info.addr);
		iph->ip_dst.s_addr = vpninfo->esp_magic;
		iph->ip_sum = csum((uint16_t *)iph, sizeof(*iph)/2);

		/* ICMP echo request */
		icmph->icmp_type = ICMP_ECHO;
		icmph->icmp_hun.ih_idseq.icd_id = htons(0x4747);
		icmph->icmp_hun.ih_idseq.icd_seq = htons(seq);
		memcpy(pmagic, magic, sizeof(magic)); /* required to get gateway to respond */
		icmph->icmp_cksum = csum((uint16_t *)icmph, (ICMP_MINLEN+sizeof(magic))/2);

		pktlen = encrypt_esp_packet(vpninfo, pkt);
		if (pktlen >= 0)
			send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0);
	}

	free(pkt);

	vpninfo->dtls_times.last_tx = time(&vpninfo->new_dtls_started);

	return 0;
}

int esp_catch_probe(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	return (pkt->len == 1 && pkt->data[0] == 0);
}

int esp_catch_probe_gp(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	return ( pkt->len >= 21
		 && pkt->data[9]==1 /* IPv4 protocol field == ICMP */
		 && *((in_addr_t *)(pkt->data + 12)) == vpninfo->esp_magic /* source == magic address */
		 && pkt->data[20]==0 /* ICMP reply */ );
}

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

	vpn_progress(vpninfo, PRG_DEBUG, _("Send ESP probes\n"));
	if (vpninfo->proto->udp_send_probes)
		vpninfo->proto->udp_send_probes(vpninfo);

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
		if (when <= 0 || vpninfo->dtls_need_reconnect) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Send ESP probes\n"));
			if (vpninfo->proto->udp_send_probes)
				vpninfo->proto->udp_send_probes(vpninfo);
			when = vpninfo->dtls_attempt_period;
		}
		if (*timeout > when * 1000)
			*timeout = when * 1000;
	}
	if (vpninfo->dtls_fd == -1)
		return 0;

	while (1) {
		int len = vpninfo->ip_info.mtu + vpninfo->pkt_trailer;
		int i;
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
		pkt->len = len - 2 - pkt->data[len - 2];
		for (i = 0 ; i < pkt->data[len - 2]; i++) {
			if (pkt->data[pkt->len + i] != i + 1)
				break; /* We can't just 'continue' here because it
					* would only break out of this 'for' loop */
		}
		if (i != pkt->data[len - 2]) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid padding bytes in ESP\n"));
			continue; /* We can here, though */
		}
		vpninfo->dtls_times.last_rx = time(NULL);

		if (vpninfo->proto->udp_catch_probe) {
			if (vpninfo->proto->udp_catch_probe(vpninfo, pkt)) {
				if (vpninfo->dtls_state == DTLS_SLEEPING) {
					vpn_progress(vpninfo, PRG_INFO,
						     _("ESP session established with server\n"));
					queue_esp_control(vpninfo, 1);
					vpninfo->dtls_state = DTLS_CONNECTING;
				}
				continue;
			}
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
		if (vpninfo->proto->udp_send_probes)
			vpninfo->proto->udp_send_probes(vpninfo);
		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send ESP probes for DPD\n"));
		if (vpninfo->proto->udp_send_probes)
			vpninfo->proto->udp_send_probes(vpninfo);
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
		vpninfo->dtls_fd = -1;
	}
	if (vpninfo->dtls_state > DTLS_DISABLED)
		vpninfo->dtls_state = DTLS_SLEEPING;
}

void esp_close_secret(struct openconnect_info *vpninfo)
{
	esp_close(vpninfo);
	vpninfo->dtls_state = DTLS_NOSECRET;
}

void esp_shutdown(struct openconnect_info *vpninfo)
{
	destroy_esp_ciphers(&vpninfo->esp_in[0]);
	destroy_esp_ciphers(&vpninfo->esp_in[1]);
	destroy_esp_ciphers(&vpninfo->esp_out);
	esp_close(vpninfo);
}
