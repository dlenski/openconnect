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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "openconnect-internal.h"

void destroy_esp_ciphers(struct esp *esp)
{
	if (esp->cipher) {
		gnutls_cipher_deinit(esp->cipher);
		esp->cipher = NULL;
	}
	if (esp->hmac) {
		gnutls_hmac_deinit(esp->hmac, NULL);
		esp->hmac = NULL;
	}
}

static int init_esp_ciphers(struct openconnect_info *vpninfo, struct esp *esp,
			    gnutls_mac_algorithm_t macalg, gnutls_cipher_algorithm_t encalg)
{
	gnutls_datum_t enc_key;
	int err;

	/* ∄ gnutls_cipher_get_key_size() */
	if (encalg == GNUTLS_CIPHER_AES_128_CBC)
		enc_key.size = 16;
	else if (encalg == GNUTLS_CIPHER_AES_256_CBC)
		enc_key.size = 32;
	else
		return -EINVAL;
	
	enc_key.data = esp->secrets;

	err = gnutls_cipher_init(&esp->cipher, encalg, &enc_key, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	err = gnutls_hmac_init(&esp->hmac, macalg,
			       esp->secrets + enc_key.size,
			       gnutls_hmac_get_len(macalg));
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialize ESP HMAC: %s\n"),
			     gnutls_strerror(err));
		destroy_esp_ciphers(esp);
	}
	esp->seq = 0;
	esp->seq_backlog = 0;
	return 0;
}

int setup_esp_keys(struct openconnect_info *vpninfo)
{
	gnutls_mac_algorithm_t macalg;
	gnutls_cipher_algorithm_t encalg;
	int ret;

	if (vpninfo->dtls_state == DTLS_DISABLED)
		return -EOPNOTSUPP;
	if (!vpninfo->dtls_addr)
		return -EINVAL;

	switch (vpninfo->esp_enc) {
	case 0x02:
		encalg = GNUTLS_CIPHER_AES_128_CBC;
		break;
	case 0x05:
		encalg = GNUTLS_CIPHER_AES_256_CBC;
		break;
	default:
		return -EINVAL;
	}

	switch (vpninfo->esp_hmac) {
	case 0x01:
		macalg = GNUTLS_MAC_MD5;
		break;
	case 0x02:
		macalg = GNUTLS_MAC_SHA1;
		break;
	default:
		return -EINVAL;
	}

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, &vpninfo->esp_in.spi,
			 sizeof(vpninfo->esp_in.secrets) + sizeof(vpninfo->esp_in.spi));
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate random keys for ESP: %s\n"),
			     gnutls_strerror(ret));
		return -EIO;
	}

	ret = init_esp_ciphers(vpninfo, &vpninfo->esp_out, macalg, encalg);
	if (ret)
		return ret;

	ret = init_esp_ciphers(vpninfo, &vpninfo->esp_in, macalg, encalg);
	if (ret) {
		destroy_esp_ciphers(&vpninfo->esp_out);
		return ret;
	}

	vpninfo->dtls_state = DTLS_SECRET;
	vpninfo->pkt_trailer = 16 + 20; /* 16 for pad, 20 for HMAC (of which we use 16) */
	return 0;
}

/* pkt->len shall be the *payload* length. Omitting the header and the 12-byte HMAC */
int decrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	unsigned char hmac_buf[20];
	int err;

	if (memcmp(pkt->esp.spi, vpninfo->esp_in.spi, 4)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid SPI %02x%02x%02x%02x\n"),
			     pkt->esp.spi[0], pkt->esp.spi[1], pkt->esp.spi[2], pkt->esp.spi[3]);
		return -EINVAL;
	}

	gnutls_hmac(vpninfo->esp_in.hmac, &pkt->esp, sizeof(pkt->esp) + pkt->len);
	gnutls_hmac_output(vpninfo->esp_in.hmac, hmac_buf);
	if (memcmp(hmac_buf, pkt->data + pkt->len, 12)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid HMAC\n"));
		return -EINVAL;
	}

	/* Why in $DEITY's name would you ever *not* set this? Perhaps we
	 * should do th check anyway, but only warn instead of discarding
	 * the packet? */
	if (vpninfo->esp_replay_protect &&
	    verify_packet_seqno(vpninfo, &vpninfo->esp_in, ntohl(pkt->esp.seq)))
		return -EINVAL;

	gnutls_cipher_set_iv(vpninfo->esp_in.cipher, pkt->esp.iv, sizeof(pkt->esp.iv));

	err = gnutls_cipher_decrypt(vpninfo->esp_in.cipher,
				    pkt->data, pkt->len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Decrypting ESP packet failed: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}

	return 0;
}

int encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	int i, padlen;
	const int blksize = 16;
	int err;

	/* This gets much more fun if the IV is variable-length */
	memcpy(pkt->esp.spi, vpninfo->esp_out.spi, 4);
	pkt->esp.seq = htonl(vpninfo->esp_out.seq++);
	err = gnutls_rnd(GNUTLS_RND_NONCE, pkt->esp.iv, sizeof(pkt->esp.iv));
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate ESP packet IV: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	padlen = blksize - 1 - ((pkt->len + 1) % blksize);
	for (i=0; i<padlen; i++)
		pkt->data[pkt->len + i] = i + 1;
	pkt->data[pkt->len + padlen] = padlen;
	pkt->data[pkt->len + padlen + 1] = 0x04; /* Legacy IP */
	
	gnutls_cipher_set_iv(vpninfo->esp_out.cipher, pkt->esp.iv, sizeof(pkt->esp.iv));
	err = gnutls_cipher_encrypt(vpninfo->esp_out.cipher, pkt->data, pkt->len + padlen + 2);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to encrypt ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	err = gnutls_hmac(vpninfo->esp_out.hmac, &pkt->esp, sizeof(pkt->esp) + pkt->len + padlen + 2);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to calculate HMAC for ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	gnutls_hmac_output(vpninfo->esp_out.hmac, pkt->data + pkt->len + padlen + 2);
	return sizeof(pkt->esp) + pkt->len + padlen + 2 + 12;
}
