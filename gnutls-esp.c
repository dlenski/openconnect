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

	destroy_esp_ciphers(esp);

	enc_key.size = gnutls_cipher_get_key_size(encalg);
	enc_key.data = esp->enc_key;

	err = gnutls_cipher_init(&esp->cipher, encalg, &enc_key, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	err = gnutls_hmac_init(&esp->hmac, macalg,
			       esp->hmac_key,
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

int setup_esp_keys(struct openconnect_info *vpninfo, int new_keys)
{
	struct esp *esp_in;
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

	if (new_keys) {
		vpninfo->old_esp_maxseq = vpninfo->esp_in[vpninfo->current_esp_in].seq + 32;
		vpninfo->current_esp_in ^= 1;
	}

	esp_in = &vpninfo->esp_in[vpninfo->current_esp_in];

	if (new_keys) {
		if ((ret = gnutls_rnd(GNUTLS_RND_NONCE, &esp_in->spi, sizeof(esp_in->spi))) ||
		    (ret = gnutls_rnd(GNUTLS_RND_RANDOM, &esp_in->enc_key, vpninfo->enc_key_len)) ||
		    (ret = gnutls_rnd(GNUTLS_RND_RANDOM, &esp_in->hmac_key, vpninfo->hmac_key_len)) ) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to generate random keys for ESP: %s\n"),
				     gnutls_strerror(ret));
			return -EIO;
		}
	}

	ret = init_esp_ciphers(vpninfo, &vpninfo->esp_out, macalg, encalg);
	if (ret)
		return ret;

	ret = init_esp_ciphers(vpninfo, esp_in, macalg, encalg);
	if (ret) {
		destroy_esp_ciphers(&vpninfo->esp_out);
		return ret;
	}

	if (vpninfo->dtls_state == DTLS_NOSECRET)
		vpninfo->dtls_state = DTLS_SECRET;
	vpninfo->pkt_trailer = 16 + 20; /* 16 for pad, 20 for HMAC (of which we use 16) */
	return 0;
}

/* pkt->len shall be the *payload* length. Omitting the header and the 12-byte HMAC */
int decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt)
{
	unsigned char hmac_buf[20];
	int err;

	err = gnutls_hmac(esp->hmac, &pkt->esp, sizeof(pkt->esp) + pkt->len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to calculate HMAC for ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	gnutls_hmac_output(esp->hmac, hmac_buf);
	if (memcmp(hmac_buf, pkt->data + pkt->len, 12)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid HMAC\n"));
		return -EINVAL;
	}

	if (verify_packet_seqno(vpninfo, esp, ntohl(pkt->esp.seq)))
		return -EINVAL;

	gnutls_cipher_set_iv(esp->cipher, pkt->esp.iv, sizeof(pkt->esp.iv));

	err = gnutls_cipher_decrypt(esp->cipher, pkt->data, pkt->len);
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
	pkt->esp.spi = vpninfo->esp_out.spi;
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
