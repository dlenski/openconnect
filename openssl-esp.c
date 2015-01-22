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

#include "openconnect-internal.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

void destroy_esp_ciphers(struct esp *esp)
{
	EVP_CIPHER_CTX_cleanup(&esp->cipher);
	HMAC_CTX_cleanup(&esp->hmac);
}

static int init_esp_ciphers(struct openconnect_info *vpninfo, struct esp *esp,
			    const EVP_MD *macalg, const EVP_CIPHER *encalg, int decrypt)
{
	int ret;

	EVP_CIPHER_CTX_init(&esp->cipher);
	if (decrypt)
		ret = EVP_DecryptInit_ex(&esp->cipher, encalg, NULL, esp->secrets, NULL);
	else
		ret = EVP_EncryptInit_ex(&esp->cipher, encalg, NULL, esp->secrets, NULL);

	if (!ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}
	EVP_CIPHER_CTX_set_padding(&esp->cipher, 0);
	
	HMAC_CTX_init(&esp->hmac);
	if (!HMAC_Init_ex(&esp->hmac, esp->secrets + EVP_CIPHER_key_length(encalg),
			  EVP_MD_size(macalg), macalg, NULL)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialize ESP HMAC\n"));

		openconnect_report_ssl_errors(vpninfo);
		destroy_esp_ciphers(esp);
	}
	esp->seq = 0;
	esp->seq_backlog = 0;
	return 0;
}

int setup_esp_keys(struct openconnect_info *vpninfo)
{
	const EVP_CIPHER *encalg;
	const EVP_MD *macalg;
	int ret;

	if (vpninfo->dtls_state == DTLS_DISABLED)
		return -EOPNOTSUPP;
	if (!vpninfo->dtls_addr)
		return -EINVAL;

	switch (vpninfo->esp_enc) {
	case 0x02:
		encalg = EVP_aes_128_cbc();
		break;
	case 0x05:
		encalg = EVP_aes_256_cbc();
		break;
	default:
		return -EINVAL;
	}

	switch (vpninfo->esp_hmac) {
	case 0x01:
		macalg = EVP_md5();
		break;
	case 0x02:
		macalg = EVP_sha1();
		break;
	default:
		return -EINVAL;
	}

	if (!RAND_bytes((void *)&vpninfo->esp_in.spi,
			sizeof(vpninfo->esp_in.secrets) + sizeof(vpninfo->esp_in.spi))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate random keys for ESP:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}

	ret = init_esp_ciphers(vpninfo, &vpninfo->esp_out, macalg, encalg, 0);
	if (ret)
		return ret;

	ret = init_esp_ciphers(vpninfo, &vpninfo->esp_in, macalg, encalg, 1);
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
	unsigned int hmac_len = sizeof(hmac_buf);
	int crypt_len = pkt->len;
	HMAC_CTX hmac_ctx;

	if (memcmp(pkt->esp.spi, vpninfo->esp_in.spi, 4)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid SPI %02x%02x%02x%02x\n"),
			     pkt->esp.spi[0], pkt->esp.spi[1], pkt->esp.spi[2], pkt->esp.spi[3]);
		return -EINVAL;
	}

	HMAC_CTX_copy(&hmac_ctx, &vpninfo->esp_in.hmac);
	HMAC_Update(&hmac_ctx, (void *)&pkt->esp, sizeof(pkt->esp) + pkt->len);
	HMAC_Final(&hmac_ctx, hmac_buf, &hmac_len);
	HMAC_CTX_cleanup(&hmac_ctx);

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


	if (!EVP_DecryptInit_ex(&vpninfo->esp_in.cipher, NULL, NULL, NULL,
				pkt->esp.iv)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set up decryption context for ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	if (!EVP_DecryptUpdate(&vpninfo->esp_in.cipher, pkt->data, &crypt_len,
			       pkt->data, pkt->len)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to decrypt ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	return 0;
}

int encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	int i, padlen;
	const int blksize = 16;
	unsigned int hmac_len = 20;
	int crypt_len;
	HMAC_CTX hmac_ctx;

	/* This gets much more fun if the IV is variable-length */
	memcpy(pkt->esp.spi, vpninfo->esp_out.spi, 4);
	pkt->esp.seq = htonl(vpninfo->esp_out.seq++);
	if (!RAND_pseudo_bytes((void *)&pkt->esp.iv, sizeof(pkt->esp.iv))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate random IV for ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}

	padlen = blksize - 1 - ((pkt->len + 1) % blksize);
	for (i=0; i<padlen; i++)
		pkt->data[pkt->len + i] = i + 1;
	pkt->data[pkt->len + padlen] = padlen;
	pkt->data[pkt->len + padlen + 1] = 0x04; /* Legacy IP */
	
	if (!EVP_EncryptInit_ex(&vpninfo->esp_out.cipher, NULL, NULL, NULL,
				pkt->esp.iv)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set up encryption context for ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	crypt_len = pkt->len + padlen + 2;
	if (!EVP_EncryptUpdate(&vpninfo->esp_out.cipher, pkt->data, &crypt_len,
			       pkt->data, crypt_len)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to encrypt ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	HMAC_CTX_copy(&hmac_ctx, &vpninfo->esp_out.hmac);
	HMAC_Update(&hmac_ctx, (void *)&pkt->esp, sizeof(pkt->esp) + pkt->len);
	HMAC_Final(&hmac_ctx, pkt->data + crypt_len, &hmac_len);
	HMAC_CTX_cleanup(&hmac_ctx);

	return sizeof(pkt->esp) + crypt_len + 12;
}
