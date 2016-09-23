
/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2016 Intel Corporation.
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


#include <gnutls/dtls.h>
#include "gnutls.h"

#if GNUTLS_VERSION_NUMBER < 0x030200
# define GNUTLS_DTLS1_2 202
#endif
#if GNUTLS_VERSION_NUMBER < 0x030400
# define GNUTLS_CIPHER_CHACHA20_POLY1305 23
#endif

/* sets the DTLS MTU and returns the actual tunnel MTU */
unsigned dtls_set_mtu(struct openconnect_info *vpninfo, unsigned mtu)
{
	gnutls_dtls_set_mtu(vpninfo->dtls_ssl, mtu);
	return gnutls_dtls_get_data_mtu(vpninfo->dtls_ssl);
}

struct {
	const char *name;
	gnutls_protocol_t version;
	gnutls_cipher_algorithm_t cipher;
	gnutls_kx_algorithm_t kx;
	gnutls_mac_algorithm_t mac;
	const char *prio;
	const char *min_gnutls_version;
} gnutls_dtls_ciphers[] = {
	{ "AES128-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_KX_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:%COMPAT", "3.0.0" },
	{ "AES256-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_KX_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-256-CBC:+SHA1:+RSA:%COMPAT", "3.0.0" },
	{ "DES-CBC3-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_3DES_CBC, GNUTLS_KX_RSA, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+3DES-CBC:+SHA1:+RSA:%COMPAT", "3.0.0" },
	{ "OC-DTLS1_2-AES128-GCM", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_KX_RSA, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL", "3.2.7" },
	{ "OC-DTLS1_2-AES256-GCM", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_KX_RSA, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL", "3.2.7" },
	{ "OC2-DTLS1_2-CHACHA20-POLY1305", GNUTLS_DTLS1_2, GNUTLS_CIPHER_CHACHA20_POLY1305, GNUTLS_KX_PSK, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+CHACHA20-POLY1305:+AEAD:+PSK:%COMPAT:+SIGN-ALL", "3.4.8" },
	/* NB. We agreed that any new cipher suites probably shouldn't use
	 * Cisco's session resume hack (which ties us to a specific version
	 * of DTLS). Instead, we'll use GNUTLS_KX_PSK and let it negotiate
	 * the session properly. We might want to wait for
	 * draft-jay-tls-psk-identity-extension before we do that. */
};

#if GNUTLS_VERSION_NUMBER < 0x030009
void append_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	int i, first = 1;

	for (i = 0; i < sizeof(gnutls_dtls_ciphers) / sizeof(gnutls_dtls_ciphers[0]); i++) {
		if (gnutls_check_version(gnutls_dtls_ciphers[i].min_gnutls_version)) {
			buf_append(buf, "%s%s", first ? "" : ":",
				   gnutls_dtls_ciphers[i].name);
			first = 0;
		}
	}
#else
void append_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	/* only enable the ciphers that would have been negotiated in the TLS channel */
	unsigned i, j, first = 1;
	int ret;
	unsigned idx;
	gnutls_cipher_algorithm_t cipher;
	gnutls_mac_algorithm_t mac;
	gnutls_priority_t cache;
	uint32_t used = 0;

	buf_append(buf, "PSK-NEGOTIATE");
	first = 0;

	ret = gnutls_priority_init(&cache, vpninfo->gnutls_prio, NULL);
	if (ret < 0) {
		buf->error = -EIO;
		return;
	}

	for (j=0; ; j++) {
		ret = gnutls_priority_get_cipher_suite_index(cache, j, &idx);
		if (ret == GNUTLS_E_UNKNOWN_CIPHER_SUITE)
			continue;
		else if (ret < 0)
			break;

		if (gnutls_cipher_suite_info(idx, NULL, NULL, &cipher, &mac, NULL) != NULL) {
			for (i = 0; i < sizeof(gnutls_dtls_ciphers)/sizeof(gnutls_dtls_ciphers[0]); i++) {
				if (used & (1 << i))
					continue;
				if (gnutls_dtls_ciphers[i].mac == mac && gnutls_dtls_ciphers[i].cipher == cipher) {
					buf_append(buf, "%s%s", first ? "" : ":",
						   gnutls_dtls_ciphers[i].name);
					first = 0;
					used |= (1 << i);
					break;
				}
			}
		}
	}

	gnutls_priority_deinit(cache);
}
#endif

/* This enables a DTLS protocol negotiation. The new negotiation is as follows:
 *
 * If the client's X-DTLS-CipherSuite contains the "PSK-NEGOTIATE" keyword,
 * the server will reply with "X-DTLS-CipherSuite: PSK-NEGOTIATE" and will
 * enable DTLS-PSK negotiation on the DTLS channel. This allows the protocol
 * to use new DTLS versions, as well as new DTLS ciphersuites, as long as
 * they are also permitted by the system crypto policy in use.
 *
 * That change still requires to client to pretend it is resuming by setting
 * in the TLS ClientHello the session ID provided by the X-DTLS-Session-ID
 * header. That is, because there is no TLS extension we can use to set an
 * identifier in the client hello (draft-jay-tls-psk-identity-extension
 * could be used in the future). The session is not actually resumed.
 */
static int start_dtls_psk_handshake(struct openconnect_info *vpninfo, int dtls_fd)
{
	gnutls_session_t dtls_ssl;
	gnutls_datum_t key;
	struct oc_text_buf *prio;
	int err;

	prio = buf_alloc();
	buf_append(prio, "%s:-VERS-TLS-ALL:+VERS-DTLS-ALL:-KX-ALL:+PSK", vpninfo->gnutls_prio);
	if (buf_error(prio)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate DTLS priority string\n"));
		vpninfo->dtls_attempt_period = 0;
		return buf_free(prio);
	}


	err = gnutls_init(&dtls_ssl, GNUTLS_CLIENT|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialize DTLS: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}
	gnutls_session_set_ptr(dtls_ssl, (void *) vpninfo);

	err = gnutls_priority_set_direct(dtls_ssl, prio->data, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS priority: '%s': %s\n"),
			     prio->data, gnutls_strerror(err));
		goto fail;
	}

	gnutls_transport_set_ptr(dtls_ssl,
				 (gnutls_transport_ptr_t)(intptr_t)dtls_fd);

	/* set PSK credentials */
	err = gnutls_psk_allocate_client_credentials(&vpninfo->psk_cred);
	if (err < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate credentials: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}

	/* generate key */
	/* we should have used gnutls_prf_rfc5705() but since we don't use
	 * the RFC5705 context, the output is identical with gnutls_prf(). The
	 * latter is available in much earlier versions of gnutls. */
	err = gnutls_prf(vpninfo->https_sess, PSK_LABEL_SIZE, PSK_LABEL,
			 0, 0, 0, PSK_KEY_SIZE, (char*)vpninfo->dtls_secret);
	if (err < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate DTLS key: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}

	key.data = vpninfo->dtls_secret;
	key.size = PSK_KEY_SIZE;

	/* we set an arbitrary username here. We cannot take advantage of the
	 * username field to send our ID to the server, since the username in TLS-PSK
	 * is sent after the server-hello. */
	err = gnutls_psk_set_client_credentials(vpninfo->psk_cred, "psk", &key, 0);
	if (err < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS key: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}

	err = gnutls_credentials_set(dtls_ssl, GNUTLS_CRD_PSK, vpninfo->psk_cred);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS PSK credentials: %s\n"),
			     gnutls_strerror(err));
		goto fail;
	}

	buf_free(prio);
	vpninfo->dtls_ssl = dtls_ssl;
	return 0;
 fail:
	buf_free(prio);
	gnutls_deinit(dtls_ssl);
	gnutls_psk_free_client_credentials(vpninfo->psk_cred);
	vpninfo->psk_cred = NULL;
	vpninfo->dtls_attempt_period = 0;
	return -EINVAL;
}

int start_dtls_handshake(struct openconnect_info *vpninfo, int dtls_fd)
{
	gnutls_session_t dtls_ssl;
	gnutls_datum_t master_secret, session_id;
	int err;
	int cipher;

	if (strcmp(vpninfo->dtls_cipher, "PSK-NEGOTIATE") == 0)
		return start_dtls_psk_handshake(vpninfo, dtls_fd);

	for (cipher = 0; cipher < sizeof(gnutls_dtls_ciphers)/sizeof(gnutls_dtls_ciphers[0]); cipher++) {
		if (gnutls_check_version(gnutls_dtls_ciphers[cipher].min_gnutls_version) == NULL)
			continue;
		if (!strcmp(vpninfo->dtls_cipher, gnutls_dtls_ciphers[cipher].name))
			goto found_cipher;
	}
	vpn_progress(vpninfo, PRG_ERR, _("Unknown DTLS parameters for requested CipherSuite '%s'\n"),
		     vpninfo->dtls_cipher);
	vpninfo->dtls_attempt_period = 0;

	return -EINVAL;

 found_cipher:
	gnutls_init(&dtls_ssl, GNUTLS_CLIENT|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
	gnutls_session_set_ptr(dtls_ssl, (void *) vpninfo);

	err = gnutls_priority_set_direct(dtls_ssl,
					 gnutls_dtls_ciphers[cipher].prio,
					 NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS priority: %s\n"),
			     gnutls_strerror(err));
		gnutls_deinit(dtls_ssl);
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	gnutls_transport_set_ptr(dtls_ssl,
				 (gnutls_transport_ptr_t)(intptr_t)dtls_fd);

	gnutls_record_disable_padding(dtls_ssl);
	master_secret.data = vpninfo->dtls_secret;
	master_secret.size = sizeof(vpninfo->dtls_secret);
	session_id.data = vpninfo->dtls_session_id;
	session_id.size = sizeof(vpninfo->dtls_session_id);
	err = gnutls_session_set_premaster(dtls_ssl, GNUTLS_CLIENT, gnutls_dtls_ciphers[cipher].version,
					   gnutls_dtls_ciphers[cipher].kx, gnutls_dtls_ciphers[cipher].cipher,
					   gnutls_dtls_ciphers[cipher].mac, GNUTLS_COMP_NULL,
					   &master_secret, &session_id);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set DTLS session parameters: %s\n"),
			     gnutls_strerror(err));
		gnutls_deinit(dtls_ssl);
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	vpninfo->dtls_ssl = dtls_ssl;
	return 0;
}

int dtls_try_handshake(struct openconnect_info *vpninfo)
{
	int err = gnutls_handshake(vpninfo->dtls_ssl);
	char *str;

	if (!err) {
		if (strcmp(vpninfo->dtls_cipher, "PSK-NEGOTIATE") &&
		    !gnutls_session_is_resumed(vpninfo->dtls_ssl)) {
			/* Someone attempting to hijack the DTLS session?
			 * A real server would never allow a full session
			 * establishment instead of the agreed resume. */
			vpn_progress(vpninfo, PRG_ERR,
				     _("DTLS session resume failed; possible MITM attack. Disabling DTLS.\n"));
			dtls_close(vpninfo);
			vpninfo->dtls_attempt_period = 0;
			vpninfo->dtls_state = DTLS_DISABLED;
			return -EIO;
		}

#ifdef HAVE_GNUTLS_DTLS_SET_DATA_MTU
		/* Make sure GnuTLS's idea of the MTU is sufficient to take
		   a full VPN MTU (with 1-byte header) in a data record. */
		err = gnutls_dtls_set_data_mtu(vpninfo->dtls_ssl, vpninfo->ip_info.mtu + 1);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to set DTLS MTU: %s\n"),
				     gnutls_strerror(err));
			goto error;
		}
#else
		/* If we don't have gnutls_dtls_set_data_mtu() then make sure
		   we leave enough headroom by adding the worst-case overhead.
		   We only support AES128-CBC and DES-CBC3-SHA anyway, so
		   working out the worst case isn't hard. */
		gnutls_dtls_set_mtu(vpninfo->dtls_ssl,
				    vpninfo->ip_info.mtu + DTLS_OVERHEAD);
#endif

		vpninfo->dtls_state = DTLS_CONNECTED;
		str = get_gnutls_cipher(vpninfo->dtls_ssl);
		if (str) {
			const char *c;
			vpn_progress(vpninfo, PRG_INFO,
				     _("Established DTLS connection (using GnuTLS). Ciphersuite %s.\n"),
				     str);
			gnutls_free(str);
			c = openconnect_get_dtls_compression(vpninfo);
			if (c) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("DTLS connection compression using %s.\n"), c);
			}
		}

		vpninfo->dtls_times.last_rekey = vpninfo->dtls_times.last_rx = 
			vpninfo->dtls_times.last_tx = time(NULL);

		dtls_detect_mtu(vpninfo);
		/* XXX: For OpenSSL we explicitly prevent retransmits here. */
		return 0;
	}

	if (err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED) {
		if (time(NULL) < vpninfo->new_dtls_started + 12)
			return 0;
		vpn_progress(vpninfo, PRG_DEBUG, _("DTLS handshake timed out\n"));
	}

	vpn_progress(vpninfo, PRG_ERR, _("DTLS handshake failed: %s\n"),
		     gnutls_strerror(err));
	if (err == GNUTLS_E_PUSH_ERROR)
		vpn_progress(vpninfo, PRG_ERR,
			     _("(Is a firewall preventing you from sending UDP packets?)\n"));
 error:
	dtls_close(vpninfo);

	vpninfo->dtls_state = DTLS_SLEEPING;
	time(&vpninfo->new_dtls_started);
	return -EINVAL;
}

void dtls_shutdown(struct openconnect_info *vpninfo)
{
	dtls_close(vpninfo);
}

void dtls_ssl_free(struct openconnect_info *vpninfo)
{
	gnutls_deinit(vpninfo->dtls_ssl);

	if (vpninfo->psk_cred) {
		gnutls_psk_free_client_credentials(vpninfo->psk_cred);
		vpninfo->psk_cred = NULL;
	}
}
