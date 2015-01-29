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

#include "openconnect-internal.h"

#ifdef HAVE_DTLS

#if 0
/*
 * Useful for catching test cases, where we want everything to be
 * reproducible.  *NEVER* do this in the wild.
 */
time_t time(time_t *t)
{
	time_t x = 0x3ab2d948;
	if (t)
		*t = x;
	return x;
}

int RAND_pseudo_bytes(char *buf, int len)
{
	memset(buf, 0x5a, len);
	printf("FAKE PSEUDO RANDOM!\n");
	return 1;

}
int RAND_bytes(char *buf, int len)
{
	static int foo = 0x5b;
	printf("FAKE RANDOM!\n");
	memset(buf, foo, len);
	return 1;
}
#endif

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

#if defined(DTLS_OPENSSL)
#define DTLS_SEND SSL_write
#define DTLS_RECV SSL_read
#define DTLS_FREE SSL_free

#ifdef HAVE_DTLS1_STOP_TIMER
/* OpenSSL doesn't deliberately export this, but we need it to
   workaround a DTLS bug in versions < 1.0.0e */
extern void dtls1_stop_timer(SSL *);
#endif

static int start_dtls_handshake(struct openconnect_info *vpninfo, int dtls_fd)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	method_const SSL_METHOD *dtls_method;
	SSL_CIPHER *dtls_cipher;
	SSL *dtls_ssl;
	BIO *dtls_bio;

	if (!vpninfo->dtls_ctx) {
		dtls_method = DTLSv1_client_method();
		vpninfo->dtls_ctx = SSL_CTX_new(dtls_method);
		if (!vpninfo->dtls_ctx) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Initialise DTLSv1 CTX failed\n"));
			openconnect_report_ssl_errors(vpninfo);
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}

		/* If we don't readahead, then we do short reads and throw
		   away the tail of data packets. */
		SSL_CTX_set_read_ahead(vpninfo->dtls_ctx, 1);

		if (!SSL_CTX_set_cipher_list(vpninfo->dtls_ctx, vpninfo->dtls_cipher)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Set DTLS cipher list failed\n"));
			SSL_CTX_free(vpninfo->dtls_ctx);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
	}

	if (!vpninfo->dtls_session) {
		/* We're going to "resume" a session which never existed. Fake it... */
		vpninfo->dtls_session = SSL_SESSION_new();
		if (!vpninfo->dtls_session) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Initialise DTLSv1 session failed\n"));
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
		vpninfo->dtls_session->ssl_version = 0x0100; /* DTLS1_BAD_VER */
	}

	/* Do this every time; it may have changed due to a rekey */
	vpninfo->dtls_session->master_key_length = sizeof(vpninfo->dtls_secret);
	memcpy(vpninfo->dtls_session->master_key, vpninfo->dtls_secret,
	       sizeof(vpninfo->dtls_secret));

	vpninfo->dtls_session->session_id_length = sizeof(vpninfo->dtls_session_id);
	memcpy(vpninfo->dtls_session->session_id, vpninfo->dtls_session_id,
	       sizeof(vpninfo->dtls_session_id));

	dtls_ssl = SSL_new(vpninfo->dtls_ctx);
	SSL_set_connect_state(dtls_ssl);

	ciphers = SSL_get_ciphers(dtls_ssl);
	if (sk_SSL_CIPHER_num(ciphers) != 1) {
		vpn_progress(vpninfo, PRG_ERR, _("Not precisely one DTLS cipher\n"));
		SSL_CTX_free(vpninfo->dtls_ctx);
		SSL_free(dtls_ssl);
		SSL_SESSION_free(vpninfo->dtls_session);
		vpninfo->dtls_ctx = NULL;
		vpninfo->dtls_session = NULL;
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}
	dtls_cipher = sk_SSL_CIPHER_value(ciphers, 0);

	/* Set the appropriate cipher on our session to be resumed */
	vpninfo->dtls_session->cipher = dtls_cipher;
	vpninfo->dtls_session->cipher_id = dtls_cipher->id;

	/* Add the generated session to the SSL */
	if (!SSL_set_session(dtls_ssl, vpninfo->dtls_session)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("SSL_set_session() failed with old protocol version 0x%x\n"
			       "Are you using a version of OpenSSL older than 0.9.8m?\n"
			       "See http://rt.openssl.org/Ticket/Display.html?id=1751\n"
			       "Use the --no-dtls command line option to avoid this message\n"),
			     vpninfo->dtls_session->ssl_version);
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	dtls_bio = BIO_new_socket(dtls_fd, BIO_NOCLOSE);
	/* Set non-blocking */
	BIO_set_nbio(dtls_bio, 1);
	SSL_set_bio(dtls_ssl, dtls_bio, dtls_bio);

	SSL_set_options(dtls_ssl, SSL_OP_CISCO_ANYCONNECT);

	vpninfo->dtls_ssl = dtls_ssl;

	return 0;
}

static int dtls_try_handshake(struct openconnect_info *vpninfo)
{
	int ret = SSL_do_handshake(vpninfo->dtls_ssl);

	if (ret == 1) {
		vpninfo->dtls_state = DTLS_CONNECTED;
		vpn_progress(vpninfo, PRG_INFO,
			     _("Established DTLS connection (using OpenSSL). Ciphersuite %s.\n"),
			     vpninfo->dtls_cipher);

		vpninfo->dtls_times.last_rekey = vpninfo->dtls_times.last_rx = 
			vpninfo->dtls_times.last_tx = time(NULL);

		/* From about 8.4.1(11) onwards, the ASA seems to get
		   very unhappy if we resend ChangeCipherSpec messages
		   after the initial setup. This was "fixed" in OpenSSL
		   1.0.0e for RT#2505, but it's not clear if that was
		   the right fix. What happens if the original packet
		   *does* get lost? Surely we *wanted* the retransmits,
		   because without them the server will never be able
		   to decrypt anything we send?
		   Oh well, our retransmitted packets upset the server
		   because we don't get the Cisco-compatibility right
		   (this is one of the areas in which Cisco's DTLS differs
		   from the RFC4347 spec), and DPD should help us notice
		   if *nothing* is getting through. */
#if OPENSSL_VERSION_NUMBER >= 0x1000005fL
		/* OpenSSL 1.0.0e or above doesn't resend anyway; do nothing.
		   However, if we were *built* against 1.0.0e or newer, but at
		   runtime we find that we are being run against an older
		   version, warn about it. */
		if (SSLeay() < 0x1000005fL) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Your OpenSSL is older than the one you built against, so DTLS may fail!"));
		}
#elif defined(HAVE_DTLS1_STOP_TIMER)
		/*
		 * This works for any normal OpenSSL that supports
		 * Cisco DTLS compatibility (0.9.8m to 1.0.0d inclusive,
		 * and even later versions although it isn't needed there.
		 */
		dtls1_stop_timer(vpninfo->dtls_ssl);
#elif defined(BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT)
		/*
		 * Debian restricts visibility of dtls1_stop_timer()
		 * so do it manually. This version also works on all
		 * sane versions of OpenSSL:
		 */
		memset(&(vpninfo->dtls_ssl->d1->next_timeout), 0,
		       sizeof((vpninfo->dtls_ssl->d1->next_timeout)));
		vpninfo->dtls_ssl->d1->timeout_duration = 1;
		BIO_ctrl(SSL_get_rbio(vpninfo->dtls_ssl),
			 BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0,
			 &(vpninfo->dtls_ssl->d1->next_timeout));
#elif defined(BIO_CTRL_DGRAM_SET_TIMEOUT)
		/*
		 * OK, here it gets more fun... this shoul handle the case
		 * of older OpenSSL which has the Cisco DTLS compatibility
		 * backported, but *not* the fix for RT#1922.
		 */
		BIO_ctrl(SSL_get_rbio(vpninfo->dtls_ssl),
			 BIO_CTRL_DGRAM_SET_TIMEOUT, 0, NULL);
#else
		/*
		 * And if they don't have any of the above, they probably
		 * don't have RT#1829 fixed either, but that's OK because
		 * that's the "fix" that *introduces* the timeout we're
		 * trying to disable. So do nothing...
		 */
#endif
		return 0;
	}

	ret = SSL_get_error(vpninfo->dtls_ssl, ret);
	if (ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_WANT_READ) {
		static int badossl_bitched = 0;
		if (time(NULL) < vpninfo->new_dtls_started + 12)
			return 0;
		if (((OPENSSL_VERSION_NUMBER >= 0x100000b0L && OPENSSL_VERSION_NUMBER <= 0x100000c0L) || \
		     (OPENSSL_VERSION_NUMBER >= 0x10001040L && OPENSSL_VERSION_NUMBER <= 0x10001060L) || \
		     OPENSSL_VERSION_NUMBER == 0x10002000L) && !badossl_bitched) {
			badossl_bitched = 1;
			vpn_progress(vpninfo, PRG_ERR, _("DTLS handshake timed out\n"));
			vpn_progress(vpninfo, PRG_ERR, _("This is probably because your OpenSSL is broken\n"
				"See http://rt.openssl.org/Ticket/Display.html?id=2984\n"));
		} else {
			vpn_progress(vpninfo, PRG_DEBUG, _("DTLS handshake timed out\n"));
		}
	}

	vpn_progress(vpninfo, PRG_ERR, _("DTLS handshake failed: %d\n"), ret);
	openconnect_report_ssl_errors(vpninfo);

	dtls_close(vpninfo);

	vpninfo->dtls_state = DTLS_SLEEPING;
	time(&vpninfo->new_dtls_started);
	return -EINVAL;
}

void dtls_shutdown(struct openconnect_info *vpninfo)
{
	dtls_close(vpninfo);
	SSL_CTX_free(vpninfo->dtls_ctx);
	SSL_SESSION_free(vpninfo->dtls_session);
}

#elif defined(DTLS_GNUTLS)
#include <gnutls/dtls.h>
#include "gnutls.h"

struct {
	const char *name;
	gnutls_protocol_t version;
	gnutls_cipher_algorithm_t cipher;
	gnutls_mac_algorithm_t mac;
	const char *prio;
} gnutls_dtls_ciphers[] = {
	{ "AES128-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:%COMPAT" },
	{ "AES256-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-256-CBC:+SHA1:+RSA:%COMPAT" },
	{ "DES-CBC3-SHA", GNUTLS_DTLS0_9, GNUTLS_CIPHER_3DES_CBC, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+3DES-CBC:+SHA1:+RSA:%COMPAT" },
#if GNUTLS_VERSION_NUMBER >= 0x030207 /* if DTLS 1.2 is supported (and a bug in gnutls is solved) */
	{ "OC-DTLS1_2-AES128-GCM", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL" },
	{ "OC-DTLS1_2-AES256-GCM", GNUTLS_DTLS1_2, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_MAC_AEAD,
	  "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL" },
#endif
};

#define DTLS_SEND gnutls_record_send
#define DTLS_RECV gnutls_record_recv
#define DTLS_FREE gnutls_deinit
static int start_dtls_handshake(struct openconnect_info *vpninfo, int dtls_fd)
{
	gnutls_session_t dtls_ssl;
	gnutls_datum_t master_secret, session_id;
	int err;
	int cipher;

	for (cipher = 0; cipher < sizeof(gnutls_dtls_ciphers)/sizeof(gnutls_dtls_ciphers[0]); cipher++) {
		if (!strcmp(vpninfo->dtls_cipher, gnutls_dtls_ciphers[cipher].name))
			goto found_cipher;
	}
	vpn_progress(vpninfo, PRG_ERR, _("Unknown DTLS parameters for requested CipherSuite '%s'\n"),
		     vpninfo->dtls_cipher);
	vpninfo->dtls_attempt_period = 0;

	return -EINVAL;

 found_cipher:
	gnutls_init(&dtls_ssl, GNUTLS_CLIENT|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
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
					   GNUTLS_KX_RSA, gnutls_dtls_ciphers[cipher].cipher,
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

static int dtls_try_handshake(struct openconnect_info *vpninfo)
{
	int err = gnutls_handshake(vpninfo->dtls_ssl);
	char *str;

	if (!err) {
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
				    vpninfo->ip_info.mtu + 1 /* packet + header */
				    + 13 /* DTLS header */
				    + 20 /* biggest supported MAC (SHA1) */
				    + 16 /* biggest supported IV (AES-128) */
				    + 16 /* max padding */);
#endif

		vpninfo->dtls_state = DTLS_CONNECTED;
		str = get_gnutls_cipher(vpninfo->dtls_ssl);
		if (str) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Established DTLS connection (using GnuTLS). Ciphersuite %s.\n"),
				     str);
			gnutls_free(str);
		}

		vpninfo->dtls_times.last_rekey = vpninfo->dtls_times.last_rx = 
			vpninfo->dtls_times.last_tx = time(NULL);

		/* XXX: For OpenSSL we explicitly prevent retransmits here. */
		return 0;
	}

	if (err == GNUTLS_E_AGAIN) {
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
#endif

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
		DTLS_FREE(vpninfo->dtls_ssl);
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

#if defined(OPENCONNECT_GNUTLS) && defined(DTLS_OPENSSL)
	/* If we're using GnuTLS for authentication but OpenSSL for DTLS,
	   we'll need to initialise OpenSSL now... */
	SSL_library_init();
	ERR_clear_error();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif

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
			decompress_and_queue_packet(vpninfo, vpninfo->dtls_pkt->data,
						    len - 1);
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

#if defined(DTLS_OPENSSL)
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
#elif defined(DTLS_GNUTLS)
		ret = gnutls_record_send(vpninfo->dtls_ssl, &send_pkt->cstp.hdr[7], send_pkt->len + 1);
		if (ret <= 0) {
			if (ret != GNUTLS_E_AGAIN) {
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
#else /* !HAVE_DTLS */
#warning Your SSL library does not seem to support Cisco DTLS compatibility
#endif
