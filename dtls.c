/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
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

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "openconnect-internal.h"

#include <gnutls/dtls.h>

static unsigned char nybble(unsigned char n)
{
	if      (n >= '0' && n <= '9') return n - '0';
	else if (n >= 'A' && n <= 'F') return n - ('A' - 10);
	else if (n >= 'a' && n <= 'f') return n - ('a' - 10);
	return 0;
}

unsigned char unhex(const char *data)
{
	return (nybble(data[0]) << 4) | nybble(data[1]);
}

#ifdef HAVE_DTLS

#if 0
/*
 * Useful for catching test cases, where we want everything to be
 * reproducible.  *NEVER* do this in the wild.
 */
time_t time(time_t *t)
{
	time_t x = 0x3ab2d948;
	if (t) *t = x;
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

#if defined (DTLS_OPENSSL)
#define DTLS_SEND SSL_write
#define DTLS_RECV SSL_read

#ifdef HAVE_DTLS1_STOP_TIMER
/* OpenSSL doesn't deliberately export this, but we need it to
   workaround a DTLS bug in versions < 1.0.0e */
extern void dtls1_stop_timer (SSL *);
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

	vpninfo->new_dtls_ssl = dtls_ssl;

	return 0;
}

int dtls_try_handshake(struct openconnect_info *vpninfo)
{
	int ret = SSL_do_handshake(vpninfo->new_dtls_ssl);

	if (ret == 1) {
		vpn_progress(vpninfo, PRG_INFO, _("Established DTLS connection (using OpenSSL)\n"));

		if (vpninfo->dtls_ssl) {
			/* We are replacing an old connection */
			SSL_free(vpninfo->dtls_ssl);
			close(vpninfo->dtls_fd);
			FD_CLR(vpninfo->dtls_fd, &vpninfo->select_rfds);
			FD_CLR(vpninfo->dtls_fd, &vpninfo->select_wfds);
			FD_CLR(vpninfo->dtls_fd, &vpninfo->select_efds);
		}
		vpninfo->dtls_ssl = vpninfo->new_dtls_ssl;
		vpninfo->dtls_fd = vpninfo->new_dtls_fd;

		vpninfo->new_dtls_ssl = NULL;
		vpninfo->new_dtls_fd = -1;

		vpninfo->dtls_times.last_rx = vpninfo->dtls_times.last_tx = time(NULL);

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
#elif defined (HAVE_DTLS1_STOP_TIMER)
		/*
		 * This works for any normal OpenSSL that supports
		 * Cisco DTLS compatibility (0.9.8m to 1.0.0d inclusive,
		 * and even later versions although it isn't needed there.
		 */
		dtls1_stop_timer(vpninfo->dtls_ssl);
#elif defined (BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT)
		/*
		 * Debian restricts visibility of dtls1_stop_timer()
		 * so do it manually. This version also works on all
		 * sane versions of OpenSSL:
		 */
		memset (&(vpninfo->dtls_ssl->d1->next_timeout), 0,
			sizeof((vpninfo->dtls_ssl->d1->next_timeout)));
		vpninfo->dtls_ssl->d1->timeout_duration = 1;
		BIO_ctrl(SSL_get_rbio(vpninfo->dtls_ssl),
			 BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0,
			 &(vpninfo->dtls_ssl->d1->next_timeout));
#elif defined (BIO_CTRL_DGRAM_SET_TIMEOUT)
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

	ret = SSL_get_error(vpninfo->new_dtls_ssl, ret);
	if (ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_WANT_READ) {
		if (time(NULL) < vpninfo->new_dtls_started + 5)
			return 0;
		vpn_progress(vpninfo, PRG_TRACE, _("DTLS handshake timed out\n"));
	}

	vpn_progress(vpninfo, PRG_ERR, _("DTLS handshake failed: %d\n"), ret);
	openconnect_report_ssl_errors(vpninfo);

	/* Kill the new (failed) connection... */
	SSL_free(vpninfo->new_dtls_ssl);
	FD_CLR(vpninfo->new_dtls_fd, &vpninfo->select_rfds);
	FD_CLR(vpninfo->new_dtls_fd, &vpninfo->select_efds);
	close(vpninfo->new_dtls_fd);
	vpninfo->new_dtls_ssl = NULL;
	vpninfo->new_dtls_fd = -1;

	/* ... and kill the old one too. The only time there'll be a valid
	   existing session is when it was a rekey, and in that case it's
	   time for the old one to die. */
	if (vpninfo->dtls_ssl) {
		SSL_free(vpninfo->dtls_ssl);
		close(vpninfo->dtls_fd);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_rfds);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_wfds);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_efds);
		vpninfo->dtls_ssl = NULL;
		vpninfo->dtls_fd = -1;
	}

	time(&vpninfo->new_dtls_started);
	return -EINVAL;
}

#elif defined (DTLS_GNUTLS)
struct {
	const char *name;
	gnutls_cipher_algorithm_t cipher;
	gnutls_mac_algorithm_t mac;
	const char *prio;
} gnutls_dtls_ciphers[] = {
	{ "AES128-SHA", GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:%COMPAT:%DISABLE_SAFE_RENEGOTIATION" },
	{ "DES-CBC3-SHA", GNUTLS_CIPHER_3DES_CBC, GNUTLS_MAC_SHA1,
	  "NONE:+VERS-DTLS0.9:+COMP-NULL:+3DES-CBC:+SHA1:+RSA:%COMPAT:%DISABLE_SAFE_RENEGOTIATION" },
};

#define DTLS_SEND gnutls_record_send
#define DTLS_RECV gnutls_record_recv
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
	/* +1 for packet header, +13 for DTLS overhead */
	gnutls_dtls_set_mtu(dtls_ssl, vpninfo->mtu + 14);
	gnutls_transport_set_ptr(dtls_ssl,
				 (gnutls_transport_ptr_t)(long) dtls_fd);
	gnutls_record_disable_padding(dtls_ssl);
	master_secret.data = vpninfo->dtls_secret;
	master_secret.size = sizeof(vpninfo->dtls_secret);
	session_id.data = vpninfo->dtls_session_id;
	session_id.size = sizeof(vpninfo->dtls_session_id);
	err = gnutls_session_set_premaster(dtls_ssl, GNUTLS_CLIENT, GNUTLS_DTLS0_9,
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

	vpninfo->new_dtls_ssl = dtls_ssl;
	return 0;
}

int dtls_try_handshake(struct openconnect_info *vpninfo)
{
	int err = gnutls_handshake(vpninfo->new_dtls_ssl);

	if (!err) {
		vpn_progress(vpninfo, PRG_INFO, _("Established DTLS connection (using GnuTLS)\n"));

		if (vpninfo->dtls_ssl) {
			/* We are replacing an old connection */
			gnutls_deinit(vpninfo->dtls_ssl);
			close(vpninfo->dtls_fd);
			FD_CLR(vpninfo->dtls_fd, &vpninfo->select_rfds);
			FD_CLR(vpninfo->dtls_fd, &vpninfo->select_wfds);
			FD_CLR(vpninfo->dtls_fd, &vpninfo->select_efds);
		}
		vpninfo->dtls_ssl = vpninfo->new_dtls_ssl;
		vpninfo->dtls_fd = vpninfo->new_dtls_fd;

		vpninfo->new_dtls_ssl = NULL;
		vpninfo->new_dtls_fd = -1;

		vpninfo->dtls_times.last_rx = vpninfo->dtls_times.last_tx = time(NULL);

		/* XXX: For OpenSSL we explicitly prevent retransmits here. */
		return 0;
	}

	if (err == GNUTLS_E_AGAIN) {
		if (time(NULL) < vpninfo->new_dtls_started + 5)
			return 0;
		vpn_progress(vpninfo, PRG_TRACE, _("DTLS handshake timed out\n"));
	}

	vpn_progress(vpninfo, PRG_ERR, _("DTLS handshake failed: %s\n"),
		     gnutls_strerror(err));

	/* Kill the new (failed) connection... */
	gnutls_deinit(vpninfo->new_dtls_ssl);
	FD_CLR(vpninfo->new_dtls_fd, &vpninfo->select_rfds);
	FD_CLR(vpninfo->new_dtls_fd, &vpninfo->select_efds);
	close(vpninfo->new_dtls_fd);
	vpninfo->new_dtls_ssl = NULL;
	vpninfo->new_dtls_fd = -1;

	/* ... and kill the old one too. The only time there'll be a valid
	   existing session is when it was a rekey, and in that case it's
	   time for the old one to die. */
	if (vpninfo->dtls_ssl) {
		gnutls_deinit(vpninfo->dtls_ssl);
		close(vpninfo->dtls_fd);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_rfds);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_wfds);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_efds);
		vpninfo->dtls_ssl = NULL;
		vpninfo->dtls_fd = -1;
	}

	time(&vpninfo->new_dtls_started);
	return -EINVAL;
}
#endif

int connect_dtls_socket(struct openconnect_info *vpninfo)
{
	int dtls_fd, ret;

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

	dtls_fd = socket(vpninfo->peer_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (dtls_fd < 0) {
		perror(_("Open UDP socket for DTLS:"));
		return -EINVAL;
	}

	if (vpninfo->dtls_local_port) {
		struct sockaddr_storage dtls_bind_addr;
		int dtls_bind_addrlen;
		memset(&dtls_bind_addr, 0, sizeof(dtls_bind_addr));

		if (vpninfo->peer_addr->sa_family == AF_INET) {
			struct sockaddr_in *addr = (struct sockaddr_in *)&dtls_bind_addr;
			dtls_bind_addrlen = sizeof(*addr);
			addr->sin_family = AF_INET;
			addr->sin_addr.s_addr = INADDR_ANY;
			addr->sin_port = htons(vpninfo->dtls_local_port);
		} else if (vpninfo->peer_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&dtls_bind_addr;
			dtls_bind_addrlen = sizeof(*addr);
			addr->sin6_family = AF_INET6;
			addr->sin6_addr = in6addr_any;
			addr->sin6_port = htons(vpninfo->dtls_local_port);
		} else {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown protocol family %d. Cannot do DTLS\n"),
				     vpninfo->peer_addr->sa_family);
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}

		if (bind(dtls_fd, (struct sockaddr *)&dtls_bind_addr, dtls_bind_addrlen)) {
			perror(_("Bind UDP socket for DTLS"));
			return -EINVAL;
		}
	}

	if (connect(dtls_fd, vpninfo->dtls_addr, vpninfo->peer_addrlen)) {
		perror(_("UDP (DTLS) connect:\n"));
		close(dtls_fd);
		return -EINVAL;
	}

	fcntl(dtls_fd, F_SETFD, FD_CLOEXEC);
	fcntl(dtls_fd, F_SETFL, fcntl(dtls_fd, F_GETFL) | O_NONBLOCK);

	ret = start_dtls_handshake(vpninfo, dtls_fd);
	if (ret) {
		close(dtls_fd);
		return ret;
	}

	vpninfo->new_dtls_fd = dtls_fd;
	if (vpninfo->select_nfds <= dtls_fd)
		vpninfo->select_nfds = dtls_fd + 1;

	FD_SET(dtls_fd, &vpninfo->select_rfds);
	FD_SET(dtls_fd, &vpninfo->select_efds);

	time(&vpninfo->new_dtls_started);

	return dtls_try_handshake(vpninfo);
}

static int dtls_restart(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_ssl) {
#if defined (DTLS_OPENSSL)
		SSL_free(vpninfo->dtls_ssl);
#elif defined (DTLS_GNUTLS)
		gnutls_deinit(vpninfo->dtls_ssl);
#endif
		close(vpninfo->dtls_fd);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_rfds);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_wfds);
		FD_CLR(vpninfo->dtls_fd, &vpninfo->select_efds);
		vpninfo->dtls_ssl = NULL;
		vpninfo->dtls_fd = -1;
	}

	return connect_dtls_socket(vpninfo);
}


int setup_dtls(struct openconnect_info *vpninfo)
{
	struct vpn_option *dtls_opt = vpninfo->dtls_options;
	int dtls_port = 0;

#if defined (OPENCONNECT_GNUTLS) && defined (DTLS_OPENSSL)
	/* If we're using GnuTLS for authentication but OpenSSL for DTLS,
	   we'll need to initialise OpenSSL now... */
	SSL_library_init ();
	ERR_clear_error ();
	SSL_load_error_strings ();
	OpenSSL_add_all_algorithms ();
#endif

	while (dtls_opt) {
		vpn_progress(vpninfo, PRG_TRACE,
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

	vpninfo->dtls_addr = malloc(vpninfo->peer_addrlen);
	if (!vpninfo->dtls_addr) {
		vpninfo->dtls_attempt_period = 0;
		return -ENOMEM;
	}
	memcpy(vpninfo->dtls_addr, vpninfo->peer_addr, vpninfo->peer_addrlen);

	if (vpninfo->peer_addr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (void *)vpninfo->dtls_addr;
		sin->sin_port = htons(dtls_port);
	} else if (vpninfo->peer_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin = (void *)vpninfo->dtls_addr;
		sin->sin6_port = htons(dtls_port);
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown protocol family %d. Cannot do DTLS\n"),
			     vpninfo->peer_addr->sa_family);
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	if (connect_dtls_socket(vpninfo))
		return -EINVAL;

	vpn_progress(vpninfo, PRG_TRACE,
		     _("DTLS connected. DPD %d, Keepalive %d\n"),
		     vpninfo->dtls_times.dpd, vpninfo->dtls_times.keepalive);

	return 0;
}

static struct pkt *dtls_pkt;

int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int work_done = 0;
	char magic_pkt;

	while (1) {
		int len = vpninfo->mtu;
		unsigned char *buf;

		if (!dtls_pkt) {
			dtls_pkt = malloc(sizeof(struct pkt) + len);
			if (!dtls_pkt) {
				vpn_progress(vpninfo, PRG_ERR, "Allocation failed\n");
				break;
			}
		}

		buf = dtls_pkt->data - 1;
		len = DTLS_RECV(vpninfo->dtls_ssl, buf, len + 1);
		if (len <= 0)
			break;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received DTLS packet 0x%02x of %d bytes\n"),
			     buf[0], len);

		vpninfo->dtls_times.last_rx = time(NULL);

		switch(buf[0]) {
		case AC_PKT_DATA:
			dtls_pkt->len = len - 1;
			queue_packet(&vpninfo->incoming_queue, dtls_pkt);
			dtls_pkt = NULL;
			work_done = 1;
			break;

		case AC_PKT_DPD_OUT:
			vpn_progress(vpninfo, PRG_TRACE, _("Got DTLS DPD request\n"));

			/* FIXME: What if the packet doesn't get through? */
			magic_pkt = AC_PKT_DPD_RESP;
			if (DTLS_SEND(vpninfo->dtls_ssl, &magic_pkt, 1) != 1)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to send DPD response. Expect disconnect\n"));
			continue;

		case AC_PKT_DPD_RESP:
			vpn_progress(vpninfo, PRG_TRACE, _("Got DTLS DPD response\n"));
			break;

		case AC_PKT_KEEPALIVE:
			vpn_progress(vpninfo, PRG_TRACE, _("Got DTLS Keepalive\n"));
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
				vpninfo->quit_reason = "Unknown packet received";
				return 1;
			}

		}
	}

	switch (keepalive_action(&vpninfo->dtls_times, timeout)) {
	case KA_REKEY:
		vpn_progress(vpninfo, PRG_INFO, _("DTLS rekey due\n"));

		/* There ought to be a method of rekeying DTLS without tearing down
		   the CSTP session and restarting, but we don't (yet) know it */
		if (cstp_reconnect(vpninfo)) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "CSTP reconnect failed";
			return 1;
		}

		if (dtls_restart(vpninfo)) {
			vpn_progress(vpninfo, PRG_ERR, _("DTLS rekey failed\n"));
			return 1;
		}
		work_done = 1;
		break;


	case KA_DPD_DEAD:
		vpn_progress(vpninfo, PRG_ERR, _("DTLS Dead Peer Detection detected dead peer!\n"));
		/* Fall back to SSL, and start a new DTLS connection */
		dtls_restart(vpninfo);
		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_TRACE, _("Send DTLS DPD\n"));

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
		if (vpninfo->outgoing_queue)
			break;

		vpn_progress(vpninfo, PRG_TRACE, _("Send DTLS Keepalive\n"));

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
	while (vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		int ret;

		vpninfo->outgoing_queue = this->next;
		vpninfo->outgoing_qlen--;

		/* One byte of header */
		this->hdr[7] = AC_PKT_DATA;

#if defined(DTLS_OPENSSL)
		ret = SSL_write(vpninfo->dtls_ssl, &this->hdr[7], this->len + 1);
		if (ret <= 0) {
			ret = SSL_get_error(vpninfo->dtls_ssl, ret);

			/* If it's a real error, kill the DTLS connection and
			   requeue the packet to be sent over SSL */
			if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("DTLS got write error %d. Falling back to SSL\n"),
					     ret);
				openconnect_report_ssl_errors(vpninfo);
				dtls_restart(vpninfo);
				vpninfo->outgoing_queue = this;
				vpninfo->outgoing_qlen++;
			}
			return 1;
		}
#elif defined (DTLS_GNUTLS)
		ret = gnutls_record_send(vpninfo->dtls_ssl, &this->hdr[7], this->len + 1);
		if (ret <= 0) {
			if (ret != GNUTLS_E_AGAIN) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("DTLS got write error: %s. Falling back to SSL\n"),
					     gnutls_strerror(ret));
				dtls_restart(vpninfo);
				vpninfo->outgoing_queue = this;
				vpninfo->outgoing_qlen++;
			}
			return 1;
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
 int setup_dtls(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("Built against SSL library with no Cisco DTLS support\n"));
	return -EINVAL;
}
#endif

