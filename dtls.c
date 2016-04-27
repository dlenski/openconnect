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

/* In the very early days there were cases where this wasn't found in
 * the header files but it did still work somehow. I forget the details
 * now but I was definitely avoiding using the macro. Let's just define
 * it for ourselves instead.*/
#ifndef DTLS1_BAD_VER
#define DTLS1_BAD_VER 0x100
#endif

#ifdef HAVE_DTLS1_STOP_TIMER
/* OpenSSL doesn't deliberately export this, but we need it to
   workaround a DTLS bug in versions < 1.0.0e */
extern void dtls1_stop_timer(SSL *);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
/* Since OpenSSL 1.1, the SSL_SESSION structure is opaque and we can't
 * just fill it in directly. So we have to generate the OpenSSL ASN.1
 * representation of the SSL_SESSION, and use d2i_SSL_SESSION() to
 * create the SSL_SESSION from that. */

static void buf_append_INTEGER(struct oc_text_buf *buf, uint32_t datum)
{
	int l;

	/* We only handle positive integers up to INT_MAX */
	if (datum < 0x80)
		l = 1;
	else if (datum < 0x8000)
		l = 2;
	else if (datum < 0x800000)
		l = 3;
	else
		l = 4;

	if (buf_ensure_space(buf, 2 + l))
		return;

	buf->data[buf->pos++] = 0x02;
	buf->data[buf->pos++] = l;
	while (l--)
		buf->data[buf->pos++] = datum >> (l * 8);
}

static void buf_append_OCTET_STRING(struct oc_text_buf *buf, void *data, int len)
{
	/* We only (need to) cope with length < 0x80 for now */
	if (len >= 0x80) {
		buf->error = -EINVAL;
		return;
	}

	if (buf_ensure_space(buf, 2 + len))
		return;

	buf->data[buf->pos++] = 0x04;
	buf->data[buf->pos++] = len;
	memcpy(buf->data + buf->pos, data, len);
	buf->pos += len;
}

static SSL_SESSION *generate_dtls_session(struct openconnect_info *vpninfo,
					  int dtlsver, const SSL_CIPHER *cipher)
{
	struct oc_text_buf *buf = buf_alloc();
	SSL_SESSION *dtls_session;
	const unsigned char *asn;
	uint16_t cid;

	buf_append_bytes(buf, "\x30\x80", 2); // SEQUENCE, indeterminate length
	buf_append_INTEGER(buf, 1 /* SSL_SESSION_ASN1_VERSION */);
	buf_append_INTEGER(buf, dtlsver);
	store_be16(&cid, SSL_CIPHER_get_id(cipher) & 0xffff);
	buf_append_OCTET_STRING(buf, &cid, 2);
	buf_append_OCTET_STRING(buf, vpninfo->dtls_session_id,
				sizeof(vpninfo->dtls_session_id));
	buf_append_OCTET_STRING(buf, vpninfo->dtls_secret,
				sizeof(vpninfo->dtls_secret));
	/* If the length actually fits in one byte (which it should), do
	 * it that way.  Else, leave it indeterminate and add two
	 * end-of-contents octets to mark the end of the SEQUENCE. */
	if (!buf_error(buf) && buf->pos <= 0x80)
		buf->data[1] = buf->pos - 2;
	else
		buf_append_bytes(buf, "\0\0", 2);

	if (buf_error(buf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create SSL_SESSION ASN.1 for OpenSSL: %s\n"),
			     strerror(buf_error(buf)));
		buf_free(buf);
		return NULL;
	}

	asn = (void *)buf->data;
	dtls_session = d2i_SSL_SESSION(NULL, &asn, buf->pos);
	buf_free(buf);
	if (!dtls_session) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("OpenSSL failed to parse SSL_SESSION ASN.1\n"));
		openconnect_report_ssl_errors(vpninfo);
		return NULL;
	}

	return dtls_session;
}
#else /* OpenSSL before 1.1 */
static SSL_SESSION *generate_dtls_session(struct openconnect_info *vpninfo,
					  int dtlsver, const SSL_CIPHER *cipher)
{
	SSL_SESSION *dtls_session = SSL_SESSION_new();
	if (!dtls_session) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Initialise DTLSv1 session failed\n"));
		return NULL;
	}

	dtls_session->ssl_version = dtlsver;
	dtls_session->master_key_length = sizeof(vpninfo->dtls_secret);
	memcpy(dtls_session->master_key, vpninfo->dtls_secret,
	       sizeof(vpninfo->dtls_secret));

	dtls_session->session_id_length = sizeof(vpninfo->dtls_session_id);
	memcpy(dtls_session->session_id, vpninfo->dtls_session_id,
	       sizeof(vpninfo->dtls_session_id));

	dtls_session->cipher = (SSL_CIPHER *)cipher;
	dtls_session->cipher_id = cipher->id;

	return dtls_session;
}
#endif

static int start_dtls_handshake(struct openconnect_info *vpninfo, int dtls_fd)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	method_const SSL_METHOD *dtls_method;
	SSL_SESSION *dtls_session;
	SSL *dtls_ssl;
	BIO *dtls_bio;
	int dtlsver = DTLS1_BAD_VER;
	const char *cipher = vpninfo->dtls_cipher;

#ifdef HAVE_DTLS12
	if (!strcmp(cipher, "OC-DTLS1_2-AES128-GCM")) {
		dtlsver = DTLS1_2_VERSION;
		cipher = "AES128-GCM-SHA256";
	} else if (!strcmp(cipher, "OC-DTLS1_2-AES256-GCM")) {
		dtlsver = DTLS1_2_VERSION;
		cipher = "AES256-GCM-SHA384";
	}
#endif

	if (!vpninfo->dtls_ctx) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef HAVE_DTLS12
		if (dtlsver == DTLS1_2_VERSION)
			dtls_method = DTLSv1_2_client_method();
		else
#endif
			dtls_method = DTLSv1_client_method();
#else
		dtls_method = DTLS_client_method();
#endif
		vpninfo->dtls_ctx = SSL_CTX_new(dtls_method);
		if (!vpninfo->dtls_ctx) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Initialise DTLSv1 CTX failed\n"));
			openconnect_report_ssl_errors(vpninfo);
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		if (dtlsver == DTLS1_BAD_VER)
			SSL_CTX_set_options(vpninfo->dtls_ctx, SSL_OP_CISCO_ANYCONNECT);
#else
		if (!SSL_CTX_set_min_proto_version(vpninfo->dtls_ctx, dtlsver) ||
		    !SSL_CTX_set_max_proto_version(vpninfo->dtls_ctx, dtlsver)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Set DTLS CTX version failed\n"));
			openconnect_report_ssl_errors(vpninfo);
			SSL_CTX_free(vpninfo->dtls_ctx);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
#endif

		/* If we don't readahead, then we do short reads and throw
		   away the tail of data packets. */
		SSL_CTX_set_read_ahead(vpninfo->dtls_ctx, 1);

		if (!SSL_CTX_set_cipher_list(vpninfo->dtls_ctx, cipher)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Set DTLS cipher list failed\n"));
			SSL_CTX_free(vpninfo->dtls_ctx);
			vpninfo->dtls_ctx = NULL;
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
	}

	dtls_ssl = SSL_new(vpninfo->dtls_ctx);
	SSL_set_connect_state(dtls_ssl);

	ciphers = SSL_get_ciphers(dtls_ssl);
	if (sk_SSL_CIPHER_num(ciphers) != 1) {
		vpn_progress(vpninfo, PRG_ERR, _("Not precisely one DTLS cipher\n"));
		SSL_CTX_free(vpninfo->dtls_ctx);
		SSL_free(dtls_ssl);
		vpninfo->dtls_ctx = NULL;
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	/* We're going to "resume" a session which never existed. Fake it... */
	dtls_session = generate_dtls_session(vpninfo, dtlsver,
					     sk_SSL_CIPHER_value(ciphers, 0));
	if (!dtls_session) {
		SSL_CTX_free(vpninfo->dtls_ctx);
		SSL_free(dtls_ssl);
		vpninfo->dtls_ctx = NULL;
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	/* Add the generated session to the SSL */
	if (!SSL_set_session(dtls_ssl, dtls_session)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("SSL_set_session() failed with old protocol version 0x%x\n"
			       "Are you using a version of OpenSSL older than 0.9.8m?\n"
			       "See http://rt.openssl.org/Ticket/Display.html?id=1751\n"
			       "Use the --no-dtls command line option to avoid this message\n"),
			     DTLS1_BAD_VER);
		SSL_CTX_free(vpninfo->dtls_ctx);
		SSL_free(dtls_ssl);
		vpninfo->dtls_ctx = NULL;
		vpninfo->dtls_attempt_period = 0;
		SSL_SESSION_free(dtls_session);
		return -EINVAL;
	}
	/* We don't need our own refcount on it any more */
	SSL_SESSION_free(dtls_session);

	dtls_bio = BIO_new_socket(dtls_fd, BIO_NOCLOSE);
	/* Set non-blocking */
	BIO_set_nbio(dtls_bio, 1);
	SSL_set_bio(dtls_ssl, dtls_bio, dtls_bio);

	vpninfo->dtls_ssl = dtls_ssl;

	return 0;
}

static int dtls_try_handshake(struct openconnect_info *vpninfo)
{
	int ret = SSL_do_handshake(vpninfo->dtls_ssl);

	if (ret == 1) {
		const char *c;
		vpninfo->dtls_state = DTLS_CONNECTED;
		vpn_progress(vpninfo, PRG_INFO,
			     _("Established DTLS connection (using OpenSSL). Ciphersuite %s.\n"),
			     vpninfo->dtls_cipher);

		c = openconnect_get_dtls_compression(vpninfo);
		if (c) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("DTLS connection compression using %s.\n"), c);
		}

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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		/* OpenSSL 1.1.0 or above. Do nothing. The SSLeay() function
		   got renamed, and it's a pointless check in this case
		   anyway because there's *no* chance that we linked against
		   1.1.0 and are running against something older than 1.0.0e. */
#elif OPENSSL_VERSION_NUMBER >= 0x1000005fL
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
}

void append_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
#ifdef HAVE_DTLS12
	buf_append(buf, "OC-DTLS1_2-AES256-GCM:OC-DTLS1_2-AES128-GCM:AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA");
#else
	buf_append(buf, "AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA");
#endif
}

#elif defined(DTLS_GNUTLS)
#include <gnutls/dtls.h>
#include "gnutls.h"

#if GNUTLS_VERSION_NUMBER < 0x030200
# define GNUTLS_DTLS1_2 202
#endif
#if GNUTLS_VERSION_NUMBER < 0x030400
# define GNUTLS_CIPHER_CHACHA20_POLY1305 23
#endif

static void detect_mtu(struct openconnect_info *vpninfo);

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

		detect_mtu(vpninfo);
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

#if defined(DTLS_GNUTLS)

static int is_cancelled(struct openconnect_info *vpninfo)
{
	fd_set rd_set;
	int maxfd = 0;
	FD_ZERO(&rd_set);
	cmd_fd_set(vpninfo, &rd_set, &maxfd);

	if (is_cancel_pending(vpninfo, &rd_set)) {
		vpn_progress(vpninfo, PRG_ERR, _("SSL operation cancelled\n"));
		return -EINTR;
	}

	return 0;
}

static
void ms_sleep(unsigned ms)
{
	struct timespec tv;

	tv.tv_sec = ms/1000;
	tv.tv_nsec = (ms%1000) * 1000 * 1000;

	nanosleep(&tv, NULL);
}

#define MTU_ID_SIZE 4
#define MTU_FAIL_CONT { \
		cur--; \
		max = cur; \
		continue; \
	}

/* Performs a binary search to detect MTU.
 * @buf: is preallocated with MTU size
 * @id: a unique ID for our DPD exchange
 *
 * Returns: new MTU or 0
 */
static int detect_mtu_ipv4(struct openconnect_info *vpninfo, unsigned char *buf)
{
	int max, min, cur, ret;
	int max_tries = 100; /* maximum number of loops in bin search */
	int max_recv_loops = 40; /* 4 secs max */
	char id[MTU_ID_SIZE];

	cur = max = vpninfo->ip_info.mtu;
	min = vpninfo->ip_info.mtu/2;

	vpn_progress(vpninfo, PRG_DEBUG,
	     _("Initiating IPv4 MTU detection (min=%d, max=%d)\n"), min, max);

	while (max > min) {
		if (max_tries-- <= 0) {
			vpn_progress(vpninfo, PRG_ERR,
			     _("Too long time in MTU detect loop; bailing out.\n"));
			goto fail;
		}

		/* generate unique ID */
		if (gnutls_rnd(GNUTLS_RND_NONCE, id, sizeof(id)) < 0)
			goto fail;

		cur = (min + max + 1) / 2;
		buf[0] = AC_PKT_DPD_OUT;
		memcpy(&buf[1], id, sizeof(id));

		do {
			if (is_cancelled(vpninfo))
				goto fail;

			ret = DTLS_SEND(vpninfo->dtls_ssl, buf, cur+1);
			if (ret < 0)
				ms_sleep(100);
		} while(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

		if (ret != cur+1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send DPD request (%d): %s\n"), cur, gnutls_strerror(ret));
			MTU_FAIL_CONT;
		}

 reread:
		memset(buf, 0, sizeof(id)+1);
		do {
			if (is_cancelled(vpninfo))
				goto fail;

			ret = DTLS_RECV(vpninfo->dtls_ssl, buf, cur + 1);
			if (ret < 0)
				ms_sleep(100);

			if (max_recv_loops-- <= 0)
				goto fail;
		} while(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

		if (ret > 0 && (buf[0] != AC_PKT_DPD_RESP || memcmp(&buf[1], id, sizeof(id)) != 0)) {
			vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received unexpected packet (%.2x) in MTU detection; skipping.\n"), (unsigned)buf[0]);
			goto reread; /* resend */
		}

		if (ret <= 0) {
			vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to recv DPD request (%d): %s\n"), cur, gnutls_strerror(ret));
			MTU_FAIL_CONT;
		}

		/* If we reached the max, success */
		if (cur == max) {
			break;
		}
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
	int max_recv_loops = 40; /* 4 secs max */
	char id[MTU_ID_SIZE];

	cur = max = vpninfo->ip_info.mtu;

	vpn_progress(vpninfo, PRG_DEBUG,
	     _("Initiating IPv6 MTU detection\n"));

	do {
		/* generate unique ID */
		if (gnutls_rnd(GNUTLS_RND_NONCE, id, sizeof(id)) < 0)
			goto fail;

		buf[0] = AC_PKT_DPD_OUT;
		memcpy(&buf[1], id, sizeof(id));
		do {
			if (is_cancelled(vpninfo))
				goto fail;

			ret = DTLS_SEND(vpninfo->dtls_ssl, buf, cur+1);
			if (ret < 0)
				ms_sleep(100);
		} while(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

		if (ret != cur+1) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send DPD request (%d): %s\n"), cur, gnutls_strerror(ret));
			goto mtu6_fail;
		}

 reread:
		memset(buf, 0, sizeof(id)+1);
		do {
			if (is_cancelled(vpninfo))
				goto fail;

			ret = DTLS_RECV(vpninfo->dtls_ssl, buf, cur + 1);
			if (ret < 0)
				ms_sleep(100);

			if (max_recv_loops-- <= 0)
				goto fail;
		} while(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

		/* timeout, probably our original request was lost,
		 * let's resend the DPD */
		if (ret == GNUTLS_E_TIMEDOUT)
			continue;

		/* something unexpected was received, let's ignore it */
		if (ret > 0 && (buf[0] != AC_PKT_DPD_RESP || memcmp(&buf[1], id, sizeof(id)) != 0)) {
			vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received unexpected packet (%.2x) in MTU detection; skipping.\n"), (unsigned)buf[0]);
			goto reread;
		}

		/* we received what we expected, move on */
		break;
	} while(max_resends-- > 0);

#ifdef HAVE_IPV6_PATHMTU
	/* If we received back our DPD packet, do nothing; otherwise,
	 * attempt to get MTU from the ICMP6 packet we received */
	if (ret <= 0) {
		struct ip6_mtuinfo mtuinfo;
		socklen_t len = sizeof(mtuinfo);
		max = 0;
		vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to recv DPD request (%d): %s\n"), cur, gnutls_strerror(ret));
 mtu6_fail:
		if (getsockopt(vpninfo->dtls_fd, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo, &len) >= 0) {
			max = mtuinfo.ip6m_mtu;
			if (max >= 0 && max < cur) {
				gnutls_dtls_set_mtu(vpninfo->dtls_ssl, max);
				cur = gnutls_dtls_get_data_mtu(vpninfo->dtls_ssl) - /*ipv6*/40 - /*udp*/20 - /*oc dtls*/1;
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

static void detect_mtu(struct openconnect_info *vpninfo)
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

	/* enforce a timeout in receiving */
	gnutls_record_set_timeout(vpninfo->dtls_ssl, 2400);
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
	gnutls_record_set_timeout(vpninfo->dtls_ssl, 0);
	free(buf);
}

#endif

#else /* !HAVE_DTLS */
#warning Your SSL library does not seem to support Cisco DTLS compatibility
#endif
