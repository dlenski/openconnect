/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008 Intel Corporation.
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
#include <openssl/err.h>
#include <fcntl.h>
#include <string.h>

#include "openconnect.h"

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

static unsigned char nybble(unsigned char n)
{
	if      (n >= '0' && n <= '9') return n - '0';
	else if (n >= 'A' && n <= 'F') return n - ('A' - 10);
	else if (n >= 'a' && n <= 'f') return n - ('a' - 10);
	return 0;
}

static unsigned char hex(const char *data)
{
	return (nybble(data[0]) << 4) | nybble(data[1]);
}

int connect_dtls_socket(struct openconnect_info *vpninfo)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	SSL_METHOD *dtls_method;
	SSL_CIPHER *dtls_cipher;
	SSL *dtls_ssl;
	BIO *dtls_bio;
	int dtls_fd;

	if (!vpninfo->dtls_cipher) {
		/* We probably didn't offer it any ciphers it liked */
		vpninfo->progress(vpninfo, PRG_ERR, "Server offered no DTLS cipher option\n");
		return -EINVAL;
	}
		
	dtls_fd = socket(vpninfo->peer_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (dtls_fd < 0) {
		perror("Open UDP socket for DTLS:");
		return -EINVAL;
	}

	if (connect(dtls_fd, vpninfo->peer_addr, vpninfo->peer_addrlen)) {
		perror("UDP (DTLS) connect:\n");
		close(dtls_fd);
		return -EINVAL;
	}

	fcntl(dtls_fd, F_SETFD, FD_CLOEXEC);

	if (!vpninfo->dtls_ctx) {
		dtls_method = DTLSv1_client_method();
		vpninfo->dtls_ctx = SSL_CTX_new(dtls_method);
		if (!vpninfo->dtls_ctx) {
			vpninfo->progress(vpninfo, PRG_ERR, "Initialise DTLSv1 CTX failed\n");
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}

		/* If we don't readahead, then we do short reads and throw
		   away the tail of data packets. */
		SSL_CTX_set_read_ahead(vpninfo->dtls_ctx, 1);

		if (!SSL_CTX_set_cipher_list(vpninfo->dtls_ctx, vpninfo->dtls_cipher)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Set DTLS cipher list failed\n");
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
			vpninfo->progress(vpninfo, PRG_ERR, "Initialise DTLSv1 session failed\n");
			vpninfo->dtls_attempt_period = 0;
			return -EINVAL;
		}
		vpninfo->dtls_session->ssl_version = 0x0100; // DTLS1_BAD_VER

		vpninfo->dtls_session->master_key_length = sizeof(vpninfo->dtls_secret);
		memcpy(vpninfo->dtls_session->master_key, vpninfo->dtls_secret,
		       sizeof(vpninfo->dtls_secret));

		vpninfo->dtls_session->session_id_length = sizeof(vpninfo->dtls_session_id);
		memcpy(vpninfo->dtls_session->session_id, vpninfo->dtls_session_id,
		       sizeof(vpninfo->dtls_session_id));
	}

	dtls_ssl = SSL_new(vpninfo->dtls_ctx);
	SSL_set_connect_state(dtls_ssl);

	ciphers = SSL_get_ciphers(dtls_ssl);
	if (sk_SSL_CIPHER_num(ciphers) != 1) {
		vpninfo->progress(vpninfo, PRG_ERR, "Not precisely one DTLS cipher\n");
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
		vpninfo->progress(vpninfo, PRG_ERR,
				  "SSL_set_session() failed with old protocol version 0x%x\n"
				  "Your OpenSSL may lack Cisco compatibility support\n"
				  "See http://rt.openssl.org/Ticket/Display.html?id=1751\n"
				  "Use the --no-dtls command line option to avoid this message\n",
				  vpninfo->dtls_session->ssl_version);
		vpninfo->dtls_attempt_period = 0;
		return -EINVAL;
	}

	/* Go Go Go! */
	dtls_bio = BIO_new_socket(dtls_fd, BIO_NOCLOSE);
	SSL_set_bio(dtls_ssl, dtls_bio, dtls_bio);

#ifndef SSL_OP_CISCO_ANYCONNECT
#define SSL_OP_CISCO_ANYCONNECT 0x8000
#endif
	SSL_set_options(dtls_ssl, SSL_OP_CISCO_ANYCONNECT);

	/* Set non-blocking */
	BIO_set_nbio(SSL_get_rbio(dtls_ssl), 1);
	BIO_set_nbio(SSL_get_wbio(dtls_ssl), 1);

	fcntl(dtls_fd, F_SETFL, fcntl(dtls_fd, F_GETFL) | O_NONBLOCK);

	vpninfo->new_dtls_fd = dtls_fd;
	vpninfo->new_dtls_ssl = dtls_ssl;

	if (vpninfo->select_nfds <= dtls_fd)
		vpninfo->select_nfds = dtls_fd + 1;

	FD_SET(dtls_fd, &vpninfo->select_rfds);
	FD_SET(dtls_fd, &vpninfo->select_efds);

	time(&vpninfo->new_dtls_started);
	return dtls_try_handshake(vpninfo);
}

int dtls_try_handshake(struct openconnect_info *vpninfo)
{
	int ret = SSL_do_handshake(vpninfo->new_dtls_ssl);

	if (ret == 1) {
		vpninfo->progress(vpninfo, PRG_INFO, "Established DTLS connection\n");

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

		vpninfo->dtls_times.last_rekey = vpninfo->dtls_times.last_rx =
			vpninfo->dtls_times.last_tx = time(NULL);

		return 0;
	}

	ret = SSL_get_error(vpninfo->new_dtls_ssl, ret);
	if (ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_WANT_READ) {
		if (time(NULL) < vpninfo->new_dtls_started + 5)
			return 0;
		vpninfo->progress(vpninfo, PRG_TRACE, "DTLS handshake timed out\n");
	}

	vpninfo->progress(vpninfo, PRG_ERR, "DTLS handshake failed: %d\n", ret);
	report_ssl_errors(vpninfo);

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

static int dtls_restart(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_ssl) {
		SSL_free(vpninfo->dtls_ssl);
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
	int sessid_found = 0;
	int dtls_port = 0;
	int i;

	while (dtls_opt) {
		vpninfo->progress(vpninfo, PRG_TRACE,
				  "DTLS option %s : %s\n",
				  dtls_opt->option, dtls_opt->value);

		if (!strcmp(dtls_opt->option, "X-DTLS-Session-ID")) {
			if (strlen(dtls_opt->value) != 64) {
				vpninfo->progress(vpninfo, PRG_ERR, "X-DTLS-Session-ID not 64 characters\n");
				vpninfo->progress(vpninfo, PRG_ERR, "Is: %s\n", dtls_opt->value);
				return -EINVAL;
			}
			for (i = 0; i < 64; i += 2)
				vpninfo->dtls_session_id[i/2] = hex(dtls_opt->value + i);
			sessid_found = 1;
		} else if (!strcmp(dtls_opt->option + 7, "Port")) {
			dtls_port = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "Keepalive")) {
			vpninfo->dtls_times.keepalive = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "DPD")) {
			vpninfo->dtls_times.dpd = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "Rekey-Time")) {
			vpninfo->dtls_times.rekey = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "CipherSuite")) {
			vpninfo->dtls_cipher = dtls_opt->value;
		}

		dtls_opt = dtls_opt->next;
	}
	if (!sessid_found || !dtls_port)
		return -EINVAL;

	if (vpninfo->peer_addr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (void *)vpninfo->peer_addr;
		sin->sin_port = htons(dtls_port);
	} else if (vpninfo->peer_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin = (void *)vpninfo->peer_addr;
		sin->sin6_port = htons(dtls_port);
	} else {
		vpninfo->progress(vpninfo, PRG_ERR, "Unknown protocol family %d. Cannot do DTLS\n",
			vpninfo->peer_addr->sa_family);
		return -EINVAL;
	}


	if (connect_dtls_socket(vpninfo))
		return -EINVAL;

	vpninfo->progress(vpninfo, PRG_TRACE,
			  "DTLS connected. DPD %d, Keepalive %d\n",
			  vpninfo->dtls_times.dpd, vpninfo->dtls_times.keepalive);

	return 0;
}

int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	unsigned char buf[2000];
	int len;
	int work_done = 0;
	char magic_pkt;

	while ( (len = SSL_read(vpninfo->dtls_ssl, buf, sizeof(buf))) > 0 ) {

		vpninfo->progress(vpninfo, PRG_TRACE,
				  "Received DTLS packet 0x%02x of %d bytes\n",
				  buf[0], len);

		vpninfo->dtls_times.last_rx = time(NULL);

		switch(buf[0]) {
		case AC_PKT_DATA:
			queue_new_packet(&vpninfo->incoming_queue, AF_INET, buf+1, len-1);
			work_done = 1;
			break;

		case AC_PKT_DPD_OUT:
			vpninfo->progress(vpninfo, PRG_TRACE, "Got DTLS DPD request\n");

			/* FIXME: What if the packet doesn't get through? */
			magic_pkt = AC_PKT_DPD_RESP;
			if (SSL_write(vpninfo->dtls_ssl, &magic_pkt, 1) != 1)
				vpninfo->progress(vpninfo, PRG_ERR, "Failed to send DPD response. Expect disconnect\n");
			continue;

		case AC_PKT_DPD_RESP:
			vpninfo->progress(vpninfo, PRG_TRACE, "Got DTLS DPD response\n");
			break;

		case AC_PKT_KEEPALIVE:
			vpninfo->progress(vpninfo, PRG_TRACE, "Got DTLS Keepalive\n");
			break;

		default:
			vpninfo->progress(vpninfo, PRG_ERR,
					  "Unknown DTLS packet type %02x, len %d\n", buf[0], len);
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
		time(&vpninfo->dtls_times.last_rekey);
		vpninfo->progress(vpninfo, PRG_TRACE, "DTLS rekey due\n");
		if (connect_dtls_socket(vpninfo)) {
			vpninfo->progress(vpninfo, PRG_ERR, "DTLS rekey failed\n");
			return 1;
		}
		work_done = 1;
		break;


	case KA_DPD_DEAD:
		vpninfo->progress(vpninfo, PRG_ERR, "DTLS Dead Peer Detection detected dead peer!\n");
		/* Fall back to SSL, and start a new DTLS connection */
		dtls_restart(vpninfo);
		return 1;

	case KA_DPD:
		vpninfo->progress(vpninfo, PRG_TRACE, "Send DTLS DPD\n");

		magic_pkt = AC_PKT_DPD_OUT;
		SSL_write(vpninfo->dtls_ssl, &magic_pkt, 1);
		/* last_dpd will just have been set */
		vpninfo->dtls_times.last_tx = vpninfo->dtls_times.last_dpd;
		work_done = 1;
		break;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->outgoing_queue)
			break;

		vpninfo->progress(vpninfo, PRG_TRACE, "Send DTLS Keepalive\n");

		magic_pkt = AC_PKT_KEEPALIVE;
		SSL_write(vpninfo->dtls_ssl, &magic_pkt, 1);
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

		ret = SSL_write(vpninfo->dtls_ssl, &this->hdr[7], this->len + 1);
		if (ret <= 0) {
			ret = SSL_get_error(vpninfo->dtls_ssl, ret);

			/* If it's a real error, kill the DTLS connection and
			   requeue the packet to be sent over SSL */
			if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE) {
				vpninfo->progress(vpninfo, PRG_ERR,
						  "DTLS got write error %d. Falling back to SSL\n", ret);
				report_ssl_errors(vpninfo);
				dtls_restart(vpninfo);
				vpninfo->outgoing_queue = this;
				vpninfo->outgoing_qlen++;
			}
			return 1;
		}
		time(&vpninfo->dtls_times.last_tx);
		vpninfo->progress(vpninfo, PRG_TRACE,
				  "Sent DTLS packet of %d bytes; SSL_write() returned %d\n",
				  this->len, ret);
		free(this);
	}

	return work_done;
}


