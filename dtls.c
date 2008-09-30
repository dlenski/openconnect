/*
 * Open AnyConnect (SSL + DTLS) client
 *
 * © 2008 David Woodhouse <dwmw2@infradead.org>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/err.h>
#include <fcntl.h>

#include "anyconnect.h"

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
 * my subsequent data packets.
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

static int connect_dtls_socket(struct anyconnect_info *vpninfo, SSL **ret_ssl,
			       int *ret_fd)
{
	SSL_METHOD *dtls_method;
	SSL_CTX *dtls_ctx;
	SSL_SESSION *dtls_session;
	SSL_CIPHER *https_cipher;
	SSL *dtls_ssl;
	BIO *dtls_bio;
	int dtls_fd;
	int ret;

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

	dtls_method = DTLSv1_client_method();
	dtls_ctx = SSL_CTX_new(dtls_method);
	SSL_CTX_set_read_ahead(dtls_ctx, 1);
	https_cipher = SSL_get_current_cipher(vpninfo->https_ssl);

	dtls_ssl = SSL_new(dtls_ctx);
	SSL_set_connect_state(dtls_ssl);
	SSL_set_cipher_list(dtls_ssl, SSL_CIPHER_get_name(https_cipher));

	if (verbose)
		printf("SSL_SESSION is %zd bytes\n", sizeof(*dtls_session));
	/* We're going to "resume" a session which never existed. Fake it... */
	dtls_session = SSL_SESSION_new();

	dtls_session->ssl_version = 0x0100; // DTLS1_BAD_VER

	dtls_session->master_key_length = sizeof(vpninfo->dtls_secret);
	memcpy(dtls_session->master_key, vpninfo->dtls_secret,
	       sizeof(vpninfo->dtls_secret));

	dtls_session->session_id_length = sizeof(vpninfo->dtls_session_id);
	memcpy(dtls_session->session_id, vpninfo->dtls_session_id,
	       sizeof(vpninfo->dtls_session_id));

	dtls_session->cipher = https_cipher;
	dtls_session->cipher_id = https_cipher->id;

	/* Having faked a session, add it to the CTX and the SSL */
	if (!SSL_set_session(dtls_ssl, dtls_session)) {
		printf("SSL_set_session() failed with old protocol version 0x%x\n", dtls_session->ssl_version);
		printf("Trying the official version %x\n", 0xfeff);
		dtls_session->ssl_version = 0xfeff;
		if (!SSL_set_session(dtls_ssl, dtls_session)) {
			printf("SSL_set_session() failed still. Is your build ABI-compatible with your libssl?\n");
			return -EINVAL;
		}
	}
	if (!SSL_CTX_add_session(dtls_ctx, dtls_session))
		printf("SSL_CTX_add_session() failed\n");


	/* Go Go Go! */
	dtls_bio = BIO_new_socket(dtls_fd, BIO_NOCLOSE);
	SSL_set_bio(dtls_ssl, dtls_bio, dtls_bio);

#ifndef SSL_OP_CISCO_ANYCONNECT
#define SSL_OP_CISCO_ANYCONNECT 0x8000
#endif
	SSL_set_options(dtls_ssl, SSL_OP_CISCO_ANYCONNECT);
	ret = SSL_do_handshake(dtls_ssl);
	
	if (ret != 1) {
		fprintf(stderr, "DTLS connection returned %d\n", ret);
		if (ret < 0)
			fprintf(stderr, "DTLS handshake error: %d\n", SSL_get_error(dtls_ssl, ret));
		ERR_print_errors_fp(stderr);
		SSL_free(dtls_ssl);
		SSL_CTX_free(dtls_ctx);
		close(dtls_fd);
		return -EINVAL;
	}

	BIO_set_nbio(SSL_get_rbio(dtls_ssl),1);
	BIO_set_nbio(SSL_get_wbio(dtls_ssl),1);

	fcntl(dtls_fd, F_SETFL, fcntl(dtls_fd, F_GETFL) | O_NONBLOCK);

	*ret_fd = dtls_fd;
	*ret_ssl = dtls_ssl;

	return 0;
}

static int dtls_rekey(struct anyconnect_info *vpninfo)
{
	SSL *dtls_ssl;
	int dtls_fd;

	/* To rekey, we just 'resume' the session again */
	if (connect_dtls_socket(vpninfo, &dtls_ssl, &dtls_fd))
		return -EINVAL;

	vpninfo->pfds[vpninfo->dtls_pfd].fd = dtls_fd;

	SSL_free(vpninfo->dtls_ssl);
	close(vpninfo->dtls_fd);

	vpninfo->dtls_ssl = dtls_ssl;
	vpninfo->dtls_fd = dtls_fd;

	return 0;
}

int setup_dtls(struct anyconnect_info *vpninfo)
{
	struct vpn_option *dtls_opt = vpninfo->dtls_options;
	int sessid_found = 0;
	int dtls_port = 0;
	int i;

	while (dtls_opt) {
		if (verbose)
			printf("DTLS option %s : %s\n", dtls_opt->option, dtls_opt->value);

		if (!strcmp(dtls_opt->option, "X-DTLS-Session-ID")) {
			if (strlen(dtls_opt->value) != 64) {
				fprintf(stderr, "X-DTLS-Session-ID not 64 characters\n");
				fprintf(stderr, "Is: %s\n", dtls_opt->value);
				return -EINVAL;
			}
			for (i = 0; i < 64; i += 2)
				vpninfo->dtls_session_id[i/2] = hex(dtls_opt->value + i);
			sessid_found = 1;
		} else if (!strcmp(dtls_opt->option + 7, "Port")) {
			dtls_port = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "Keepalive")) {
			vpninfo->dtls_keepalive = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "DPD")) {
			vpninfo->dtls_dpd = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "Rekey-Time")) {
			vpninfo->dtls_rekey = atol(dtls_opt->value);
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
		fprintf(stderr, "Unknown protocol family %d. Cannot do DTLS\n",
			vpninfo->peer_addr->sa_family);
		return -EINVAL;
	}

	if (connect_dtls_socket(vpninfo, &vpninfo->dtls_ssl, &vpninfo->dtls_fd))
		return -EINVAL;

	vpninfo->dtls_pfd = vpn_add_pollfd(vpninfo, vpninfo->dtls_fd,
					   POLLIN|POLLHUP|POLLERR);
	vpninfo->last_dtls_rekey = vpninfo->last_dtls_rx =
		vpninfo->last_dtls_tx = time(NULL);

	if (verbose)
		printf("DTLS connected. DPD %d, Keepalive %d\n",
		       vpninfo->dtls_dpd, vpninfo->dtls_keepalive);

	return 0;
}

int dtls_mainloop(struct anyconnect_info *vpninfo, int *timeout)
{
	unsigned char buf[2000];
	int len;
	int work_done = 0;

	while ( (len = SSL_read(vpninfo->dtls_ssl, buf, sizeof(buf))) > 0 ) {
		if (verbose)
			printf("Received DTLS packet 0x%02x of %d bytes\n",
			       len, buf[0]);

		vpninfo->last_dtls_rx = time(NULL);

		switch(buf[0]) {
		case 0:
			queue_new_packet(&vpninfo->incoming_queue, AF_INET, buf+1, len-1);
			work_done = 1;
			break;

		case 4: /* DPD response */
			if (verbose)
				printf("Got DTLS DPD response\n");
			break;

		default:
			fprintf(stderr, "Unknown DTLS packet type %02x\n", buf[0]);
			vpninfo->quit_reason = "Unknown packet received";
			return 1;
		}
	}
	while (vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		int ret;

		vpninfo->outgoing_queue = this->next;

		buf[0] = 0;
		memcpy(buf + 1, this->data, this->len);
		
		ret = SSL_write(vpninfo->dtls_ssl, buf, this->len + 1);
		vpninfo->last_dtls_tx = time(NULL);
		if (verbose) {
			printf("Sent DTLS packet of %d bytes; SSL_write() returned %d\n",
			       this->len, ret);
		}
	}

	/* DPD is bidirectional -- PKT 3 out, PKT 4 back */
	if (vpninfo->dtls_dpd) {
		time_t now = time(NULL);
		time_t due = vpninfo->last_dtls_rx + vpninfo->dtls_dpd;
		time_t overdue = vpninfo->last_dtls_rx + (5 * vpninfo->dtls_dpd);

		/* If we already have DPD outstanding, don't flood */
		if (vpninfo->last_dtls_dpd > vpninfo->last_dtls_rx)
			due = vpninfo->last_dtls_dpd + vpninfo->dtls_dpd;
			
		if (now > overdue) {
			fprintf(stderr, "DTLS Dead Peer Detection detected dead peer!\n");
			/* Fall back to SSL */
			SSL_free(vpninfo->dtls_ssl);
			close(vpninfo->dtls_fd);
			vpninfo->dtls_ssl = NULL;
			vpninfo->dtls_fd = -1;
			return 1;
		}
		if (now >= due) {
			static unsigned char dtls_dpd_pkt[1] = { 3 };
			/* Haven't heard anything from the other end for a while.
			   Check if it's still there */
			/* FIXME: If isn't, we should act on that */
			SSL_write(vpninfo->dtls_ssl, dtls_dpd_pkt, 1);
			vpninfo->last_dtls_tx = now;

			due = now + vpninfo->dtls_dpd;
			if (verbose)
				printf("Sent DTLS DPD\n");
		}

		if (verbose)
			printf("Next DTLS DPD due in %ld seconds\n", (due - now));
		if (*timeout > (due - now) * 1000)
			*timeout = (due - now) * 1000;
	}

	/* Keepalive is just client -> server */
	if (vpninfo->dtls_keepalive) {
		time_t now = time(NULL);
		time_t due = vpninfo->last_dtls_tx + vpninfo->dtls_keepalive;

		if (now >= due) {
			static unsigned char dtls_keepalive_pkt[1] = { 7 };

			/* Send something (which is discarded), to keep
			   the connection alive. */
			SSL_write(vpninfo->dtls_ssl, dtls_keepalive_pkt, 1);
			vpninfo->last_dtls_tx = now;

			due = now + vpninfo->dtls_keepalive;
			if (verbose)
				printf("Sent DTLS Keepalive\n");
		}

		if (verbose)
			printf("Next DTLS Keepalive due in %ld seconds\n", (due - now));
		if (*timeout > (due - now) * 1000)
			*timeout = (due - now) * 1000;
	}

	if (vpninfo->dtls_rekey) {
		time_t now = time(NULL);
		time_t due = vpninfo->last_dtls_rekey + vpninfo->dtls_rekey;

		if (now >= due) {
			if (verbose)
				printf("DTLS rekey due\n");
			if (dtls_rekey(vpninfo)) {
				fprintf(stderr, "DTLS rekey failed\n");
				/* Fall back to SSL */
				SSL_free(vpninfo->dtls_ssl);
				close(vpninfo->dtls_fd);
				vpninfo->dtls_ssl = NULL;
				vpninfo->dtls_fd = -1;
				return 1;
			}
			vpninfo->last_dtls_rekey = time(NULL);
			due = vpninfo->last_dtls_rekey + vpninfo->dtls_rekey;
		}
		if (verbose)
			printf("Next DTLS rekey due in %ld seconds\n", (due - now));
		if (*timeout > (due - now) * 1000)
			*timeout = (due - now) * 1000;
	}

	return work_done;
}


