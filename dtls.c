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
		printf("SSL_set_session() failed with old protocol version 0x%x\n",
		       dtls_session->ssl_version);
		printf("Your OpenSSL may lack Cisco compatibility support\n");
		printf("See http://rt.openssl.org/Ticket/Display.html?id=1751\n");
		printf("Use the --no-dtls command line option to avoid this message\n");
		return -EINVAL;
	}
	if (!SSL_CTX_add_session(dtls_ctx, dtls_session))
		printf("SSL_CTX_add_session() failed\n");


	/* Go Go Go! */
	dtls_bio = BIO_new_socket(dtls_fd, BIO_NOCLOSE);
	SSL_set_bio(dtls_ssl, dtls_bio, dtls_bio);

	/* XXX Cargo cult programming. Other DTLS code does this, and it might
	   avoid http://rt.openssl.org/Ticket/Display.html?id=1703 */
        BIO_ctrl(dtls_bio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);

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
			vpninfo->dtls_times.keepalive = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "DPD")) {
			vpninfo->dtls_times.dpd = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option + 7, "Rekey-Time")) {
			vpninfo->dtls_times.rekey = atol(dtls_opt->value);
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
	vpninfo->dtls_times.last_rekey = vpninfo->dtls_times.last_rx =
		vpninfo->dtls_times.last_tx = time(NULL);

	if (verbose)
		printf("DTLS connected. DPD %d, Keepalive %d\n",
		       vpninfo->dtls_times.dpd, vpninfo->dtls_times.keepalive);

	return 0;
}

int dtls_mainloop(struct anyconnect_info *vpninfo, int *timeout)
{
	unsigned char buf[2000];
	int len;
	int work_done = 0;
	char magic_pkt;

	while ( (len = SSL_read(vpninfo->dtls_ssl, buf, sizeof(buf))) > 0 ) {
		if (verbose)
			printf("Received DTLS packet 0x%02x of %d bytes\n",
			       len, buf[0]);

		vpninfo->dtls_times.last_rx = time(NULL);

		switch(buf[0]) {
		case AC_PKT_DATA:
			queue_new_packet(&vpninfo->incoming_queue, AF_INET, buf+1, len-1);
			work_done = 1;
			break;

		case AC_PKT_DPD_RESP:
			if (verbose)
				printf("Got DTLS DPD response\n");
			break;

		default:
			fprintf(stderr, "Unknown DTLS packet type %02x\n", buf[0]);
			vpninfo->quit_reason = "Unknown packet received";
			return 1;
		}
	}

	if (verbose)
		printf("Process DTLS keepalive...\n");
	switch (keepalive_action(&vpninfo->dtls_times, timeout)) {
	case KA_REKEY:
		if (verbose)
			printf("DTLS rekey due\n");
		if (dtls_rekey(vpninfo)) {
			fprintf(stderr, "DTLS rekey failed\n");
			/* Fall back to SSL */
			SSL_free(vpninfo->dtls_ssl);
			close(vpninfo->dtls_fd);
			vpninfo->pfds[vpninfo->dtls_pfd].fd = -1;
			vpninfo->dtls_ssl = NULL;
			vpninfo->dtls_fd = -1;
			return 1;
		}
		time(&vpninfo->dtls_times.last_rekey);
		work_done = 1;
		break;


	case KA_DPD_DEAD:
		fprintf(stderr, "DTLS Dead Peer Detection detected dead peer!\n");
		/* Fall back to SSL */
		SSL_free(vpninfo->dtls_ssl);
		close(vpninfo->dtls_fd);
		vpninfo->pfds[vpninfo->dtls_pfd].fd = -1;
		vpninfo->dtls_ssl = NULL;
		vpninfo->dtls_fd = -1;
		return 1;

	case KA_DPD:
		if (verbose)
			printf("Send DTLS DPD\n");

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

		if (verbose)
			printf("Send DTLS Keepalive\n");

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

		/* One byte of header */
		this->hdr[7] = AC_PKT_DATA;
		
		ret = SSL_write(vpninfo->dtls_ssl, &this->hdr[7], this->len + 1);
		time(&vpninfo->dtls_times.last_tx);
		if (verbose) {
			printf("Sent DTLS packet of %d bytes; SSL_write() returned %d\n",
			       this->len, ret);
		}
	}

	return work_done;
}


