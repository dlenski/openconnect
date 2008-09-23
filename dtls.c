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
 * This code works when run against Cisco's own libssl.so.0.9.8, but
 * fails (Bad Record MAC on receipt of the Server Hello) when run
 * against my own build of OpenSSL-0.9.8f.
 *
 * It lookslike they've reverted _some_ of the changes beween 0.9.8e
 * and 0.9.8f, but not all of them. In particular, they use
 * DTLS1_BAD_VER for the protocol version.
 *
 * Using OpenSSL-0.9.8e, which was the last release of OpenSSL to use
 * DTLS1_BAD_VER, also fails similarly.
 *
 * Hopefully they're just using something equivalent to a snapshot
 * between 0.9.8e and 0.9.8f, and they don't have their own "special"
 * changes on top.
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

static int connect_dtls_socket(struct anyconnect_info *vpninfo, int dtls_port)
{
	SSL_METHOD *dtls_method;
	SSL_CTX *dtls_ctx;
	SSL_SESSION *dtls_session;
	SSL_CIPHER *https_cipher;
	SSL *dtls_ssl;
	BIO *dtls_bio;
	int dtls_fd;
	int ret;

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

	dtls_method = DTLSv1_client_method();
	dtls_ctx = SSL_CTX_new(dtls_method);
	SSL_CTX_set_read_ahead(dtls_ctx, 1);
	https_cipher = SSL_get_current_cipher(vpninfo->https_ssl);

	dtls_ssl = SSL_new(dtls_ctx);
	SSL_set_connect_state(dtls_ssl);
	SSL_set_cipher_list(dtls_ssl, SSL_CIPHER_get_name(https_cipher));
	printf("SSL_SESSION is %d bytes\n", sizeof(*dtls_session));
	/* We're going to "resume" a session which never existed. Fake it... */
	dtls_session = SSL_SESSION_new();

	dtls_session->ssl_version = DTLS1_BAD_VER;

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
		printf("Trying the official version %x\n", DTLS1_VERSION);
		dtls_session->ssl_version = DTLS1_VERSION;
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
	printf("DTLS Connection successful!\n");
	/* FIXME: implement data transfer over it! */
	vpninfo->dtls_fd = dtls_fd;
	vpninfo->dtls_ssl = dtls_ssl;
	return 0;
}
static char start_dtls_hdr[8] = {'S', 'T', 'F', 1, 0, 0, 7, 0};

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
		} else if (!strcmp(dtls_opt->option, "X-DTLS-Port")) {
			dtls_port = atol(dtls_opt->value);
		} else if (!strcmp(dtls_opt->option, "X-DTLS-Keepalive")) {
			vpninfo->dtls_keepalive = atol(dtls_opt->value);
		}
			
		dtls_opt = dtls_opt->next;
	}
	if (!sessid_found || !dtls_port)
		return -EINVAL;

	if (connect_dtls_socket(vpninfo, dtls_port))
		return -EINVAL;

	BIO_set_nbio(SSL_get_rbio(vpninfo->dtls_ssl),1);
	BIO_set_nbio(SSL_get_wbio(vpninfo->dtls_ssl),1);

	fcntl(vpninfo->dtls_fd, F_SETFL, fcntl(vpninfo->dtls_fd, F_GETFL) | O_NONBLOCK);

	vpn_add_pollfd(vpninfo, vpninfo->ssl_fd, POLLIN|POLLHUP|POLLERR);
	vpninfo->last_ssl_tx = time(NULL);

	SSL_write(vpninfo->https_ssl, start_dtls_hdr, sizeof(start_dtls_hdr));
	return 0;
}

int dtls_mainloop(struct anyconnect_info *vpninfo, int *timeout)
{
	char buf[2000];
	int len;
	int work_done = 0;

	while ( (len = SSL_read(vpninfo->dtls_ssl, buf, sizeof(buf))) > 0 ) {
		if (verbose) {
			printf("Received DTLS packet of %d bytes\n", len);
			printf("Packet starts %02x %02x %02x %02x %02x %02x %02x %02x\n",
			       buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
		}	
		switch(buf[0]) {
		case 0:
			queue_new_packet(&vpninfo->incoming_queue, AF_INET, buf+1, len-1);
			work_done = 1;
			break;

		case 4: /* keepalive response */
			break;

		default:
			fprintf(stderr, "Unknown DTLS packet type %02x\n", buf[0]);
			break;
		}

	}
	while (vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		int ret;

		vpninfo->outgoing_queue = this->next;

		buf[0] = 0;
		memcpy(buf + 1, this->data, this->len);
		
		ret = SSL_write(vpninfo->dtls_ssl, buf, this->len + 1);
		if (verbose) {
			printf("Sent DTLS packet of %d bytes; SSL_write() returned %d\n",
			       this->len, ret);
		}
	}

	/* FIXME: Keepalive */
	return work_done;
}


