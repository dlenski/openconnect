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

#include "anyconnect.h"

/*
 * The master-secret is generated randomly by the client. The server
 * responds with a DTLS Session-ID. These, done over the HTTPS
 * connection, are enough to 'resume' a DTLS session, bypassing all
 * the normal setup of a normal DTLS connection.
 * 
 * Cisco's own client uses an old version of OpenSSL, which implements
 * the pre-RFC version of DTLS. I haven't been able to get it working 
 * when I force it to link against any of my own builds of OpenSSL.
 *
 * Hopefully, it'll just work when I get round to implementing it
 * here, either with the system OpenSSL, or linking against their
 * library (which will at least be progress, and make it a little
 * easier to debug.
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
	
	/* We're going to "resume" a session which never existed. Fake it... */
	dtls_session = SSL_SESSION_new();

	dtls_session->ssl_version = DTLS1_VERSION;

	dtls_session->master_key_length = sizeof(vpninfo->dtls_secret);
	memcpy(dtls_session->master_key, vpninfo->dtls_secret,
	       sizeof(vpninfo->dtls_secret));

	dtls_session->session_id_length = sizeof(vpninfo->dtls_session_id);
	memcpy(dtls_session->session_id, vpninfo->dtls_session_id,
	       sizeof(vpninfo->dtls_session_id));

	dtls_session->cipher = https_cipher;
	dtls_session->cipher_id = https_cipher->id;

	/* Having faked a session, add it to the CTX and the SSL */
	if (!SSL_CTX_add_session(dtls_ctx, dtls_session))
		printf("SSL_CTX_add_session() failed\n");

	if (!SSL_set_session(dtls_ssl, dtls_session))
		printf("SSL_set_session() failed\n");

	/* Go Go Go! */
	dtls_bio = BIO_new_socket(dtls_fd, BIO_NOCLOSE);
	SSL_set_bio(dtls_ssl, dtls_bio, dtls_bio);

	if (SSL_do_handshake(dtls_ssl)) {
		fprintf(stderr, "DTLS connection failure\n");
		ERR_print_errors_fp(stderr);
		SSL_free(dtls_ssl);
		SSL_CTX_free(dtls_ctx);
		close(dtls_fd);
		return -EINVAL;
	}

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

	/* No idea how to do this yet */
	close(vpninfo->dtls_fd);
	vpninfo->dtls_fd = -1;
	return -EINVAL;
}

int dtls_mainloop(struct anyconnect_info *vpninfo, int *timeout)
{
	return 0;
}


