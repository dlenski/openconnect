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
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "anyconnect.h"

/*
 * Data packets are encapsulated in the SSL stream as follows:
 * 
 * 0000: Magic "STF\x1"
 * 0004: Big-endian 16-bit length (not including 8-byte header)
 * 0006: Byte packet type (see anyconnect.h)
 * 0008: data payload
 */

static char data_hdr[8] = {
	'S', 'T', 'F', 1,
	0, 0,		/* Length */
	AC_PKT_DATA,	/* Type */
	0		/* Unknown */
};

/* Helper functions for reading/writing lines over SSL.
   We could use cURL for the HTTP stuff, but it's overkill */

int  __attribute__ ((format (printf, 2, 3)))
	my_SSL_printf(SSL *ssl, const char *fmt, ...) 
{
	char buf[1024];
	va_list args;
	
	buf[1023] = 0;

	va_start(args, fmt);
	vsnprintf(buf, 1023, fmt, args);
	va_end(args);
	if (verbose)
		printf("%s", buf);
	return SSL_write(ssl, buf, strlen(buf));

}

int my_SSL_gets(SSL *ssl, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while ( (ret = SSL_read(ssl, buf + i, 1)) == 1) {
		if (buf[i] == '\n') {
			buf[i] = 0;
			if (i && buf[i-1] == '\r') {
				buf[i-1] = 0;
				i--;
			}
			return i;
		}
		i++;

		if (i >= len - 1) {
			buf[i] = 0;
			return i;
		}
	}
	if (ret == 0) {
		ret = -SSL_get_error(ssl, ret);
	}
	buf[i] = 0;
	return i?:ret;
}


/* OpenSSL UI method calls. These are just stubs, to show how it's done */
/* While we can set user data on the calls from the TPM setup, we can't
   set it on the calls for PEM certificate passphrases, AFAICT. */
static int ui_open(UI *ui)
{
	/* Fall through to default OpenSSL UI */
	return UI_method_get_opener(UI_OpenSSL())(ui);
}

static int ui_read(UI *ui, UI_STRING *uis)
{
	/* Fall through to default OpenSSL UI */
	return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}
static int ui_write(UI *ui, UI_STRING *uis)
{
	/* Fall through to default OpenSSL UI */
	return UI_method_get_writer(UI_OpenSSL())(ui, uis);

}
static int ui_close(UI *ui)
{
	/* Fall through to default OpenSSL UI */
	return UI_method_get_closer(UI_OpenSSL())(ui);
}

static int load_certificate(struct anyconnect_info *vpninfo)
{
	UI_METHOD *ui_method = UI_create_method("AnyConnect VPN UI");

	/* Set up a UI method of our own for password/passphrase requests */
	UI_method_set_opener(ui_method, ui_open);
	UI_method_set_reader(ui_method, ui_read);
	UI_method_set_writer(ui_method, ui_write);
	UI_method_set_closer(ui_method, ui_close);

	UI_set_default_method(ui_method);

	if (verbose)
		printf("Using Certificate file %s\n", vpninfo->cert);
	if (!SSL_CTX_use_certificate_file(vpninfo->https_ctx, vpninfo->cert,
					  SSL_FILETYPE_PEM)) {
		fprintf(stderr, "Certificate failed\n");
		ERR_print_errors_fp(stderr);
		return -EINVAL;
	}
	
	if (vpninfo->tpm) {
		ENGINE *e;
		EVP_PKEY *key;
		ENGINE_load_builtin_engines();

		e = ENGINE_by_id("tpm");
		if (!e) {
			fprintf(stderr, "Can't load TPM engine.\n");
			ERR_print_errors_fp(stderr);
			return -EINVAL;
		}
		if (!ENGINE_init(e) || !ENGINE_set_default_RSA(e) ||
		    !ENGINE_set_default_RAND(e)) {
			fprintf(stderr, "Failed to init TPM engine\n");
			ERR_print_errors_fp(stderr);
			ENGINE_free(e);
			return -EINVAL;
		}     

		if (vpninfo->tpmpass) {
			if (!ENGINE_ctrl_cmd(e, "PIN", strlen(vpninfo->tpmpass),
					     vpninfo->tpmpass, NULL, 0)) {
				fprintf(stderr, "Failed to set TPM SRK password\n");
				ERR_print_errors_fp(stderr);
			}
		}
		key = ENGINE_load_private_key(e, vpninfo->sslkey, NULL, NULL);
		if (!key) {
			fprintf(stderr, 
				"Failed to load TPM private key\n");
			ERR_print_errors_fp(stderr);
			ENGINE_free(e);
			ENGINE_finish(e);
			return -EINVAL;
		}
		if (!SSL_CTX_use_PrivateKey(vpninfo->https_ctx, key)) {
			fprintf(stderr, "Add key from TPM failed\n");
			ERR_print_errors_fp(stderr);
			ENGINE_free(e);
			ENGINE_finish(e);
			return -EINVAL;
		}
	} else {
		/* Key should be in cert file too*/
		/* FIXME: Can we do our own UI for PEM passphrase too? */
		if (!SSL_CTX_use_RSAPrivateKey_file(vpninfo->https_ctx, vpninfo->cert,
						    SSL_FILETYPE_PEM)) {
			fprintf(stderr, "Private key failed\n");
			ERR_print_errors_fp(stderr);
			return -EINVAL;
		}
	}
	return 0;
}
 
int open_https(struct anyconnect_info *vpninfo)
{
	SSL_METHOD *ssl3_method;
	SSL *https_ssl;
	BIO *https_bio;
	int ssl_sock;
	int err;
	struct addrinfo hints, *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	err = getaddrinfo(vpninfo->hostname, "https", &hints, &result);
	if (err) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(err));
		return -EINVAL;
	}

	for (rp = result; rp ; rp = rp->ai_next) {
		ssl_sock = socket(rp->ai_family, rp->ai_socktype,
				  rp->ai_protocol);
		if (ssl_sock < 0)
			continue;

		if (connect(ssl_sock, rp->ai_addr, rp->ai_addrlen) >= 0) {
			/* Store the peer address we actually used, so that DTLS can 
			   use it again later */
			vpninfo->peer_addr = malloc(rp->ai_addrlen);
			if (!vpninfo->peer_addr) {
				fprintf(stderr, "Failed to allocate sockaddr storage\n");
				close(ssl_sock);
				return -ENOMEM;
			}
			vpninfo->peer_addrlen = rp->ai_addrlen;
			memcpy(vpninfo->peer_addr, rp->ai_addr, rp->ai_addrlen);
			break;
		}
		close(ssl_sock);
	}
	freeaddrinfo(result);

	if (!rp) {
		fprintf(stderr, "Failed to connect to host %s\n", vpninfo->hostname);
		return -EINVAL;
	}
	fcntl(ssl_sock, F_SETFD, FD_CLOEXEC);

	ssl3_method = SSLv23_client_method();
	if (!vpninfo->https_ctx) {
		vpninfo->https_ctx = SSL_CTX_new(ssl3_method);

		if (vpninfo->cert)
			load_certificate(vpninfo);

		if (vpninfo->cafile) {
			SSL_CTX_load_verify_locations(vpninfo->https_ctx, vpninfo->cafile, NULL);
			SSL_CTX_set_default_verify_paths(vpninfo->https_ctx);
		}
	}
	https_ssl = SSL_new(vpninfo->https_ctx);

	https_bio = BIO_new_socket(ssl_sock, BIO_NOCLOSE);
	SSL_set_bio(https_ssl, https_bio, https_bio);

	if (SSL_connect(https_ssl) <= 0) {
		fprintf(stderr, "SSL connection failure\n");
		ERR_print_errors_fp(stderr);
		SSL_free(https_ssl);
		close(ssl_sock);
		return -EINVAL;
	}

	if (vpninfo->cafile) {
		int vfy = SSL_get_verify_result(https_ssl);

		/* FIXME: Show cert details, allow user to accept (and store?) */
		if (vfy != X509_V_OK) {
			fprintf(stderr, "Server certificate verify failed: %s\n",
				X509_verify_cert_error_string(vfy));
			SSL_free(https_ssl);
			close(ssl_sock);
			return -EINVAL;
		}
	}

	vpninfo->ssl_fd = ssl_sock;
	vpninfo->https_ssl = https_ssl;

	if (verbose)
		printf("Connected to HTTPS on %s\n", vpninfo->hostname);

	return 0;
}

static int start_ssl_connection(struct anyconnect_info *vpninfo)
{
	char buf[65536];
	int i;
	int retried = 0;

	struct vpn_option **next_dtls_option = &vpninfo->dtls_options;
	struct vpn_option **next_cstp_option = &vpninfo->cstp_options;

 retry:
	my_SSL_printf(vpninfo->https_ssl, "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n");
	my_SSL_printf(vpninfo->https_ssl, "Host: %s\r\n", vpninfo->hostname);
	my_SSL_printf(vpninfo->https_ssl, "User-Agent: %s\r\n", vpninfo->useragent);
	my_SSL_printf(vpninfo->https_ssl, "Cookie: webvpn=%s\r\n", vpninfo->cookie);
	my_SSL_printf(vpninfo->https_ssl, "X-CSTP-Version: 1\r\n");
	my_SSL_printf(vpninfo->https_ssl, "X-CSTP-Hostname: %s\r\n", vpninfo->localname);
	if (vpninfo->deflate)
		my_SSL_printf(vpninfo->https_ssl, "X-CSTP-Accept-Encoding: deflate;q=1.0\r\n");
	my_SSL_printf(vpninfo->https_ssl, "X-CSTP-MTU: %d\r\n", vpninfo->mtu);
	/* To enable IPv6, send 'IPv6,IPv4'.
	   We don't know how most of that works yet though. */
	my_SSL_printf(vpninfo->https_ssl, "X-CSTP-Address-Type: IPv4\r\n");
	my_SSL_printf(vpninfo->https_ssl, "X-DTLS-Master-Secret: ");
	for (i = 0; i < sizeof(vpninfo->dtls_secret); i++)
		my_SSL_printf(vpninfo->https_ssl, "%02X", vpninfo->dtls_secret[i]);
	my_SSL_printf(vpninfo->https_ssl, "\r\nX-DTLS-CipherSuite: AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA\r\n\r\n");

	if (my_SSL_gets(vpninfo->https_ssl, buf, 65536) < 0) {
		fprintf(stderr, "Error fetching HTTPS response\n");
		if (!retried) {
			retried = 1;
			SSL_free(vpninfo->https_ssl);
			close(vpninfo->ssl_fd);
		
			if (open_https(vpninfo)) {
				fprintf(stderr, "Failed to open HTTPS connection to %s\n",
					vpninfo->hostname);
				exit(1);
			}
			goto retry;
		}
		return -EINVAL;
	}

	if (strncmp(buf, "HTTP/1.1 200 ", 13)) {
		fprintf(stderr, "Got inappropriate HTTP CONNECT response: %s\n",
			buf);
		my_SSL_gets(vpninfo->https_ssl, buf, 65536);
		return -EINVAL;
	}

	if (verbose)
		printf("Got CONNECT response: %s\n", buf);

	/* We may have advertised it, but we only do it if the server agrees */
	vpninfo->deflate = 0;

	while ((i=my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		struct vpn_option *new_option;
		char *colon = strchr(buf, ':');
		if (!colon)
			continue;

		*colon = 0;
		colon++;
		if (*colon == ' ')
			colon++;

		if (strncmp(buf, "X-DTLS-", 7) &&
		    strncmp(buf, "X-CSTP-", 7))
			continue;

		new_option = malloc(sizeof(*new_option));
		if (!new_option) {
			fprintf(stderr, "No memory for allocation options\n");
			return -ENOMEM;
		}
		new_option->option = strdup(buf);
		new_option->value = strdup(colon);
		new_option->next = NULL;

		if (!new_option->option || !new_option->value) {
			fprintf(stderr, "No memory for allocation options\n");
			return -ENOMEM;
		}

		if (!strncmp(buf, "X-DTLS-", 7)) {
			*next_dtls_option = new_option;
			next_dtls_option = &new_option->next;
			continue;
		}
		/* CSTP options... */
		*next_cstp_option = new_option;
		next_cstp_option = &new_option->next;

		if (verbose)
			printf("DTLS option %s : %s\n", buf, colon);

		if (!strcmp(buf + 7, "Keepalive")) {
			vpninfo->ssl_times.keepalive = atol(colon);
		} else if (!strcmp(buf + 7, "DPD")) {
			vpninfo->ssl_times.dpd = atol(colon);
		} else if (!strcmp(buf + 7, "Content-Encoding")) {
			if (!strcmp(colon, "deflate"))
				vpninfo->deflate = 1;
			else {
				fprintf(stderr, 
					"Unknown CSTP-Content-Encoding %s\n",
					colon);
				return -EINVAL;
			}
		} else if (!strcmp(buf + 7, "MTU")) {
			vpninfo->mtu = atol(colon);
		} else if (!strcmp(buf + 7, "Address")) {
			vpninfo->vpn_addr = new_option->value;
		} else if (!strcmp(buf + 7, "Netmask")) {
			vpninfo->vpn_netmask = new_option->value;
		} else if (!strcmp(buf + 7, "DNS")) {
			int j;
			for (j = 0; j < 3; j++) {
				if (!vpninfo->vpn_dns[j]) {
					vpninfo->vpn_dns[j] = new_option->value;
					break;
				}
			}
		} else if (!strcmp(buf + 7, "NBNS")) {
			int j;
			for (j = 0; j < 3; j++) {
				if (!vpninfo->vpn_nbns[j]) {
					vpninfo->vpn_nbns[j] = new_option->value;
					break;
				}
			}
		} else if (!strcmp(buf + 7, "Default-Domain")) {
			vpninfo->vpn_domain = new_option->value;
		}
	}

	if (!vpninfo->vpn_addr) {
		fprintf(stderr, "No IP address received. Aborting\n");
		return -EINVAL;
	}
	if (!vpninfo->vpn_netmask)
		vpninfo->vpn_netmask = "255.255.255.255";
	if (verbose)
		printf("SSL connected. DPD %d, Keepalive %d\n",
		       vpninfo->ssl_times.dpd, vpninfo->ssl_times.keepalive);

	BIO_set_nbio(SSL_get_rbio(vpninfo->https_ssl),1);
	BIO_set_nbio(SSL_get_wbio(vpninfo->https_ssl),1);

	fcntl(vpninfo->ssl_fd, F_SETFL, fcntl(vpninfo->ssl_fd, F_GETFL) | O_NONBLOCK);
	vpninfo->ssl_pfd = vpn_add_pollfd(vpninfo, vpninfo->ssl_fd, POLLIN|POLLHUP|POLLERR);

	vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
	return 0;
}

int make_ssl_connection(struct anyconnect_info *vpninfo)
{
	if (!vpninfo->https_ssl && open_https(vpninfo))
		exit(1);

	if (vpninfo->deflate) {
		vpninfo->deflate_pkt = malloc(sizeof(struct pkt) + 2048);
		if (!vpninfo->deflate_pkt) {
			fprintf(stderr, "Allocation of deflate buffer failed\n");
			return -ENOMEM;
		}
		memset(vpninfo->deflate_pkt, 0, sizeof(struct pkt));
		memcpy(vpninfo->deflate_pkt->hdr, data_hdr, 8);
		vpninfo->deflate_pkt->hdr[6] = AC_PKT_COMPRESSED;
	}

	if (start_ssl_connection(vpninfo))
		exit(1);

	return 0;
}


void vpn_init_openssl(void)
{
	SSL_library_init ();
	ERR_clear_error ();
	SSL_load_error_strings ();
	OpenSSL_add_all_algorithms ();
}

static int inflate_and_queue_packet(struct anyconnect_info *vpninfo, int type, void *buf, int len)
{
	struct pkt *new = malloc(sizeof(struct pkt) + vpninfo->mtu);

	if (!new)
		return -ENOMEM;

	new->type = type;
	new->next = NULL;

	vpninfo->inflate_strm.next_in = buf;
	vpninfo->inflate_strm.avail_in = len - 4;

	vpninfo->inflate_strm.next_out = new->data;
	vpninfo->inflate_strm.avail_out = vpninfo->mtu;
	vpninfo->inflate_strm.total_out = 0;

	if (inflate(&vpninfo->inflate_strm, Z_SYNC_FLUSH)) {
		fprintf(stderr, "inflate failed\n");
		free(new);
		return -EINVAL;
	}

	new->len = vpninfo->inflate_strm.total_out;

	vpninfo->inflate_adler32 = adler32(vpninfo->inflate_adler32,
					   new->data, new->len);

	if (vpninfo->inflate_adler32 != ntohl( *(uint32_t *)(buf + len - 4))) {
		vpninfo->quit_reason = "Compression (inflate) adler32 failure";
	}

	if (verbose) {
		printf("Received compressed data packet of %ld bytes\n",
		       vpninfo->inflate_strm.total_out);
	}

	queue_packet(&vpninfo->incoming_queue, new);
	return 0;
}

static struct pkt keepalive_pkt = {
	.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_KEEPALIVE, 0 },
};

static struct pkt dpd_pkt = {
	.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_DPD_OUT, 0 },
};

static struct pkt dpd_resp_pkt = {
	.hdr = { 'S', 'T', 'F', 1, 0, 0, AC_PKT_DPD_RESP, 0 },
};

int ssl_mainloop(struct anyconnect_info *vpninfo, int *timeout)
{
	unsigned char buf[16384];
	int len, ret;
	int work_done = 0;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while ( (len = SSL_read(vpninfo->https_ssl, buf, sizeof(buf))) > 0) {
		int payload_len;

		if (buf[0] != 'S' || buf[1] != 'T' ||
		    buf[2] != 'F' || buf[3] != 1 || buf[7])
			goto unknown_pkt;

		payload_len = (buf[4] << 8) + buf[5];
		if (len != 8 + payload_len) {
			printf("Unexpected packet length. SSL_read returned %d but packet is\n",
			       len);
			printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			       buf[0], buf[1], buf[2], buf[3],
			       buf[4], buf[5], buf[6], buf[7]);
			continue;
		}
		vpninfo->ssl_times.last_rx = time(NULL);
		switch(buf[6]) {
		case AC_PKT_DPD_OUT:
			if (verbose)
				printf("Got CSTP DPD request\n");
			vpninfo->owe_ssl_dpd_response = 1;
			continue;

		case AC_PKT_DPD_RESP:
			if (verbose)
				printf("Got CSTP DPD response\n");
			continue;

		case AC_PKT_KEEPALIVE:
			if (verbose)
				printf("Got CSTP Keepalive\n");
			continue;

		case AC_PKT_DATA:
			if (verbose) {
				printf("Received uncompressed data packet of %d bytes\n",
				       payload_len);
			}
			queue_new_packet(&vpninfo->incoming_queue, AF_INET, buf + 8,
					 payload_len);
			work_done = 1;
			continue;

		case AC_PKT_COMPRESSED:
			if (!vpninfo->deflate) {
				fprintf(stderr, "Compressed packet received in !deflate mode\n");
				goto unknown_pkt;
			}
			inflate_and_queue_packet(vpninfo, AF_INET, buf + 8, payload_len);
			work_done = 1;
			continue;

		case AC_PKT_TERM_SERVER:
			fprintf(stderr, "received server terminate packet\n");
			vpninfo->quit_reason = "Server request";
			return 1;
		}

	unknown_pkt:
		printf("Unknown packet %02x %02x %02x %02x %02x %02x %02x %02x\n",
		       buf[0], buf[1], buf[2], buf[3],
		       buf[4], buf[5], buf[6], buf[7]);
		vpninfo->quit_reason = "Unknown packet received";
		return 1;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the 
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		vpninfo->pfds[vpninfo->ssl_pfd].events &= ~POLLOUT;
		ret = SSL_write(vpninfo->https_ssl,
				vpninfo->current_ssl_pkt->hdr,
				vpninfo->current_ssl_pkt->len + 8);
		if (ret <= 0) {
			ret = SSL_get_error(vpninfo->https_ssl, ret);
			switch (ret) {
			case SSL_ERROR_WANT_WRITE:
				/* Waiting for the socket to become writable -- it's
				   probably stalled, and/or the buffers are full */
				vpninfo->pfds[vpninfo->ssl_pfd].events |= POLLOUT;
			case SSL_ERROR_WANT_READ:
				if (ka_stalled_dpd_time(&vpninfo->ssl_times, timeout)) {
					vpninfo->quit_reason = "SSL DPD detected dead peer";
					return 1;
				}
				return work_done;
			default:
				fprintf(stderr, "SSL_write failed: %d", ret);
				ERR_print_errors_fp(stderr);
				vpninfo->quit_reason = "SSL write error";
				return 1;
			}
		}
		if (ret != vpninfo->current_ssl_pkt->len + 8) {
			fprintf(stderr, "SSL wrote too few bytes! Asked for %d, sent %d\n",
				vpninfo->current_ssl_pkt->len + 8, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt != vpninfo->deflate_pkt &&
		    vpninfo->current_ssl_pkt != &dpd_pkt &&
		    vpninfo->current_ssl_pkt != &dpd_resp_pkt &&
		    vpninfo->current_ssl_pkt != &keepalive_pkt)
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	if (vpninfo->owe_ssl_dpd_response) {
		vpninfo->owe_ssl_dpd_response = 0;
		vpninfo->current_ssl_pkt = &dpd_resp_pkt;
		goto handle_outgoing;
	}

	if (verbose)
		printf("Process CSTP keepalive...\n");
	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
		/* Not that this will ever happen; we don't even process
		   the setting when we're asked for it. */
		fprintf(stderr, "CSTP rekey due but we don't know how\n");
		time(&vpninfo->ssl_times.last_rekey);
		work_done = 1;
		break;

	case KA_DPD_DEAD:
		fprintf(stderr, "CSTP Dead Peer Detection detected dead peer!\n");
		vpninfo->quit_reason = "SSL DPD detected dead peer";
		/* FIXME: We should try to reconnect with the same cookie */
		return 1;

	case KA_DPD:
		if (verbose)
			printf("Send CSTP DPD\n");

		vpninfo->current_ssl_pkt = &dpd_pkt;
		goto handle_outgoing;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_fd == -1 && vpninfo->outgoing_queue)
			break;

		if (verbose)
			printf("Send CSTP Keepalive\n");

		vpninfo->current_ssl_pkt = &keepalive_pkt;
		goto handle_outgoing;

	case KA_NONE:
		;
	}

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_fd == -1 && vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		vpninfo->outgoing_queue = this->next;

		if (vpninfo->deflate) {
			unsigned char *adler;
			int ret;

			vpninfo->deflate_strm.next_in = this->data;
			vpninfo->deflate_strm.avail_in = this->len;
			vpninfo->deflate_strm.next_out = (void *)vpninfo->deflate_pkt->data;
			vpninfo->deflate_strm.avail_out = 2040;
			vpninfo->deflate_strm.total_out = 0;

			ret = deflate(&vpninfo->deflate_strm, Z_SYNC_FLUSH);
			if (ret) {
				fprintf(stderr, "deflate failed %d\n", ret);
				goto uncompr;
			}

			vpninfo->deflate_pkt->hdr[4] = (vpninfo->deflate_strm.total_out + 4) >> 8;
			vpninfo->deflate_pkt->hdr[5] = (vpninfo->deflate_strm.total_out + 4) & 0xff;

			/* Add ongoing adler32 to tail of compressed packet */
			vpninfo->deflate_adler32 = adler32(vpninfo->deflate_adler32,
							   this->data, this->len);

			adler = &vpninfo->deflate_pkt->data[vpninfo->deflate_strm.total_out];
			*(adler++) =  vpninfo->deflate_adler32 >> 24;
			*(adler++) = (vpninfo->deflate_adler32 >> 16) & 0xff;
			*(adler++) = (vpninfo->deflate_adler32 >> 8) & 0xff;
			*(adler)   =  vpninfo->deflate_adler32 & 0xff;

			vpninfo->deflate_pkt->len = vpninfo->deflate_strm.total_out + 4;

			if (verbose) {
				printf("Sending compressed data packet of %d bytes\n",
				       this->len);
			}
			vpninfo->current_ssl_pkt = vpninfo->deflate_pkt;
		} else {
		uncompr:
			memcpy(this->hdr, data_hdr, 8);
			this->hdr[4] = this->len >> 8;
			this->hdr[5] = this->len & 0xff;

			if (verbose) {
				printf("Sending uncompressed data packet of %d bytes\n",
				       this->len);
			}
			vpninfo->current_ssl_pkt = this;
		}
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int ssl_bye(struct anyconnect_info *vpninfo, char *reason)
{
	unsigned char *bye_pkt;
	int reason_len = strlen(reason);
	bye_pkt = malloc(reason_len + 8);
	if (!bye_pkt)
		return -ENOMEM;
	
	memcpy(bye_pkt, data_hdr, 8);
	memcpy(bye_pkt + 8, reason, strlen(reason));

	bye_pkt[4] = reason_len >> 8;
	bye_pkt[5] = reason_len & 0xff;
	bye_pkt[6] = 5;

	SSL_write(vpninfo->https_ssl, bye_pkt, reason_len + 8);
	free(bye_pkt);

	if (verbose)
		printf("Send BYE packet: %s\n", reason);

	return 0;
}
