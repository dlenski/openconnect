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

#include "anyconnect.h"

/* Helper functions for reading/writing lines over SSL.
   We could use cURL for the HTTP stuff, but it's overkill */

static int  __attribute__ ((format (printf, 2, 3)))
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

static int my_SSL_gets(SSL *ssl, char *buf, size_t len)
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

	buf[i] = 0;
	return i?:ret;
}



int open_https(struct anyconnect_info *vpninfo)
{
	SSL_METHOD *ssl3_method;
	SSL_CTX *https_ctx;
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

	ssl3_method = SSLv23_client_method();
	https_ctx = SSL_CTX_new(ssl3_method);
	https_ssl = SSL_new(https_ctx);
		
	https_bio = BIO_new_socket(ssl_sock, BIO_NOCLOSE);
	SSL_set_bio(https_ssl, https_bio, https_bio);

	if (SSL_connect(https_ssl) <= 0) {
		fprintf(stderr, "SSL connection failure\n");
		ERR_print_errors_fp(stderr);
		SSL_free(https_ssl);
		SSL_CTX_free(https_ctx);
		return -EINVAL;
	}

	vpninfo->ssl_fd = ssl_sock;
	vpninfo->https_ssl = https_ssl;
	return 0;
}


int start_ssl_connection(struct anyconnect_info *vpninfo)
{
	char buf[65536];
	int i;
	struct vpn_option **next_dtls_option = &vpninfo->dtls_options;
	struct vpn_option **next_cstp_option = &vpninfo->cstp_options;

	if (verbose)
		printf("Connected to HTTPS on %s\n", vpninfo->hostname);

	my_SSL_printf(vpninfo->https_ssl, "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n");
	my_SSL_printf(vpninfo->https_ssl, "Host: %s\r\n", vpninfo->hostname);
	my_SSL_printf(vpninfo->https_ssl, "User-Agent: %s\r\n", vpninfo->useragent);
	my_SSL_printf(vpninfo->https_ssl, "Cookie: webvpn=%s\r\n", vpninfo->cookie);
	my_SSL_printf(vpninfo->https_ssl, "X-CSTP-Version: 1\r\n");
	my_SSL_printf(vpninfo->https_ssl, "X-CSTP-Hostname: %s\r\n", vpninfo->localname);
	if (vpninfo->deflate)
		my_SSL_printf(vpninfo->https_ssl, "X-CSTP-Accept-Encoding: deflate;q=1.0\r\n");
	my_SSL_printf(vpninfo->https_ssl, "X-CSTP-MTU: %d\r\n", vpninfo->mtu);
	my_SSL_printf(vpninfo->https_ssl, "X-CSTP-Address-Type: IPv6,IPv4\r\n");
	my_SSL_printf(vpninfo->https_ssl, "X-DTLS-Master-Secret: ");
	for (i = 0; i < sizeof(vpninfo->dtls_secret); i++)
		my_SSL_printf(vpninfo->https_ssl, "%02X", vpninfo->dtls_secret[i]);
	my_SSL_printf(vpninfo->https_ssl, "\r\nX-DTLS-CipherSuite: AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA\r\n\r\n");

	if (my_SSL_gets(vpninfo->https_ssl, buf, 65536) < 0) {
		fprintf(stderr, "Error fetching HTTPS response\n");
		return -EINVAL;
	}

	if (verbose)
		printf("Got CONNECT response: %s\n", buf);

	if (strncmp(buf, "HTTP/1.1 200 ", 13)) {
		fprintf(stderr, "Got inappropriate HTTP CONNECT response: %s\n",
			buf);
		return -EINVAL;
	}


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

		if (!strcmp(buf, "X-CSTP-Keepalive"))
			vpninfo->ssl_keepalive = atol(colon);
		    
		if (!strncmp(buf, "X-DTLS-", 7)) {
			*next_dtls_option = new_option;
			next_dtls_option = &new_option->next;
		} else {
			*next_cstp_option = new_option;
			next_cstp_option = &new_option->next;
		}
	}

	if (verbose)
		printf("Connected!\n");

	BIO_set_nbio(SSL_get_rbio(vpninfo->https_ssl),1);
	BIO_set_nbio(SSL_get_wbio(vpninfo->https_ssl),1);

	fcntl(vpninfo->ssl_fd, F_SETFL, fcntl(vpninfo->ssl_fd, F_GETFL) | O_NONBLOCK);

	vpninfo->ssl_pfd = vpn_add_pollfd(vpninfo, vpninfo->ssl_fd, POLLIN);
	vpninfo->last_ssl_tx = time(NULL);
	return 0;
}

int make_ssl_connection(struct anyconnect_info *vpninfo)
{
	if (open_https(vpninfo))
		exit(1);

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

static char data_hdr[8] = {'S', 'T', 'F', 1, 0, 0, 0, 0};

int ssl_mainloop(struct anyconnect_info *vpninfo, int *timeout)
{
	unsigned char buf[16384];
	int len;
	int work_done = 0;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while ( (len = SSL_read(vpninfo->https_ssl, buf, sizeof(buf))) > 0) {

		if (buf[0] != 'S' || buf[1] != 'T' ||
		    buf[2] != 'F' || buf[3] != 1 || buf[7]) {
		unknown_pkt:
			printf("Unknown packet %02x %02x %02x %02x %02x %02x %02x %02x\n",
			       buf[0], buf[1], buf[2], buf[3],
			       buf[4], buf[5], buf[6], buf[7]);
			continue;
		}
		if (len != 8 + (buf[4] << 8) + buf[5]) {
			printf("Unexpected packet length. SSL_read returned %d but packet is\n",
			       len);
			printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			       buf[0], buf[1], buf[2], buf[3],
			       buf[4], buf[5], buf[6], buf[7]);
		}
		if (buf[6] == 4) {
			/* Keepalive response */
			if (verbose)
				printf("Got keepalive response\n");
			continue;
		}
		if (buf[6] != 0) /* Data */
			goto unknown_pkt;
		
		queue_new_packet(&vpninfo->incoming_queue, AF_INET, buf + 8,
				 (buf[4] << 8) + buf[5]);
		work_done = 1;
	}

	while (vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		vpninfo->outgoing_queue = this->next;
		memcpy(this->hdr, data_hdr, 8);
		this->hdr[4] = this->len >> 8;
		this->hdr[5] = this->len & 0xff;
		      
		SSL_write(vpninfo->https_ssl, this->hdr, this->len + 8);
		vpninfo->last_ssl_tx = time(NULL);
	}

	if (vpninfo->ssl_keepalive) {
		time_t now = time(NULL);
		time_t due = vpninfo->last_ssl_tx + vpninfo->ssl_keepalive;
		if (now >= due) {
			static unsigned char cstp_keepalive[8] = 
				{'S', 'T', 'F', 1, 0, 0, 3, 0};
		
			SSL_write(vpninfo->https_ssl, cstp_keepalive, 8);
			vpninfo->last_ssl_tx = now;
			due = now + vpninfo->ssl_keepalive;
			if (verbose)
				printf("Sent keepalive\n");
		}

		if (*timeout > (due - now) * 1000)
			*timeout = (due - now) * 1000;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}
