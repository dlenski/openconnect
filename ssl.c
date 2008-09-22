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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "anyconnect.h"

SSL *open_https(struct anyconnect_info *vpninfo)
{
	SSL_METHOD *ssl3_method;
	SSL_CTX *https_ctx;
	SSL *https_ssl;
	BIO *https_bio;
	int ssl_sock;
	int err;
	struct addrinfo hints, *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	err = getaddrinfo(vpninfo->hostname, "https", &hints, &result);
	if (err) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(err));
		return NULL;
	}

	for (rp = result; rp ; rp = rp->ai_next) {
		ssl_sock = socket(rp->ai_family, rp->ai_socktype,
				  rp->ai_protocol);
		if (ssl_sock < 0)
			continue;

		if (connect(ssl_sock, rp->ai_addr, rp->ai_addrlen) >= 0)
			break;

		close(ssl_sock);
	}
	freeaddrinfo(result);

	if (!rp) {
		fprintf(stderr, "Failed to connect to host %s\n", vpninfo->hostname);
		return NULL;
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
		return NULL;
	}

	return https_ssl;
}


int  __attribute__ ((format (printf, 2, 3))) my_SSL_printf(SSL *ssl, const char *fmt, ...) 
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

	buf[i] = 0;
	return i?:ret;
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
	return 0;
}

int make_ssl_connection(struct anyconnect_info *vpninfo)
{
	SSL *https_ssl = open_https(vpninfo);
	if (!https_ssl)
		exit(1);

	vpninfo->https_ssl = https_ssl;
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
