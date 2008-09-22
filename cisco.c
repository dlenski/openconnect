#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "anyconnect.h"

/* The master-secret is generated randomly by the client. The server
   responds with a DTLS Session-ID. These are enough to 'resume' the DTLS
   session, bypassing all the initial setup of a normal DTLS connection.
   Or you can just send traffic over the HTTPS connection... */

char *cookie;
char *hostname;
unsigned char dtls_secret[48];
int mtu = 1406;
int deflate;
const char *useragent = "Open AnyConnect VPN Agent v0.01";
int verbose;

/* Set up a tuntap device. */
int setup_tun(struct cstp_option *options)
{
	struct ifreq ifr;
	int tun_fd;

	tun_fd = open("/dev/net/tun", O_RDWR);
	if (tun_fd == -1) {
		perror("open tun");
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, "cisco0", sizeof(ifr.ifr_name) - 1);
	if (ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0){
		perror("TUNSETIFF");
		exit(1);
	}
	/* FIXME: Configure it... */
	/* Better still, use lwip and just provide a SOCKS server rather than
	   telling the kernel at all */
	return tun_fd;
}


SSL *open_https(const char *host)
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

	err = getaddrinfo(host, "https", &hints, &result);
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
		fprintf(stderr, "Failed to connect to host %s\n", host);
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

struct cstp_option *start_ssl_connection(SSL *ssl)
{
	char buf[65536];
	int i;
	struct utsname utsbuf;
	struct cstp_option *options = NULL, **next_option = &options;

	if (uname(&utsbuf))
		printf(utsbuf.nodename, "localhost");

	if (verbose)
		printf("Connected to HTTPS on %s\n", hostname);

	my_SSL_printf(ssl, "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n");
	my_SSL_printf(ssl, "Host: %s\r\n", hostname);
	my_SSL_printf(ssl, "User-Agent: %s\r\n", useragent);
	my_SSL_printf(ssl, "Cookie: webvpn=%s\r\n", cookie);
	my_SSL_printf(ssl, "X-CSTP-Version: 1\r\n");
	my_SSL_printf(ssl, "X-CSTP-Hostname: %s\r\n", utsbuf.nodename);
	if (deflate)
		my_SSL_printf(ssl, "X-CSTP-Accept-Encoding: deflate;q=1.0\r\n");
	my_SSL_printf(ssl, "X-CSTP-MTU: %d\r\n", mtu);
	my_SSL_printf(ssl, "X-CSTP-Address-Type: IPv6,IPv4\r\n");
	my_SSL_printf(ssl, "X-DTLS-Master-Secret: ");
	for (i = 0; i < sizeof(dtls_secret); i++)
		my_SSL_printf(ssl, "%02X", dtls_secret[i]);
	my_SSL_printf(ssl, "\r\nX-DTLS-CipherSuite: AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA\r\n\r\n");

	if (my_SSL_gets(ssl, buf, 65536) < 0) {
		fprintf(stderr, "Error fetching HTTPS response\n");
		return NULL;
	}

	if (verbose)
		printf("Got CONNECT response: %s\n", buf);

	if (strncmp(buf, "HTTP/1.1 200 ", 13)) {
		fprintf(stderr, "Got inappropriate HTTP CONNECT response: %s\n",
			buf);
		return NULL;
	}


	while ((i=my_SSL_gets(ssl, buf, sizeof(buf)))) {
		char *colon = strchr(buf, ':');
		if (!colon)
			continue;

		*colon = 0;
		colon++;
		if (*colon == ' ')
			colon++;

		*next_option = malloc(sizeof(*options));
		(*next_option)->option = strdup(buf);
		(*next_option)->value = strdup(colon);
		(*next_option)->next = NULL;
		next_option = &(*next_option)->next;
	}

	if (verbose)
		printf("Connected!\n");
	return options;
}

static struct option long_options[] = {
	{"cookie", 1, 0, 'c'},
	{"host", 1, 0, 'h'},
	{"mtu", 1, 0, 'm'},
	{"verbose", 1, 0, 'v'},
	{"deflate", 1, 0, 'd'},
};

int main(int argc, char **argv)
{
	SSL *https_ssl;
	struct cstp_option *opts;
	int tun_fd;
	int optind;
	int opt;
	char buf[65536 + 8];

	SSL_library_init ();
	ERR_clear_error ();
	SSL_load_error_strings ();
	OpenSSL_add_all_algorithms ();

	while ((opt = getopt_long(argc, argv, "c:h:vd", long_options, &optind))) {
		if (opt < 0)
			break;

		switch (opt) {
		case 'c':
			cookie = optarg;
			break;

		case 'h':
			hostname = optarg;
			break;

		case 'm':
			mtu = atol(optarg);
			if (mtu < 576) {
				fprintf(stderr, "MTU %d too small\n", mtu);
				exit(1);
			}
			break;

		case 'v':
			verbose = 1;
			break;

		case 'd':
			fprintf(stderr, "Deflate not yet supported\n");
			//deflate = 1;
			break;
		}
	}
	if (!hostname || !cookie) {
		fprintf(stderr, "Need -h hostname, -c cookie\n");
		exit(1);
	}

	https_ssl = open_https(hostname);
	if (!https_ssl)
		exit(1);
	int i;
	for (i=0; i<48; i++) 
		dtls_secret[i] = i;

	opts = start_ssl_connection(https_ssl);

	while (opts) {
		printf ("Got opt %s, val %s\n", opts->option, opts->value);
		opts = opts->next;
	}
	exit(1);

	printf("Connected\n");

	tun_fd = setup_tun(NULL);

	if (fork()) {
		while (1) {
			size_t len;

			buf[0] = 'S';
			buf[1] = 'T';
			buf[2] = 'F';
			buf[3] = 1;
			buf[4] = 0;
			buf[5] = 0;
			buf[6] = 0;
			buf[7] = 0;
				
			len = read(tun_fd, &buf[8], 65536);
			if (len >= 0) {
				buf[4] = len >> 8;
				buf[5] = len & 0xff;
			}
			SSL_write(https_ssl, buf, len + 8);
		}
	} else {
		while (1) {
			int len;
			SSL_read(https_ssl, buf, 8);
			
			len = (buf[4] << 8) + buf [5];
			SSL_read(https_ssl, buf + 8, len);
			if (buf[0] != 'S' ||
			    buf[1] != 'T' ||
			    buf[2] != 'F' ||
			    buf[3] != 1 ||
			    buf[6] != 0 ||
			    buf[7] != 0) {
				printf("Unknown packet %02x %02x %02x %02x %02x %02x %02x %02x\n",
				       buf[0], buf[1], buf[2], buf[3],
				       buf[4], buf[5], buf[6], buf[7]);
			} else {
				write(tun_fd, buf + 8, len);
			}
		}
	}
}
