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
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define _GNU_SOURCE
#include <getopt.h>

#if 0
/* If the cookie expires, you can get another one by connecting with 
   the certificate:

openssl s_client -cert mycert.pem -connect vpnserver:443 -crlf
GET /+webvpn+/index.html HTTP/1.1
User-Agent: AnyConnect Linux 2.2.0133
Host: localhost
Accept: */*
Accept-Encoding: identity
X-Transcend-Version: 1

#endif

/* The master-secret is generated randomly by the client. The server
   responds with a DTLS Session-ID. These are enough to 'resume' the DTLS
   session, bypassing all the initial setup of a normal DTLS connection.
   Or you can just send traffic over the HTTPS connection... */

struct cstp_option {
	const char *option;
	const char *value;
	struct cstp_option *next;
};

char *cookie;
char *hostname;
unsigned char dtls_secret[48];
int mtu = 1406;
int deflate;
const char *useragent = "Cisco AnyConnect VPN Agent for Windows 2.2.0";
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
		BIO *err_bio = BIO_new_fp(stderr, BIO_NOCLOSE);
		fprintf(stderr,  "SSL connection failure\n");
		SSL_free(https_ssl);
		SSL_CTX_free(https_ctx);
		return NULL;
	}

	return https_ssl;
}

struct cstp_option *start_ssl_connection(SSL *ssl)
{
	char buf[65536];
	int i, state = 0;
	struct cstp_option *options = NULL, **next_opt = &options;
	struct utsname utsbuf;
	BIO *bio = BIO_new(BIO_f_ssl());
	
	BIO_set_ssl(bio, ssl, BIO_NOCLOSE);
	
	if (uname(&utsbuf))
		sprintf(utsbuf.nodename, "localhost");

	if (verbose)
		printf("Connected to HTTPS on %s\n", hostname);

	BIO_printf(bio, "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n");
	BIO_printf(bio, "Host: %s\r\n", hostname);
	BIO_printf(bio, "User-Agent: %S\r\n", useragent);
	BIO_printf(bio, "Cookie: webvpn=%s\r\n", cookie);
	BIO_printf(bio, "X-CSTP-Version: 1\r\n");
	BIO_printf(bio, "X-CSTP-Hostname: %s\r\n", utsbuf.nodename);
	if (deflate)
		BIO_printf(bio, "X-CSTP-Accept-Encoding: deflate;q=1.0\r\n");
	BIO_printf(bio, "X-CSTP-MTU: %d\r\n", mtu);
	BIO_printf(bio, "X-CSTP-Address-Type: IPv6,IPv4\r\n");
	BIO_printf(bio, "X-DTLS-Master-Secret: ");
	for (i = 0; i < sizeof(dtls_secret); i++)
		BIO_printf(bio, "%02X", dtls_secret[i]);
	BIO_printf(bio, "X-DTLS-CipherSuite: AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA\r\n\r\n");

	state = 0;
#if 0
	state = BIO_gets(bio, buf, sizeof(buf)-1);

	if (state <= 0) {
		fprintf(stderr, "Error getting HTTP CONNECT response: %d\n", state);
		BIO_free(bio);
		return NULL;
	}
	if (!strncmp(buf, "HTTP/1.1 200 ", 13)) {
		fprintf(stderr, "Got inappropriate HTTP CONNECT response: %s\n",
			buf);
		BIO_free(bio);
		return NULL;
	}

	while (BIO_gets(bio, buf, sizeof(buf)-1)) {
		char *colon = strchr(buf, ':');

		if (buf[strlen(buf)] == '\r') {
			printf("ends \\r\n");
			buf[strlen(buf)] = 0;
		}

		if (!strlen(buf))
			break;

		fprintf(stderr, "Got: %s\n", buf);
	}
#else
        while (state < 4) {
                SSL_read(ssl, buf, 1);
                if ((state == 0 || state == 2) &&
                    buf[0] == '\r')
                        state++;
                else if ((state == 1 || state == 3) &&
                    buf[0] == '\n')
                        state++;
                else state = 0;
                write(1, buf, 1);
        }
#endif
	return NULL;
}

static struct option long_options[] = {
	{"cookie", 1, 0, 'c'},
	{"host", 1, 0, 'h'},
	{"mtu", 1, 0, 'm'},
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

	while (opt = getopt_long(argc, argv, "c:h:", long_options, &optind)) {
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
