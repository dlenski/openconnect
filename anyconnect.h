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

#include <openssl/ssl.h>
#include <poll.h>
#include <zlib.h>
#include <stdint.h>

struct pkt {
	int type;
	int len;
	struct pkt *next;
	unsigned char data[];
};
	
struct vpn_option {
	const char *option;
	const char *value;
	struct vpn_option *next;
};

struct anyconnect_info {
	const char *localname;
	const char *hostname;
	const char *cert;

	const char *cookie;
	struct vpn_option *cstp_options;
	struct vpn_option *dtls_options;

	SSL_CTX *https_ctx;
	SSL *https_ssl;
	int ssl_keepalive;
	time_t last_ssl_tx;

	z_stream inflate_strm;
	uint32_t inflate_adler32;
	z_stream deflate_strm;
	uint32_t deflate_adler32;

	unsigned char dtls_secret[48];
	SSL_CTX *dtls_ctx;
	SSL *dtls_ssl;
	int ssl_pfd;

	int mtu;

	struct pollfd *pfds;
	int nfds;

	int tun_fd;
	int ssl_fd;
	int dtls_fd;

	struct pkt *incoming_queue;
	struct pkt *outgoing_queue;

	struct sockaddr *peer_addr;

	int deflate;
	const char *useragent;

	char *quit_reason;
};

/* tun.c */
int setup_tun(struct anyconnect_info *vpninfo);
int tun_mainloop(struct anyconnect_info *vpninfo, int *timeout);

/* dtls.c */
int setup_dtls(struct anyconnect_info *vpninfo);
int dtls_mainloop(struct anyconnect_info *vpninfo, int *timeout);

/* ssl.c */
int make_ssl_connection(struct anyconnect_info *vpninfo);
void vpn_init_openssl(void);
int ssl_mainloop(struct anyconnect_info *vpninfo, int *timeout);
int ssl_bye(struct anyconnect_info *vpninfo, char *reason);

/* main.c */
extern int verbose;

/* mainloop.c */
int vpn_add_pollfd(struct anyconnect_info *vpninfo, int fd, short events);
int vpn_mainloop(struct anyconnect_info *vpninfo);
int queue_new_packet(struct pkt **q, int type, void *buf, int len);
void queue_packet(struct pkt **q, struct pkt *new);
