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
#include <sys/socket.h>

struct pkt {
	int type;
	int len;
	struct pkt *next;
	unsigned char hdr[8];
	unsigned char data[];
};
	
struct vpn_option {
	char *option;
	char *value;
	struct vpn_option *next;
};

struct keepalive_info {
	int dpd;
	int keepalive;
	int rekey;
	time_t last_rekey;
	time_t last_tx;
	time_t last_rx;
	time_t last_dpd;
};

struct anyconnect_info {
	char *redirect_url;
	
	const char *localname;
	char *hostname;
	char *urlpath;
	const char *cert;
	const char *sslkey;
	int tpm;
	char *tpmpass;
	const char *cafile;
	const char *xmlconfig;
	char xmlsha1[(SHA_DIGEST_LENGTH * 2) + 1];
	char *username;

	const char *cookie;
	struct vpn_option *cookies;
	struct vpn_option *cstp_options;
	struct vpn_option *dtls_options;

	SSL_CTX *https_ctx;
	SSL *https_ssl;
	struct keepalive_info ssl_times;
	struct pkt *deflate_pkt;
	struct pkt *current_ssl_pkt;

	z_stream inflate_strm;
	uint32_t inflate_adler32;
	z_stream deflate_strm;
	uint32_t deflate_adler32;

	int trydtls;
	SSL_CTX *dtls_ctx;
	SSL *dtls_ssl;
	struct keepalive_info dtls_times;
	unsigned char dtls_session_id[32];
	unsigned char dtls_secret[48];

	char *vpnc_script;
	char *ifname;

	int mtu;
	const char *vpn_addr;
	const char *vpn_netmask;
	const char *vpn_dns[3];
	const char *vpn_nbns[3];
	const char *vpn_domain;

	struct pollfd *pfds;
	int nfds;
	int tun_fd;
	int ssl_fd;
	int dtls_fd;
	int ssl_pfd;
	int dtls_pfd;

	struct pkt *incoming_queue;
	struct pkt *outgoing_queue;

	socklen_t peer_addrlen;
	struct sockaddr *peer_addr;

	int deflate;
	const char *useragent;

	char *quit_reason;
};

/* Packet types */

#define AC_PKT_DATA		0	/* Uncompressed data */
#define AC_PKT_DPD_OUT		3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP		4	/* DPD response */
#define AC_PKT_DISCONN		5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE	7	/* Keepalive */
#define AC_PKT_COMPRESSED	8	/* Compressed data */
#define AC_PKT_TERM_SERVER	9	/* Server kick */


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
int  __attribute__ ((format (printf, 2, 3)))
		my_SSL_printf(SSL *ssl, const char *fmt, ...);
int my_SSL_gets(SSL *ssl, char *buf, size_t len);
int open_https(struct anyconnect_info *vpninfo);

/* main.c */
extern int verbose;

/* mainloop.c */
int vpn_add_pollfd(struct anyconnect_info *vpninfo, int fd, short events);
int vpn_mainloop(struct anyconnect_info *vpninfo);
int queue_new_packet(struct pkt **q, int type, void *buf, int len);
void queue_packet(struct pkt **q, struct pkt *new);

/* xml.c */
int config_lookup_host(struct anyconnect_info *vpninfo, const char *host);

/* http.c */
int process_http_response(struct anyconnect_info *vpninfo, int *result,
			  int (*header_cb)(struct anyconnect_info *, char *, char *),
			  char *body, int buf_len);
int obtain_cookie(struct anyconnect_info *vpninfo);
