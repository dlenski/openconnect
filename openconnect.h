/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */

#ifndef __OPENCONNECT_ANYCONNECT_H
#define __OPENCONNECT_ANYCONNECT_H

#include <openssl/ssl.h>
#include <zlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

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

#define KA_NONE		0
#define KA_DPD		1
#define KA_DPD_DEAD	2
#define KA_KEEPALIVE	3
#define KA_REKEY	4

struct keepalive_info {
	int dpd;
	int keepalive;
	int rekey;
	time_t last_rekey;
	time_t last_tx;
	time_t last_rx;
	time_t last_dpd;
};

struct split_include {
	char *route;
	struct split_include *next;
};

#define RECONNECT_INTERVAL_MIN	10
#define RECONNECT_INTERVAL_MAX	100

struct openconnect_info {
	char *redirect_url;

	char *vpn_name;

	char sid_tokencode[9];
	char sid_nexttokencode[9];

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
	char *password;
	int nopasswd;

	char *cookie;
	struct vpn_option *cookies;
	struct vpn_option *cstp_options;
	struct vpn_option *dtls_options;

	SSL_CTX *https_ctx;
	SSL *https_ssl;
	struct keepalive_info ssl_times;
	int owe_ssl_dpd_response;
	struct pkt *deflate_pkt;
	struct pkt *current_ssl_pkt;

	z_stream inflate_strm;
	uint32_t inflate_adler32;
	z_stream deflate_strm;
	uint32_t deflate_adler32;

	int reconnect_timeout;
	int reconnect_interval;
	int dtls_attempt_period;
	time_t new_dtls_started;
	SSL_CTX *dtls_ctx;
	SSL *dtls_ssl;
	SSL *new_dtls_ssl;
	SSL_SESSION *dtls_session;
	struct keepalive_info dtls_times;
	unsigned char dtls_session_id[32];
	unsigned char dtls_secret[48];

	char *dtls_cipher;
	char *vpnc_script;
	int script_tun;
	char *ifname;

	int mtu;
	const char *vpn_addr;
	const char *vpn_netmask;
	const char *vpn_dns[3];
	const char *vpn_nbns[3];
	const char *vpn_domain;
	struct split_include *split_includes;

	int select_nfds;
	fd_set select_rfds;
	fd_set select_wfds;
	fd_set select_efds;

	int tun_fd;
	int ssl_fd;
	int dtls_fd;
	int new_dtls_fd;

	struct pkt *incoming_queue;
	struct pkt *outgoing_queue;
	int outgoing_qlen;
	int max_qlen;

	socklen_t peer_addrlen;
	struct sockaddr *peer_addr;

	int deflate;
	const char *useragent;

	char *quit_reason;

	int (*validate_peer_cert) (struct openconnect_info *vpninfo, X509 *cert);
	int (*write_new_config) (struct openconnect_info *vpninfo, char *buf, int buflen);

	void __attribute__ ((format(printf, 3, 4)))
	(*progress) (struct openconnect_info *vpninfo, int level, const char *fmt, ...);
};

#define PRG_ERR		0
#define PRG_INFO	1
#define PRG_DEBUG	2
#define PRG_TRACE	3

/* Packet types */

#define AC_PKT_DATA		0	/* Uncompressed data */
#define AC_PKT_DPD_OUT		3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP		4	/* DPD response */
#define AC_PKT_DISCONN		5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE	7	/* Keepalive */
#define AC_PKT_COMPRESSED	8	/* Compressed data */
#define AC_PKT_TERM_SERVER	9	/* Server kick */

/****************************************************************************/

/* Authentication form processing */

#define OC_FORM_OPT_TEXT	1
#define OC_FORM_OPT_PASSWORD	2
#define OC_FORM_OPT_SELECT	3
#define OC_FORM_OPT_HIDDEN	4

/* char * fields are static (owned by XML parser) and don't need to be
   freed by the form handling code -- except for value, which for TEXT
   and PASSWORD options is allocated by process_form() when
   interacting with the user and must be freed. */
struct oc_form_opt {
	struct oc_form_opt *next;
	int type;
	char *name;
	char *label;
	char *value;
};

/* All fields are static, owned by the XML parser */
struct oc_choice {
	char *name;
	char *label;
	char *auth_type;
	char *override_name;
	char *override_label;
};

struct oc_form_opt_select {
	struct oc_form_opt form;
	int nr_choices;
	struct oc_choice choices[0];
};

/* All char * fields are static, owned by the XML parser */
struct oc_auth_form {
	char *banner;
	char *message;
	char *error;
	char *auth_id;
	char *method;
	char *action;
	struct oc_form_opt *opts;
};

/****************************************************************************/

/* tun.c */
int setup_tun(struct openconnect_info *vpninfo);
int tun_mainloop(struct openconnect_info *vpninfo, int *timeout);

/* dtls.c */
int setup_dtls(struct openconnect_info *vpninfo);
int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout);
int dtls_try_handshake(struct openconnect_info *vpninfo);
int connect_dtls_socket(struct openconnect_info *vpninfo);

/* cstp.c */
int make_cstp_connection(struct openconnect_info *vpninfo);
int cstp_mainloop(struct openconnect_info *vpninfo, int *timeout);
int cstp_bye(struct openconnect_info *vpninfo, char *reason);

/* ssl.c */
void openconnect_init_openssl(void);
int  __attribute__ ((format (printf, 2, 3)))
		openconnect_SSL_printf(SSL *ssl, const char *fmt, ...);
int openconnect_SSL_gets(SSL *ssl, char *buf, size_t len);
int openconnect_open_https(struct openconnect_info *vpninfo);
void openconnect_close_https(struct openconnect_info *vpninfo);

/* mainloop.c */
int vpn_add_pollfd(struct openconnect_info *vpninfo, int fd, short events);
int vpn_mainloop(struct openconnect_info *vpninfo);
int queue_new_packet(struct pkt **q, int type, void *buf, int len);
void queue_packet(struct pkt **q, struct pkt *new);
int keepalive_action(struct keepalive_info *ka, int *timeout);
int ka_stalled_dpd_time(struct keepalive_info *ka, int *timeout);

extern int killed;

/* xml.c */
int config_lookup_host(struct openconnect_info *vpninfo, const char *host);

/* auth.c */
int parse_xml_response(struct openconnect_info *vpninfo, char *response,
		       char *request_body, int req_len);

/* http.c */
int openconnect_obtain_cookie(struct openconnect_info *vpninfo);
char *openconnect_create_useragent(char *base);

/* ssl_ui.c */
int set_openssl_ui(void);

/* securid.c */
int generate_securid_tokencodes(struct openconnect_info *vpninfo);
int add_securid_pin(char *token, char *pin);

/* version.c */
extern char openconnect_version[];

#endif /* __OPENCONNECT_ANYCONNECT_H */
