/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
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

#ifndef __OPENCONNECT_INTERNAL_H__
#define __OPENCONNECT_INTERNAL_H__

#include "openconnect.h"

#if defined (OPENCONNECT_OPENSSL)
#include <openssl/ssl.h>
#elif defined (OPENCONNECT_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

#include <zlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef LIBPROXY_HDR
#include LIBPROXY_HDR
#endif

#ifdef ENABLE_NLS
#include <locale.h>
#include <libintl.h>
#define _(s) dgettext("openconnect", s)
#else
#define _(s) s
#endif
#define N_(s) s

#define SHA1_SIZE 20
#define MD5_SIZE 16

/****************************************************************************/

struct pkt {
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

#define CERT_TYPE_UNKNOWN	0
#define CERT_TYPE_PEM		1
#define CERT_TYPE_PKCS12	2
#define CERT_TYPE_TPM		3

struct openconnect_info {
	char *redirect_url;

	char *csd_token;
	char *csd_ticket;
	char *csd_stuburl;
	char *csd_starturl;
	char *csd_waiturl;
	char *csd_preurl;

	char *csd_scriptname;

#ifdef LIBPROXY_HDR
	pxProxyFactory *proxy_factory;
#endif
	char *proxy_type;
	char *proxy;
	int proxy_port;

	const char *localname;
	char *hostname;
	int port;
	char *urlpath;
	int cert_expire_warning;
	const char *cert;
	const char *sslkey;
	int cert_type;
	char *cert_password;
	const char *cafile;
	const char *servercert;
	const char *xmlconfig;
	char xmlsha1[(SHA1_SIZE * 2) + 1];
	char *username;
	char *password;
	char *authgroup;
	int nopasswd;
	char *dtls_ciphers;
	uid_t uid_csd;
	char *csd_wrapper;
	int uid_csd_given;
	int no_http_keepalive;

	OPENCONNECT_X509 *peer_cert;

	char *cookie; /* Pointer to within cookies list */
	struct vpn_option *cookies;
	struct vpn_option *cstp_options;
	struct vpn_option *dtls_options;

#if defined(OPENCONNECT_OPENSSL)
	X509 *cert_x509;
	SSL_CTX *https_ctx;
	SSL *https_ssl;
#elif defined(OPENCONNECT_GNUTLS)
	gnutls_session_t https_sess;
	gnutls_certificate_credentials_t https_cred;
#endif
	struct keepalive_info ssl_times;
	int owe_ssl_dpd_response;
	struct pkt *deflate_pkt;
	struct pkt *current_ssl_pkt;
	struct pkt *pending_deflated_pkt;

	z_stream inflate_strm;
	uint32_t inflate_adler32;
	z_stream deflate_strm;
	uint32_t deflate_adler32;

	int disable_ipv6;
	int reconnect_timeout;
	int reconnect_interval;
	int dtls_attempt_period;
	time_t new_dtls_started;
#if defined(OPENCONNECT_OPENSSL)
	SSL_CTX *dtls_ctx;
	SSL *dtls_ssl;
	SSL *new_dtls_ssl;
	SSL_SESSION *dtls_session;
#elif defined(OPENCONNECT_GNUTLS)
	/* FIXME */
#endif
	struct keepalive_info dtls_times;
	unsigned char dtls_session_id[32];
	unsigned char dtls_secret[48];

	char *dtls_cipher;
	const char *vpnc_script;
	int script_tun;
	char *ifname;

	int mtu;
	const char *banner;
	const char *vpn_addr;
	const char *vpn_netmask;
	const char *vpn_addr6;
	const char *vpn_netmask6;
	const char *vpn_dns[3];
	const char *vpn_nbns[3];
	const char *vpn_domain;
	const char *vpn_proxy_pac;
	struct split_include *split_includes;
	struct split_include *split_excludes;

	int select_nfds;
	fd_set select_rfds;
	fd_set select_wfds;
	fd_set select_efds;

#ifdef __sun__
	int ip_fd;
	int ip6_fd;
#endif
	int tun_fd;
	int ssl_fd;
	int dtls_fd;
	int new_dtls_fd;
	int cancel_fd;

	struct pkt *incoming_queue;
	struct pkt *outgoing_queue;
	int outgoing_qlen;
	int max_qlen;

	socklen_t peer_addrlen;
	struct sockaddr *peer_addr;
	struct sockaddr *dtls_addr;

	int deflate;
	char *useragent;

	const char *quit_reason;

	void *cbdata;
	openconnect_validate_peer_cert_vfn validate_peer_cert;
	openconnect_write_new_config_vfn write_new_config;
	openconnect_process_auth_form_vfn process_auth_form;
	openconnect_progress_vfn progress;
};

/* Packet types */

#define AC_PKT_DATA		0	/* Uncompressed data */
#define AC_PKT_DPD_OUT		3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP		4	/* DPD response */
#define AC_PKT_DISCONN		5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE	7	/* Keepalive */
#define AC_PKT_COMPRESSED	8	/* Compressed data */
#define AC_PKT_TERM_SERVER	9	/* Server kick */

/* Ick */
#if OPENSSL_VERSION_NUMBER >= 0x00909000L
#define method_const const
#else
#define method_const
#endif

#define vpn_progress(vpninfo, ...) (vpninfo)->progress ((vpninfo)->cbdata, __VA_ARGS__)

/****************************************************************************/
/* Oh Solaris how we hate thee! */
#ifdef __sun__
#define time(x) openconnect__time(x)
time_t openconnect__time(time_t *t);
#endif
#ifndef HAVE_ASPRINTF
#define asprintf openconnect__asprintf
int openconnect__asprintf(char **strp, const char *fmt, ...);
#endif
#ifndef HAVE_GETLINE
#define getline openconnect__getline
ssize_t openconnect__getline(char **lineptr, size_t *n, FILE *stream);
#endif

/****************************************************************************/

/* tun.c */
int setup_tun(struct openconnect_info *vpninfo);
int tun_mainloop(struct openconnect_info *vpninfo, int *timeout);
void shutdown_tun(struct openconnect_info *vpninfo);
int script_config_tun (struct openconnect_info *vpninfo, const char *reason);

/* dtls.c */
unsigned char unhex(const char *data);
int setup_dtls(struct openconnect_info *vpninfo);
int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout);
int dtls_try_handshake(struct openconnect_info *vpninfo);
int connect_dtls_socket(struct openconnect_info *vpninfo);

/* cstp.c */
int make_cstp_connection(struct openconnect_info *vpninfo);
int cstp_mainloop(struct openconnect_info *vpninfo, int *timeout);
int cstp_bye(struct openconnect_info *vpninfo, const char *reason);
int cstp_reconnect(struct openconnect_info *vpninfo);

/* ssl.c */
int connect_https_socket(struct openconnect_info *vpninfo);
int request_passphrase(struct openconnect_info *vpninfo,
		       char **response, const char *fmt, ...);
int  __attribute__ ((format (printf, 2, 3)))
    openconnect_SSL_printf(struct openconnect_info *vpninfo, const char *fmt, ...);

/* ${SSL_LIBRARY}.c */
int openconnect_SSL_gets(struct openconnect_info *vpninfo, char *buf, size_t len);
int openconnect_SSL_write(struct openconnect_info *vpninfo, char *buf, size_t len);
int openconnect_SSL_read(struct openconnect_info *vpninfo, char *buf, size_t len);
int openconnect_open_https(struct openconnect_info *vpninfo);
void openconnect_close_https(struct openconnect_info *vpninfo);
int get_cert_md5_fingerprint(struct openconnect_info *vpninfo, OPENCONNECT_X509 *cert,
			     char *buf);
/* This one is actually OpenSSL-specific */
void openconnect_report_ssl_errors(struct openconnect_info *vpninfo);
int openconnect_sha1(unsigned char *result, void *data, int len);
int openconnect_random(void *bytes, int len);
int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf);

/* mainloop.c */
int vpn_add_pollfd(struct openconnect_info *vpninfo, int fd, short events);
int vpn_mainloop(struct openconnect_info *vpninfo);
int queue_new_packet(struct pkt **q, void *buf, int len);
void queue_packet(struct pkt **q, struct pkt *new);
int keepalive_action(struct keepalive_info *ka, int *timeout);
int ka_stalled_dpd_time(struct keepalive_info *ka, int *timeout);

extern int killed;

/* xml.c */
int config_lookup_host(struct openconnect_info *vpninfo, const char *host);

/* auth.c */
int parse_xml_response(struct openconnect_info *vpninfo, char *response,
		       char *request_body, int req_len, const char **method,
		       const char **request_body_type);

/* http.c */
char *openconnect_create_useragent(const char *base);
int process_proxy(struct openconnect_info *vpninfo, int ssl_sock);
int internal_parse_url(char *url, char **res_proto, char **res_host,
		       int *res_port, char **res_path, int default_port);

/* ssl_ui.c */
int set_openssl_ui(void);

/* securid.c */
int generate_securid_tokencodes(struct openconnect_info *vpninfo);
int add_securid_pin(char *token, char *pin);

/* version.c */
extern const char *openconnect_version_str;

#endif /* __OPENCONNECT_INTERNAL_H__ */
