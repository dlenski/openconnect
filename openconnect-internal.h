/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
 * Copyright © 2013 John Morrissey <jwm@horde.net>
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

#define __OPENCONNECT_PRIVATE__

#include "openconnect.h"

#if defined(OPENCONNECT_OPENSSL) || defined(DTLS_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>
/* Ick */
#if OPENSSL_VERSION_NUMBER >= 0x00909000L
#define method_const const
#else
#define method_const
#endif
#endif /* OPENSSL */

#if defined(OPENCONNECT_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#ifdef HAVE_TROUSERS
#include <trousers/tss.h>
#include <trousers/trousers.h>
#endif
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

#ifdef HAVE_LIBSTOKEN
#include <stoken.h>
#endif

#ifdef ENABLE_NLS
#include <locale.h>
#include <libintl.h>
#define _(s) dgettext("openconnect", s)
#else
#define _(s) ((char *)(s))
#endif
#define N_(s) s

#include <libxml/tree.h>

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

struct pin_cache {
	struct pin_cache *next;
	char *token;
	char *pin;
};

#define RECONNECT_INTERVAL_MIN	10
#define RECONNECT_INTERVAL_MAX	100

#define CERT_TYPE_UNKNOWN	0
#define CERT_TYPE_PEM		1
#define CERT_TYPE_PKCS12	2
#define CERT_TYPE_TPM		3

#define REDIR_TYPE_NONE		0
#define REDIR_TYPE_NEWHOST	1
#define REDIR_TYPE_LOCAL	2

struct openconnect_info {
	char *redirect_url;
	int redirect_type;

	const char *csd_xmltag;
	const char *platname;
	char *csd_token;
	char *csd_ticket;
	char *csd_stuburl;
	char *csd_starturl;
	char *csd_waiturl;
	char *csd_preurl;

	char *csd_scriptname;
	xmlNode *opaque_srvdata;

#ifdef LIBPROXY_HDR
	pxProxyFactory *proxy_factory;
#endif
	char *proxy_type;
	char *proxy;
	int proxy_port;

	const char *localname;
	char *hostname;
	char *unique_hostname;
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
	char *authgroup;
	int nopasswd;
	int xmlpost;
	char *dtls_ciphers;
	uid_t uid_csd;
	char *csd_wrapper;
	int uid_csd_given;
	int no_http_keepalive;
	int dump_http_traffic;

	int token_mode;
	int token_bypassed;
	int token_tries;
	time_t token_time;
#ifdef HAVE_LIBSTOKEN
	struct stoken_ctx *stoken_ctx;
	char *stoken_pin;
#endif
#ifdef HAVE_LIBOATH
	char *oath_secret;
	size_t oath_secret_len;
#endif

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
	struct pin_cache *pin_cache;
#ifdef HAVE_TROUSERS
	TSS_HCONTEXT tpm_context;
	TSS_HKEY srk;
	TSS_HPOLICY srk_policy;
	TSS_HKEY tpm_key;
	TSS_HPOLICY tpm_key_policy;
#endif
#ifndef HAVE_GNUTLS_CERTIFICATE_SET_KEY
#ifdef HAVE_P11KIT
	gnutls_pkcs11_privkey_t my_p11key;
#endif
	gnutls_privkey_t my_pkey;
	gnutls_x509_crt_t *my_certs;
	uint8_t *free_my_certs;
	unsigned int nr_my_certs;
#endif
#endif /* OPENCONNECT_GNUTLS */
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
#if defined(DTLS_OPENSSL)
	SSL_CTX *dtls_ctx;
	SSL *dtls_ssl;
	SSL *new_dtls_ssl;
	SSL_SESSION *dtls_session;
#elif defined(DTLS_GNUTLS)
	/* Call these *_ssl rather than *_sess because they're just
	   pointers, and generic code (in mainloop.c for example)
	   wants to check if they're NULL or not. No point in being
	   differently named to the OpenSSL variant, and forcing us to
	   have ifdefs or accessor macros for them. */
	gnutls_session_t dtls_ssl;
	gnutls_session_t new_dtls_ssl;
#endif
	struct keepalive_info dtls_times;
	unsigned char dtls_session_id[32];
	unsigned char dtls_secret[48];

	char *dtls_cipher;
	const char *vpnc_script;
	int script_tun;
	char *ifname;

	int actual_mtu;
	int reqmtu, basemtu;
	const char *banner;
	const char *vpn_addr;
	const char *vpn_netmask;
	const char *vpn_addr6;
	const char *vpn_netmask6;
	const char *vpn_dns[3];
	const char *vpn_nbns[3];
	const char *vpn_domain;
	const char *vpn_proxy_pac;
	struct split_include *split_dns;
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

	int dtls_local_port;

	int deflate;
	char *useragent;

	const char *quit_reason;

	void *cbdata;
	openconnect_validate_peer_cert_vfn validate_peer_cert;
	openconnect_write_new_config_vfn write_new_config;
	openconnect_process_auth_form_vfn process_auth_form;
	openconnect_progress_vfn progress;
};

#if (defined(DTLS_OPENSSL) && defined(SSL_OP_CISCO_ANYCONNECT)) || \
    (defined(DTLS_GNUTLS) && defined(HAVE_GNUTLS_SESSION_SET_PREMASTER))
#define HAVE_DTLS 1
#endif

/* Packet types */

#define AC_PKT_DATA		0	/* Uncompressed data */
#define AC_PKT_DPD_OUT		3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP		4	/* DPD response */
#define AC_PKT_DISCONN		5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE	7	/* Keepalive */
#define AC_PKT_COMPRESSED	8	/* Compressed data */
#define AC_PKT_TERM_SERVER	9	/* Server kick */

#define vpn_progress(vpninfo, ...) (vpninfo)->progress((vpninfo)->cbdata, __VA_ARGS__)

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
#ifndef HAVE_STRCASESTR
#define strcasestr openconnect__strcasestr
char *openconnect__strcasestr(const char *haystack, const char *needle);
#endif

/* I always coded as if it worked like this. Now it does. */
#define realloc_inplace(p, size) do {			\
	void *__realloc_old = p;			\
	p = realloc(p, size);				\
	if (size && !p)					\
		free(__realloc_old);			\
    } while (0)

/****************************************************************************/

/* tun.c */
int setup_tun(struct openconnect_info *vpninfo);
int tun_mainloop(struct openconnect_info *vpninfo, int *timeout);
void shutdown_tun(struct openconnect_info *vpninfo);
int script_config_tun(struct openconnect_info *vpninfo, const char *reason);

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
int request_passphrase(struct openconnect_info *vpninfo, const char *label,
		       char **response, const char *fmt, ...);
int  __attribute__ ((format (printf, 2, 3)))
    openconnect_SSL_printf(struct openconnect_info *vpninfo, const char *fmt, ...);
int openconnect_print_err_cb(const char *str, size_t len, void *ptr);
#define openconnect_report_ssl_errors(v) ERR_print_errors_cb(openconnect_print_err_cb, (v))
#if defined(FAKE_ANDROID_KEYSTORE) || defined(__ANDROID__)
#define ANDROID_KEYSTORE
#endif
#ifdef ANDROID_KEYSTORE
const char *keystore_strerror(int err);
int keystore_fetch(const char *key, unsigned char **result);
#endif
void cmd_fd_set(struct openconnect_info *vpninfo, fd_set *fds, int *maxfd);
int is_cancel_pending(struct openconnect_info *vpninfo, fd_set *fds);

/* ${SSL_LIBRARY}.c */
int openconnect_SSL_gets(struct openconnect_info *vpninfo, char *buf, size_t len);
int openconnect_SSL_write(struct openconnect_info *vpninfo, char *buf, size_t len);
int openconnect_SSL_read(struct openconnect_info *vpninfo, char *buf, size_t len);
int openconnect_open_https(struct openconnect_info *vpninfo);
void openconnect_close_https(struct openconnect_info *vpninfo, int final);
int get_cert_md5_fingerprint(struct openconnect_info *vpninfo, OPENCONNECT_X509 *cert,
			     char *buf);
int openconnect_sha1(unsigned char *result, void *data, int len);
int openconnect_random(void *bytes, int len);
int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf);
#if defined(OPENCONNECT_OPENSSL)
#define openconnect_https_connected(_v) ((_v)->https_ssl)
#elif defined (OPENCONNECT_GNUTLS)
#define openconnect_https_connected(_v) ((_v)->https_sess)
#endif

/* mainloop.c */
int vpn_add_pollfd(struct openconnect_info *vpninfo, int fd, short events);
int vpn_mainloop(struct openconnect_info *vpninfo);
int queue_new_packet(struct pkt **q, void *buf, int len);
void queue_packet(struct pkt **q, struct pkt *new);
int keepalive_action(struct keepalive_info *ka, int *timeout);
int ka_stalled_action(struct keepalive_info *ka, int *timeout);

extern int killed;

/* xml.c */
int config_lookup_host(struct openconnect_info *vpninfo, const char *host);

/* auth.c */
int parse_xml_response(struct openconnect_info *vpninfo, char *response,
		       struct oc_auth_form **form, int *cert_rq);
int process_auth_form(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form);
int handle_auth_form(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		     char *request_body, int req_len, const char **method,
		     const char **request_body_type);
void free_auth_form(struct oc_auth_form *form);
int xmlpost_initial_req(struct openconnect_info *vpninfo, char *request_body, int req_len, int cert_fail);
int prepare_stoken(struct openconnect_info *vpninfo);

/* http.c */
char *openconnect_create_useragent(const char *base);
int process_proxy(struct openconnect_info *vpninfo, int ssl_sock);
int internal_parse_url(char *url, char **res_proto, char **res_host,
		       int *res_port, char **res_path, int default_port);

/* ssl_ui.c */
int set_openssl_ui(void);

/* version.c */
extern const char *openconnect_version_str;

#endif /* __OPENCONNECT_INTERNAL_H__ */
