/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
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
 */

#ifndef __OPENCONNECT_INTERNAL_H__
#define __OPENCONNECT_INTERNAL_H__

#define __OPENCONNECT_PRIVATE__

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32 1
#endif
#include <security.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#endif

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

#ifdef HAVE_ICONV
#include <langinfo.h>
#include <iconv.h>
#endif

#include <zlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef LIBPROXY_HDR
#include LIBPROXY_HDR
#endif

#ifdef HAVE_LIBSTOKEN
#include <stoken.h>
#endif

#ifdef HAVE_GSSAPI
#include GSSAPI_HDR
#endif

#ifdef HAVE_LIBPSKC
#include <pskc/pskc.h>
#endif

#ifdef ENABLE_NLS
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

#define REKEY_NONE      0
#define REKEY_TUNNEL    1
#define REKEY_SSL       2

#define KA_NONE		0
#define KA_DPD		1
#define KA_DPD_DEAD	2
#define KA_KEEPALIVE	3
#define KA_REKEY	4

#define DTLS_NOSECRET	0
#define DTLS_DISABLED	1
#define DTLS_SLEEPING	2
#define DTLS_CONNECTING	3
#define DTLS_CONNECTED	4

struct keepalive_info {
	int dpd;
	int keepalive;
	int rekey;
	int rekey_method;
	time_t last_rekey;
	time_t last_tx;
	time_t last_rx;
	time_t last_dpd;
};

struct pin_cache {
	struct pin_cache *next;
	char *token;
	char *pin;
};

struct oc_text_buf {
	char *data;
	int pos;
	int buf_len;
	int error;
};

#define RECONNECT_INTERVAL_MIN	10
#define RECONNECT_INTERVAL_MAX	100

#define REDIR_TYPE_NONE		0
#define REDIR_TYPE_NEWHOST	1
#define REDIR_TYPE_LOCAL	2

#define AUTH_TYPE_GSSAPI	0
#define AUTH_TYPE_NTLM		1
#define AUTH_TYPE_DIGEST	2
#define AUTH_TYPE_BASIC		3

#define MAX_AUTH_TYPES		4

#define AUTH_DISABLED		-2
#define AUTH_FAILED		-1	/* Failed */
#define AUTH_UNSEEN		0	/* Server has not offered it */
#define AUTH_AVAILABLE		1	/* Server has offered it, we have not tried it */
	/* Individual auth types may use 2 onwards for their own state */
#define AUTH_IN_PROGRESS	2	/* In-progress attempt */

struct proxy_auth_state {
	int state;
	char *challenge;
};

struct openconnect_info {
#ifdef HAVE_ICONV
	iconv_t ic_legacy_to_utf8;
	iconv_t ic_utf8_to_legacy;
#endif
	char *redirect_url;
	int redirect_type;

	const char *csd_xmltag;
	int csd_nostub;
	const char *platname;
	char *mobile_platform_version;
	char *mobile_device_type;
	char *mobile_device_uniqueid;
	char *csd_token;
	char *csd_ticket;
	char *csd_stuburl;
	char *csd_starturl;
	char *csd_waiturl;
	char *csd_preurl;

	char *csd_scriptname;
	xmlNode *opaque_srvdata;

	char *profile_url;
	char *profile_sha1;

#ifdef LIBPROXY_HDR
	pxProxyFactory *proxy_factory;
#endif
	char *proxy_type;
	char *proxy;
	int proxy_port;
	int proxy_fd;
	char *proxy_user;
	char *proxy_pass;
	int proxy_close_during_auth;
	struct proxy_auth_state auth[MAX_AUTH_TYPES];
#ifdef HAVE_GSSAPI
	gss_name_t gss_target_name;
	gss_ctx_id_t gss_context;
#endif
#ifdef _WIN32
	CredHandle ntlm_sspi_cred;
	CtxtHandle ntlm_sspi_ctx;
	CredHandle sspi_cred;
	CtxtHandle sspi_ctx;
	SEC_WCHAR *sspi_target_name;
#else
	int ntlm_helper_fd;
#endif
	int authmethods_set;

	char *localname;
	char *hostname;
	char *unique_hostname;
	int port;
	char *urlpath;
	int cert_expire_warning;
	const char *cert;
	const char *sslkey;
	char *cert_password;
	char *cafile;
	char *servercert;
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
	int stoken_concat_pin;
	int stoken_interval;
#endif
#ifdef HAVE_LIBPSKC
	pskc_t *pskc;
	pskc_key_t *pskc_key;
#endif
#ifdef HAVE_LIBOATH
	char *oath_secret;
	size_t oath_secret_len;
	enum {
		HOTP_SECRET_BASE32 = 1,
		HOTP_SECRET_RAW,
		HOTP_SECRET_HEX,
		HOTP_SECRET_PSKC,
	} hotp_secret_format; /* We need to give it back in the same form */
#endif
	openconnect_lock_token_vfn lock_token;
	openconnect_unlock_token_vfn unlock_token;
	void *tok_cbdata;

	OPENCONNECT_X509 *peer_cert;

	char *cookie; /* Pointer to within cookies list */
	struct oc_vpn_option *cookies;
	struct oc_vpn_option *cstp_options;
	struct oc_vpn_option *dtls_options;

	unsigned pfs;
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

	struct pkt *tun_pkt;

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
	SSL_SESSION *dtls_session;
#elif defined(DTLS_GNUTLS)
	/* Call this dtls_ssl rather than dtls_sess because it's just a
	   pointer, and generic code in dtls.c wants to check if it's
	   NULL or not or pass it to DTLS_SEND/DTLS_RECV. This way we
	   have fewer ifdefs and accessor macros for it. */
	gnutls_session_t dtls_ssl;
	char *gnutls_dtls_cipher; /* cached for openconnect_get_dtls_cipher() */
	char *gnutls_cstp_cipher;
#endif
	int dtls_state;
	struct keepalive_info dtls_times;
	unsigned char dtls_session_id[32];
	unsigned char dtls_secret[48];

	char *dtls_cipher;
	char *vpnc_script;
	int script_tun;
	char *ifname;

	int reqmtu, basemtu;
	const char *banner;

	struct oc_ip_info ip_info;

#ifdef _WIN32
	long dtls_monitored, ssl_monitored, cmd_monitored, tun_monitored;
	HANDLE dtls_event, ssl_event, cmd_event;
#else
	int _select_nfds;
	fd_set _select_rfds;
	fd_set _select_wfds;
	fd_set _select_efds;
#endif

#ifdef __sun__
	int ip_fd;
	int ip6_fd;
#endif
#ifdef _WIN32
	HANDLE tun_fh;
	OVERLAPPED tun_rd_overlap, tun_wr_overlap;
	int tun_rd_pending;
#else
	int tun_fd;
#endif
	int ssl_fd;
	int dtls_fd;

	int cmd_fd;
	int cmd_fd_write;
	int got_cancel_cmd;
	int got_pause_cmd;
	char cancel_type;

	struct pkt *incoming_queue;
	struct pkt *outgoing_queue;
	int outgoing_qlen;
	int max_qlen;
	struct oc_stats stats;
	openconnect_stats_vfn stats_handler;

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
	openconnect_protect_socket_vfn protect_socket;

	int (*ssl_read)(struct openconnect_info *vpninfo, char *buf, size_t len);
	int (*ssl_gets)(struct openconnect_info *vpninfo, char *buf, size_t len);
	int (*ssl_write)(struct openconnect_info *vpninfo, char *buf, size_t len);
};

#ifdef _WIN32
#define monitor_read_fd(_v, _n) _v->_n##_monitored |= FD_READ
#define monitor_write_fd(_v, _n) _v->_n##_monitored |= FD_WRITE
#define monitor_except_fd(_v, _n) _v->_n##_monitored |= FD_CLOSE
#define unmonitor_read_fd(_v, _n) _v->_n##_monitored &= ~FD_READ
#define unmonitor_write_fd(_v, _n) _v->_n##_monitored &= ~FD_WRITE
#define unmonitor_except_fd(_v, _n) _v->_n##_monitored &= ~FD_CLOSE

#define monitor_fd_new(_v, _n) do { if (!_v->_n##_event) _v->_n##_event = CreateEvent(NULL, FALSE, FALSE, NULL); } while (0)
#define read_fd_monitored(_v, _n) (_v->_n##_monitored & FD_READ)

#else
#define monitor_read_fd(_v, _n) FD_SET(_v-> _n##_fd, &vpninfo->_select_rfds)
#define unmonitor_read_fd(_v, _n) FD_CLR(_v-> _n##_fd, &vpninfo->_select_rfds)
#define monitor_write_fd(_v, _n) FD_SET(_v-> _n##_fd, &vpninfo->_select_wfds)
#define unmonitor_write_fd(_v, _n) FD_CLR(_v-> _n##_fd, &vpninfo->_select_wfds)
#define monitor_except_fd(_v, _n) FD_SET(_v-> _n##_fd, &vpninfo->_select_efds)
#define unmonitor_except_fd(_v, _n) FD_CLR(_v-> _n##_fd, &vpninfo->_select_efds)

#define monitor_fd_new(_v, _n) do { \
		if (_v->_select_nfds <= vpninfo->_n##_fd) \
			vpninfo->_select_nfds = vpninfo->_n##_fd + 1; \
	} while (0)

#define read_fd_monitored(_v, _n) FD_ISSET(_v->_n##_fd, &_v->_select_rfds)
#endif

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
#ifdef HAVE_SUNOS_BROKEN_TIME
#define time(x) openconnect__time(x)
time_t openconnect__time(time_t *t);
#endif
#ifndef HAVE_VASPRINTF
#define vasprintf openconnect__vasprintf
int openconnect__vasprintf(char **strp, const char *fmt, va_list ap);
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
#ifndef HAVE_STRNDUP
#undef strndup
#define strndup openconnect__strndup
char *openconnect__strndup(const char *s, size_t n);
#endif
#ifndef HAVE_SETENV
#define setenv openconnect__setenv
int openconnect__setenv(const char *name, const char *value, int overwrite);
#endif
#ifndef HAVE_UNSETENV
#define unsetenv openconnect__unsetenv
void openconnect__unsetenv(const char *name);
#endif

#ifndef HAVE_INET_ATON
#define inet_aton openconnect__inet_aton
int openconnect__inet_aton(const char *cp, struct in_addr *addr);
#endif

static inline int set_sock_nonblock(int fd)
{
#ifdef _WIN32
	unsigned long mode = 1;
	return ioctlsocket(fd, FIONBIO, &mode);
#else
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#endif
}
static inline int set_fd_cloexec(int fd)
{
#ifdef _WIN32
	return 0; /* Windows has O_INHERIT but... */
#else
	return fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

#ifdef _WIN32
#define pipe(fds) _pipe(fds, 4096, O_BINARY)
void openconnect__win32_sock_init();
#undef inet_pton
#define inet_pton openconnect__win32_inet_pton
int openconnect__win32_inet_pton(int af, const char *src, void *dst);
#define OPENCONNECT_CMD_SOCKET SOCKET
OPENCONNECT_CMD_SOCKET dumb_socketpair(OPENCONNECT_CMD_SOCKET socks[2], int make_overlapped);
#else
#define closesocket close
#define OPENCONNECT_CMD_SOCKET int
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif

/* For systems that don't support O_CLOEXEC, just don't bother.
   We don't keep files open for long anyway. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* I always coded as if it worked like this. Now it does. */
#define realloc_inplace(p, size) do {			\
	void *__realloc_old = p;			\
	p = realloc(p, size);				\
	if (size && !p)					\
		free(__realloc_old);			\
    } while (0)

/****************************************************************************/

/* iconv.c */
#ifdef HAVE_ICONV
char *openconnect_utf8_to_legacy(struct openconnect_info *vpninfo, const char *utf8);
char *openconnect_legacy_to_utf8(struct openconnect_info *vpninfo, const char *legacy);
#else
#define openconnect_utf8_to_legacy(v, str) ((char *)str)
#define openconnect_legacy_to_utf8(v, str) ((char *)str)
#endif

/* script.c */
int setenv_int(const char *opt, int value);
void set_script_env(struct openconnect_info *vpninfo);
int script_config_tun(struct openconnect_info *vpninfo, const char *reason);

/* tun.c / tun-win32.c */
void os_shutdown_tun(struct openconnect_info *vpninfo);
int os_read_tun(struct openconnect_info *vpninfo, struct pkt *pkt);
int os_write_tun(struct openconnect_info *vpninfo, struct pkt *pkt);
intptr_t os_setup_tun(struct openconnect_info *vpninfo);

/* dtls.c */
unsigned char unhex(const char *data);
int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout);
int dtls_try_handshake(struct openconnect_info *vpninfo);
int connect_dtls_socket(struct openconnect_info *vpninfo);
void dtls_close(struct openconnect_info *vpninfo);
void dtls_shutdown(struct openconnect_info *vpninfo);
int dtls_reconnect(struct openconnect_info *vpninfo);

/* cstp.c */
int cstp_mainloop(struct openconnect_info *vpninfo, int *timeout);
int cstp_bye(struct openconnect_info *vpninfo, const char *reason);
void cstp_free_splits(struct openconnect_info *vpninfo);

/* ssl.c */
unsigned string_is_hostname(const char* str);
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
void check_cmd_fd(struct openconnect_info *vpninfo, fd_set *fds);
int is_cancel_pending(struct openconnect_info *vpninfo, fd_set *fds);
void poll_cmd_fd(struct openconnect_info *vpninfo, int timeout);
int openconnect_open_utf8(struct openconnect_info *vpninfo,
			  const char *fname, int mode);
FILE *openconnect_fopen_utf8(struct openconnect_info *vpninfo,
			     const char *fname, const char *mode);

void openconnect_clear_cookies(struct openconnect_info *vpninfo);

/* {gnutls,openssl}.c */
int openconnect_open_https(struct openconnect_info *vpninfo);
void openconnect_close_https(struct openconnect_info *vpninfo, int final);
int cstp_handshake(struct openconnect_info *vpninfo, unsigned init);
int get_cert_md5_fingerprint(struct openconnect_info *vpninfo, OPENCONNECT_X509 *cert,
			     char *buf);
int openconnect_sha1(unsigned char *result, void *data, int len);
int openconnect_md5(unsigned char *result, void *data, int len);
int openconnect_random(void *bytes, int len);
int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf);
#if defined(OPENCONNECT_OPENSSL)
#define openconnect_https_connected(_v) ((_v)->https_ssl)
#elif defined (OPENCONNECT_GNUTLS)
#define openconnect_https_connected(_v) ((_v)->https_sess)
#endif

/* mainloop.c */
int tun_mainloop(struct openconnect_info *vpninfo, int *timeout);
int queue_new_packet(struct pkt **q, void *buf, int len);
void queue_packet(struct pkt **q, struct pkt *new);
int keepalive_action(struct keepalive_info *ka, int *timeout);
int ka_stalled_action(struct keepalive_info *ka, int *timeout);

/* xml.c */
ssize_t read_file_into_string(struct openconnect_info *vpninfo, const char *fname,
			      char **ptr);
int config_lookup_host(struct openconnect_info *vpninfo, const char *host);

/* oath.c */
int set_totp_mode(struct openconnect_info *vpninfo, const char *token_str);
int set_hotp_mode(struct openconnect_info *vpninfo, const char *token_str);
int can_gen_totp_code(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt);
int can_gen_hotp_code(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt);
int do_gen_totp_code(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form,
		     struct oc_form_opt *opt);
int do_gen_hotp_code(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form,
		     struct oc_form_opt *opt);

/* stoken.c */
int prepare_stoken(struct openconnect_info *vpninfo);
int set_libstoken_mode(struct openconnect_info *vpninfo, const char *token_str);
int can_gen_stoken_code(struct openconnect_info *vpninfo,
			struct oc_auth_form *form,
			struct oc_form_opt *opt);
int do_gen_stoken_code(struct openconnect_info *vpninfo,
		       struct oc_auth_form *form,
		       struct oc_form_opt *opt);

/* auth.c */
void nuke_opt_values(struct oc_form_opt *opt);
int parse_xml_response(struct openconnect_info *vpninfo, char *response,
		       struct oc_auth_form **form, int *cert_rq);
int process_auth_form(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form);
int handle_auth_form(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form,
		     struct oc_text_buf *request_body, const char **method,
		     const char **request_body_type);
void free_auth_form(struct oc_auth_form *form);
int xmlpost_initial_req(struct openconnect_info *vpninfo,
			struct oc_text_buf *request_body, int cert_fail);

/* http.c */
struct oc_text_buf *buf_alloc(void);
int buf_ensure_space(struct oc_text_buf *buf, int len);
void  __attribute__ ((format (printf, 2, 3)))
	buf_append(struct oc_text_buf *buf, const char *fmt, ...);
void buf_append_bytes(struct oc_text_buf *buf, const void *bytes, int len);
void buf_append_base64(struct oc_text_buf *buf, const void *bytes, int len);
int buf_append_utf16le(struct oc_text_buf *buf, const char *utf8);
void buf_append_from_utf16le(struct oc_text_buf *buf, const void *utf16);
void *openconnect_base64_decode(int *len, const char *in);
void buf_truncate(struct oc_text_buf *buf);
void buf_append_urlencoded(struct oc_text_buf *buf, char *str);
int buf_error(struct oc_text_buf *buf);
int buf_free(struct oc_text_buf *buf);
char *openconnect_create_useragent(const char *base);
void cleanup_proxy_auth(struct openconnect_info *vpninfo);
int process_proxy(struct openconnect_info *vpninfo, int ssl_sock);
int internal_parse_url(const char *url, char **res_proto, char **res_host,
		       int *res_port, char **res_path, int default_port);

/* ntlm.c */
int ntlm_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
void cleanup_ntlm_auth(struct openconnect_info *vpninfo);

/* gssapi.c */
int gssapi_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
void cleanup_gssapi_auth(struct openconnect_info *vpninfo);
int socks_gssapi_auth(struct openconnect_info *vpninfo);

/* digest.c */
int digest_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *buf);

/* version.c */
extern const char *openconnect_version_str;

#define STRDUP(res, arg) \
	if (arg) { \
		res = strdup(arg); \
		if (res == NULL) return -ENOMEM; \
	} else res = NULL

#define UTF8CHECK(arg) \
	if ((arg) && buf_append_utf16le(NULL, (arg))) { \
		vpn_progress(vpninfo, PRG_ERR,				\
			     _("ERROR: %s() called with invalid UTF-8 for '%s' argument\n"),\
			     __func__, #arg);				\
		return -EILSEQ;						\
	}

#define UTF8CHECK_VOID(arg) \
	if ((arg) && buf_append_utf16le(NULL, (arg))) { \
		vpn_progress(vpninfo, PRG_ERR,				\
			     _("ERROR: %s() called with invalid UTF-8 for '%s' argument\n"),\
			     __func__, #arg);				\
		return;							\
	}

#endif /* __OPENCONNECT_INTERNAL_H__ */
