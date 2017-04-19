/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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

#if defined(OPENCONNECT_OPENSSL)
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
#include <gnutls/crypto.h>
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
#include <string.h>

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

#ifdef HAVE_LIBP11
#include <libp11.h>
#endif

#ifdef HAVE_LIBPCSCLITE
#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif
#endif

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(s) dgettext("openconnect", s)
#else
#define _(s) ((char *)(s))
#endif
#define N_(s) s

#include <libxml/tree.h>

#define SHA256_SIZE 32
#define SHA1_SIZE 20
#define MD5_SIZE 16

/* FreeBSD provides this in <sys/param.h>  */
#ifndef MAX
#define MAX(x,y) ((x)>(y))?(x):(y)
#endif
/****************************************************************************/

struct pkt {
	int len;
	struct pkt *next;
	union {
		struct {
			uint32_t spi;
			uint32_t seq;
			unsigned char iv[16];
			unsigned char payload[];
		} esp;
		struct {
			unsigned char pad[2];
			unsigned char rec[2];
			unsigned char kmp[20];
		} oncp;
		struct {
			unsigned char pad[16];
			unsigned char hdr[8];
		} cstp;
	};
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

#define DTLS_NOSECRET	0	/* Random secret has not been generated yet */
#define DTLS_SECRET	1	/* Secret is present, ready to attempt DTLS */
#define DTLS_DISABLED	2	/* DTLS was disabled on the *client* side */
#define DTLS_SLEEPING	3	/* For ESP, sometimes sending probes */
#define DTLS_CONNECTING	4	/* ESP probe received; must tell server */
#define DTLS_CONNECTED	5	/* Server informed and should be sending ESP */

#define COMPR_DEFLATE	(1<<0)
#define COMPR_LZS	(1<<1)
#define COMPR_LZ4	(1<<2)
#define COMPR_MAX	COMPR_LZ4

#ifdef HAVE_LZ4
#define COMPR_STATELESS	(COMPR_LZS | COMPR_LZ4)
#else
#define COMPR_STATELESS	(COMPR_LZS)
#endif
#define COMPR_ALL	(COMPR_STATELESS | COMPR_DEFLATE)

#define DTLS_APP_ID_EXT 48018

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

#define AUTH_DEFAULT_DISABLED	-3
#define AUTH_DISABLED		-2
#define AUTH_FAILED		-1	/* Failed */
#define AUTH_UNSEEN		0	/* Server has not offered it */
#define AUTH_AVAILABLE		1	/* Server has offered it, we have not tried it */
	/* Individual auth types may use 2 onwards for their own state */
#define AUTH_IN_PROGRESS	2	/* In-progress attempt */

struct http_auth_state {
	int state;
	char *challenge;
	union {
#ifdef HAVE_GSSAPI
		struct {
			gss_name_t gss_target_name;
			gss_ctx_id_t gss_context;
		};
#endif
#ifdef _WIN32
		struct {
			CredHandle ntlm_sspi_cred;
			CtxtHandle ntlm_sspi_ctx;
		};
		struct {
			CredHandle sspi_cred;
			CtxtHandle sspi_ctx;
			SEC_WCHAR *sspi_target_name;
		};
#else
		struct {
			int ntlm_helper_fd;
		};
#endif
	};
};

struct vpn_proto {
	const char *name;
	const char *pretty_name;
	const char *description;
	unsigned int flags;
	int (*vpn_close_session)(struct openconnect_info *vpninfo, const char *reason);

	/* This does the full authentication, calling back as appropriate */
	int (*obtain_cookie)(struct openconnect_info *vpninfo);

	/* Establish the TCP connection (and obtain configuration) */
	int (*tcp_connect)(struct openconnect_info *vpninfo);

	int (*tcp_mainloop)(struct openconnect_info *vpninfo, int *timeout);

	/* Add headers common to each HTTP request */
	void (*add_http_headers)(struct openconnect_info *vpninfo, struct oc_text_buf *buf);

	/* Set up the UDP (DTLS) connection. Doesn't actually *start* it. */
	int (*udp_setup)(struct openconnect_info *vpninfo, int attempt_period);

	/* This will actually complete the UDP connection setup/handshake on the wire,
	   as well as transporting packets */
	int (*udp_mainloop)(struct openconnect_info *vpninfo, int *timeout);

	/* Close the connection but leave the session setup so it restarts */
	void (*udp_close)(struct openconnect_info *vpninfo);

	/* Close and destroy the (UDP) session */
	void (*udp_shutdown)(struct openconnect_info *vpninfo);
};

struct pkt_q {
	struct pkt *head;
	struct pkt **tail;
	int count;
};

static inline struct pkt *dequeue_packet(struct pkt_q *q)
{
	struct pkt *ret = q->head;

	if (ret) {
		q->head = ret->next;
		if (!--q->count)
			q->tail = &q->head;
	}
	return ret;
}

static inline void requeue_packet(struct pkt_q *q, struct pkt *p)
{
	p->next = q->head;
	q->head = p;
	if (!q->count++)
		q->tail = &p->next;
}

static inline int queue_packet(struct pkt_q *q, struct pkt *p)
{
	*(q->tail) = p;
	p->next = NULL;
	q->tail = &p->next;
	return ++q->count;
}

static inline void init_pkt_queue(struct pkt_q *q)
{
	q->tail = &q->head;
}

#define DTLS_OVERHEAD (1 /* packet + header */ + 13 /* DTLS header */ + \
	 20 /* biggest supported MAC (SHA1) */ +  16 /* biggest supported IV (AES-128) */ + \
	 16 /* max padding */)

struct esp {
#if defined(OPENCONNECT_GNUTLS)
	gnutls_cipher_hd_t cipher;
	gnutls_hmac_hd_t hmac;
#elif defined(OPENCONNECT_OPENSSL)
	HMAC_CTX *hmac, *pkt_hmac;
	EVP_CIPHER_CTX *cipher;
#endif
	uint64_t seq_backlog;
	uint64_t seq;
	uint32_t spi; /* Stored network-endian */
	unsigned char secrets[0x40];
};

struct openconnect_info {
	const struct vpn_proto *proto;

#ifdef HAVE_ICONV
	iconv_t ic_legacy_to_utf8;
	iconv_t ic_utf8_to_legacy;
#endif
	char *redirect_url;
	int redirect_type;

	unsigned char esp_hmac;
	unsigned char esp_enc;
	unsigned char esp_compr;
	uint32_t esp_replay_protect;
	uint32_t esp_lifetime_bytes;
	uint32_t esp_lifetime_seconds;
	uint32_t esp_ssl_fallback;
	int current_esp_in;
	int old_esp_maxseq;
	struct esp esp_in[2];
	struct esp esp_out;

	int tncc_fd; /* For Juniper TNCC */
	const char *csd_xmltag;
	int csd_nostub;
	char *platname;
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
	int retry_on_auth_fail;
	int try_http_auth;
	struct http_auth_state http_auth[MAX_AUTH_TYPES];
	struct http_auth_state proxy_auth[MAX_AUTH_TYPES];

	char *localname;
	char *hostname;
	char *unique_hostname;
	int port;
	char *urlpath;
	int cert_expire_warning;
	char *cert;
	char *sslkey;
	char *cert_password;
	char *cafile;
	unsigned no_system_trust;
	const char *xmlconfig;
	char xmlsha1[(SHA1_SIZE * 2) + 1];
	char *authgroup;
	int nopasswd;
	int xmlpost;
	char *dtls_ciphers;
	char *csd_wrapper;
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
	char *oath_secret;
	size_t oath_secret_len;
	enum {
		OATH_ALG_HMAC_SHA1 = 0,
		OATH_ALG_HMAC_SHA256,
		OATH_ALG_HMAC_SHA512,
	} oath_hmac_alg;
	enum {
		HOTP_SECRET_BASE32 = 1,
		HOTP_SECRET_RAW,
		HOTP_SECRET_HEX,
		HOTP_SECRET_PSKC,
	} hotp_secret_format; /* We need to give it back in the same form */
#ifdef HAVE_LIBPCSCLITE
	SCARDHANDLE pcsc_ctx, pcsc_card;
	char *yubikey_objname;
	unsigned char yubikey_pwhash[16];
	int yubikey_pw_set;
	int yubikey_mode;
#endif
	openconnect_lock_token_vfn lock_token;
	openconnect_unlock_token_vfn unlock_token;
	void *tok_cbdata;

	void *peer_cert;
	char *peer_cert_sha1;
	char *peer_cert_sha256;
	void *cert_list_handle;
	int cert_list_size;

	char *cookie; /* Pointer to within cookies list */
	struct oc_vpn_option *cookies;
	struct oc_vpn_option *cstp_options;
	struct oc_vpn_option *dtls_options;

	struct oc_vpn_option *script_env;
	struct oc_vpn_option *csd_env;

	unsigned pfs;
#if defined(OPENCONNECT_OPENSSL)
#ifdef HAVE_LIBP11
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *pkcs11_slot_list;
	unsigned int pkcs11_slot_count;
	PKCS11_SLOT *pkcs11_cert_slot;
	unsigned char *pkcs11_cert_id;
	size_t pkcs11_cert_id_len;
 #endif
	X509 *cert_x509;
	SSL_CTX *https_ctx;
	SSL *https_ssl;
#elif defined(OPENCONNECT_GNUTLS)
	gnutls_session_t https_sess;
	gnutls_certificate_credentials_t https_cred;
	gnutls_psk_client_credentials_t psk_cred;
	char local_cert_md5[MD5_SIZE * 2 + 1]; /* For CSD */
	char gnutls_prio[256];
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
	struct pin_cache *pin_cache;
	struct keepalive_info ssl_times;
	int owe_ssl_dpd_response;

	int deflate_pkt_size;			/* It may need to be larger than MTU */
	struct pkt *deflate_pkt;		/* For compressing outbound packets into */
	struct pkt *pending_deflated_pkt;	/* The original packet associated with above */
	struct pkt *current_ssl_pkt;		/* Partially sent SSL packet */
	struct pkt_q oncp_control_queue;		/* Control packets to be sent on oNCP next */
	int oncp_rec_size;			/* For packetising incoming oNCP stream */
	/* Packet buffers for receiving into */
	struct pkt *cstp_pkt;
	struct pkt *dtls_pkt;
	struct pkt *tun_pkt;
	int pkt_trailer; /* How many bytes after payload for encryption (ESP HMAC) */

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
#elif defined(OPENCONNECT_GNUTLS)
	/* Call this dtls_ssl rather than dtls_sess because it's just a
	   pointer, and generic code in dtls.c wants to check if it's
	   NULL or not or pass it to DTLS_SEND/DTLS_RECV. This way we
	   have fewer ifdefs and accessor macros for it. */
	gnutls_session_t dtls_ssl;
	char *gnutls_dtls_cipher; /* cached for openconnect_get_dtls_cipher() */
#endif
	char *cstp_cipher;

	int dtls_state;
	int dtls_need_reconnect;
	struct keepalive_info dtls_times;
	unsigned char dtls_session_id[32];
	unsigned char dtls_secret[48];
	unsigned char dtls_app_id[32];
	unsigned dtls_app_id_size;

	char *dtls_cipher;
	char *vpnc_script;
#ifndef _WIN32
	int uid_csd_given;
	uid_t uid_csd;
	gid_t gid_csd;
	uid_t uid;
	gid_t gid;
#endif
	int use_tun_script;
	int script_tun;
	char *ifname;
	char *cmd_ifname;

	int reqmtu, basemtu; /* Local static configured values */
	const char *banner;

	struct oc_ip_info ip_info;
	int cstp_basemtu; /* Returned by server */

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
	int tun_idx, tun_rd_pending;
#else
	int tun_fd;
#endif
	int ssl_fd;
	int dtls_fd;

	int dtls_tos_current;
	int dtls_pass_tos;
	int dtls_tos_proto, dtls_tos_optname;

	int cmd_fd;
	int cmd_fd_write;
	int got_cancel_cmd;
	int got_pause_cmd;
	char cancel_type;

	struct pkt_q incoming_queue;
	struct pkt_q outgoing_queue;
	int max_qlen;
	struct oc_stats stats;
	openconnect_stats_vfn stats_handler;

	socklen_t peer_addrlen;
	struct sockaddr *peer_addr;
	struct sockaddr *dtls_addr;

	int dtls_local_port;

	int req_compr; /* What we requested */
	int cstp_compr; /* Accepted for CSTP */
	int dtls_compr; /* Accepted for DTLS */

	int is_dyndns; /* Attempt to redo DNS lookup on each CSTP reconnect */
	char *useragent;

	const char *quit_reason;

	int verbose;
	void *cbdata;
	openconnect_validate_peer_cert_vfn validate_peer_cert;
	openconnect_write_new_config_vfn write_new_config;
	openconnect_process_auth_form_vfn process_auth_form;
	openconnect_progress_vfn progress;
	openconnect_protect_socket_vfn protect_socket;
	openconnect_getaddrinfo_vfn getaddrinfo_override;
	openconnect_setup_tun_vfn setup_tun;
	openconnect_reconnected_vfn reconnected;

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

/* Key material for DTLS-PSK */
#define PSK_LABEL "EXPORTER-openconnect-psk"
#define PSK_LABEL_SIZE sizeof(PSK_LABEL)-1
#define PSK_KEY_SIZE 32

/* Packet types */

#define AC_PKT_DATA		0	/* Uncompressed data */
#define AC_PKT_DPD_OUT		3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP		4	/* DPD response */
#define AC_PKT_DISCONN		5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE	7	/* Keepalive */
#define AC_PKT_COMPRESSED	8	/* Compressed data */
#define AC_PKT_TERM_SERVER	9	/* Server kick */

#define vpn_progress(_v, lvl, ...) do {					\
	if ((_v)->verbose >= (lvl))					\
		(_v)->progress((_v)->cbdata, lvl, __VA_ARGS__);	\
	} while(0)
#define vpn_perror(vpninfo, msg) vpn_progress((vpninfo), PRG_ERR, "%s: %s\n", (msg), strerror(errno))

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
static inline int tun_is_up(struct openconnect_info *vpninfo)
{
#ifdef _WIN32
	return vpninfo->tun_fh != NULL;
#else
	return vpninfo->tun_fd != -1;
#endif
}

#ifdef _WIN32
#define pipe(fds) _pipe(fds, 4096, O_BINARY)
int openconnect__win32_sock_init();
char *openconnect__win32_strerror(DWORD err);
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
unsigned char unhex(const char *data);
int script_setenv(struct openconnect_info *vpninfo, const char *opt, const char *val, int append);
int script_setenv_int(struct openconnect_info *vpninfo, const char *opt, int value);
void prepare_script_env(struct openconnect_info *vpninfo);
int script_config_tun(struct openconnect_info *vpninfo, const char *reason);
int apply_script_env(struct oc_vpn_option *envs);
void free_split_routes(struct openconnect_info *vpninfo);

/* tun.c / tun-win32.c */
void os_shutdown_tun(struct openconnect_info *vpninfo);
int os_read_tun(struct openconnect_info *vpninfo, struct pkt *pkt);
int os_write_tun(struct openconnect_info *vpninfo, struct pkt *pkt);
intptr_t os_setup_tun(struct openconnect_info *vpninfo);

/* {gnutls,openssl}-dtls.c */
int start_dtls_handshake(struct openconnect_info *vpninfo, int dtls_fd);
int dtls_try_handshake(struct openconnect_info *vpninfo);
unsigned dtls_set_mtu(struct openconnect_info *vpninfo, unsigned mtu);
void dtls_ssl_free(struct openconnect_info *vpninfo);

/* dtls.c */
int dtls_setup(struct openconnect_info *vpninfo, int dtls_attempt_period);
int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout);
void dtls_close(struct openconnect_info *vpninfo);
void dtls_shutdown(struct openconnect_info *vpninfo);
void append_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
void dtls_detect_mtu(struct openconnect_info *vpninfo);
int openconnect_dtls_read(struct openconnect_info *vpninfo, void *buf, size_t len, unsigned ms);
int openconnect_dtls_write(struct openconnect_info *vpninfo, void *buf, size_t len);
char *openconnect_bin2hex(const char *prefix, const uint8_t *data, unsigned len);

/* cstp.c */
void cstp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
int cstp_connect(struct openconnect_info *vpninfo);
int cstp_mainloop(struct openconnect_info *vpninfo, int *timeout);
int cstp_bye(struct openconnect_info *vpninfo, const char *reason);
int decompress_and_queue_packet(struct openconnect_info *vpninfo, int compr_type,
				unsigned char *buf, int len);
int compress_packet(struct openconnect_info *vpninfo, int compr_type, struct pkt *this);

/* auth-juniper.c */
int oncp_obtain_cookie(struct openconnect_info *vpninfo);
void oncp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);

/* oncp.c */
int queue_esp_control(struct openconnect_info *vpninfo, int enable);
int oncp_connect(struct openconnect_info *vpninfo);
int oncp_mainloop(struct openconnect_info *vpninfo, int *timeout);

/* lzs.c */
int lzs_decompress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen);
int lzs_compress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen);

/* ssl.c */
unsigned string_is_hostname(const char* str);
int connect_https_socket(struct openconnect_info *vpninfo);
int __attribute__ ((format(printf, 4, 5)))
    request_passphrase(struct openconnect_info *vpninfo, const char *label,
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
int udp_sockaddr(struct openconnect_info *vpninfo, int port);
int udp_connect(struct openconnect_info *vpninfo);
int ssl_reconnect(struct openconnect_info *vpninfo);
void openconnect_clear_cookies(struct openconnect_info *vpninfo);

/* openssl-pkcs11.c */
int load_pkcs11_key(struct openconnect_info *vpninfo);
int load_pkcs11_certificate(struct openconnect_info *vpninfo);

/* esp.c */
int verify_packet_seqno(struct openconnect_info *vpninfo,
			struct esp *esp, uint32_t seq);
int esp_setup(struct openconnect_info *vpninfo, int dtls_attempt_period);
int esp_mainloop(struct openconnect_info *vpninfo, int *timeout);
void esp_close(struct openconnect_info *vpninfo);
void esp_shutdown(struct openconnect_info *vpninfo);
int print_esp_keys(struct openconnect_info *vpninfo, const char *name, struct esp *esp);

/* {gnutls,openssl}-esp.c */
int setup_esp_keys(struct openconnect_info *vpninfo);
void destroy_esp_ciphers(struct esp *esp);
int decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt);
int encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt);

/* {gnutls,openssl}.c */
int ssl_nonblock_read(struct openconnect_info *vpninfo, void *buf, int maxlen);
int ssl_nonblock_write(struct openconnect_info *vpninfo, void *buf, int buflen);
int openconnect_open_https(struct openconnect_info *vpninfo);
void openconnect_close_https(struct openconnect_info *vpninfo, int final);
int cstp_handshake(struct openconnect_info *vpninfo, unsigned init);
int get_cert_md5_fingerprint(struct openconnect_info *vpninfo, void *cert,
			     char *buf);
int openconnect_sha1(unsigned char *result, void *data, int len);
int openconnect_sha256(unsigned char *result, void *data, int len);
int openconnect_md5(unsigned char *result, void *data, int len);
int openconnect_random(void *bytes, int len);
int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf);
int openconnect_yubikey_chalresp(struct openconnect_info *vpninfo,
				 const void *challenge, int chall_len, void *result);
int openconnect_hash_yubikey_password(struct openconnect_info *vpninfo,
				      const char *password, int pwlen,
				      const void *ident, int id_len);
int hotp_hmac(struct openconnect_info *vpninfo, const void *challenge);
#if defined(OPENCONNECT_OPENSSL)
#define openconnect_https_connected(_v) ((_v)->https_ssl)
#elif defined (OPENCONNECT_GNUTLS)
#define openconnect_https_connected(_v) ((_v)->https_sess)
#endif

/* mainloop.c */
int tun_mainloop(struct openconnect_info *vpninfo, int *timeout);
int queue_new_packet(struct pkt_q *q, void *buf, int len);
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

/* yubikey.c */
int set_yubikey_mode(struct openconnect_info *vpninfo, const char *token_str);
int can_gen_yubikey_code(struct openconnect_info *vpninfo,
			 struct oc_auth_form *form,
			 struct oc_form_opt *opt);
int do_gen_yubikey_code(struct openconnect_info *vpninfo,
			struct oc_auth_form *form,
			struct oc_form_opt *opt);

/* auth.c */
int cstp_obtain_cookie(struct openconnect_info *vpninfo);

/* auth-common.c */
int xmlnode_is_named(xmlNode *xml_node, const char *name);
int xmlnode_get_prop(xmlNode *xml_node, const char *name, char **var);
int xmlnode_match_prop(xmlNode *xml_node, const char *name, const char *match);
int append_opt(struct oc_text_buf *body, const char *opt, const char *name);
int append_form_opts(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form, struct oc_text_buf *body);
void free_opt(struct oc_form_opt *opt);
void free_auth_form(struct oc_auth_form *form);
int do_gen_tokencode(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form);
int can_gen_tokencode(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt);

/* http.c */
struct oc_text_buf *buf_alloc(void);
void dump_buf(struct openconnect_info *vpninfo, char prefix, char *buf);
int buf_ensure_space(struct oc_text_buf *buf, int len);
void  __attribute__ ((format (printf, 2, 3)))
	buf_append(struct oc_text_buf *buf, const char *fmt, ...);
void buf_append_bytes(struct oc_text_buf *buf, const void *bytes, int len);
void buf_append_hex(struct oc_text_buf *buf, const void *str, unsigned len);
int buf_append_utf16le(struct oc_text_buf *buf, const char *utf8);
int get_utf8char(const char **utf8);
void buf_append_from_utf16le(struct oc_text_buf *buf, const void *utf16);
void buf_truncate(struct oc_text_buf *buf);
void buf_append_urlencoded(struct oc_text_buf *buf, const char *str);
int buf_error(struct oc_text_buf *buf);
int buf_free(struct oc_text_buf *buf);
char *openconnect_create_useragent(const char *base);
int process_proxy(struct openconnect_info *vpninfo, int ssl_sock);
int internal_parse_url(const char *url, char **res_proto, char **res_host,
		       int *res_port, char **res_path, int default_port);
int do_https_request(struct openconnect_info *vpninfo, const char *method,
		     const char *request_body_type, struct oc_text_buf *request_body,
		     char **form_buf, int fetch_redirect);
int http_add_cookie(struct openconnect_info *vpninfo, const char *option,
		    const char *value, int replace);
int process_http_response(struct openconnect_info *vpninfo, int connect,
			  int (*header_cb)(struct openconnect_info *, char *, char *),
			  struct oc_text_buf *body);
int handle_redirect(struct openconnect_info *vpninfo);
void http_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);

/* http-auth.c */
void buf_append_base64(struct oc_text_buf *buf, const void *bytes, int len);
void *openconnect_base64_decode(int *len, const char *in);
void clear_auth_states(struct openconnect_info *vpninfo,
		       struct http_auth_state *auth_states, int reset);
int proxy_auth_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val);
int http_auth_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val);
int gen_authorization_hdr(struct openconnect_info *vpninfo, int proxy,
			  struct oc_text_buf *buf);
/* ntlm.c */
int ntlm_authorization(struct openconnect_info *vpninfo, int proxy, struct http_auth_state *auth_state, struct oc_text_buf *buf);
void cleanup_ntlm_auth(struct openconnect_info *vpninfo, struct http_auth_state *auth_state);

/* gssapi.c */
int gssapi_authorization(struct openconnect_info *vpninfo, int proxy, struct http_auth_state *auth_state, struct oc_text_buf *buf);
void cleanup_gssapi_auth(struct openconnect_info *vpninfo, struct http_auth_state *auth_state);
int socks_gssapi_auth(struct openconnect_info *vpninfo);

/* digest.c */
int digest_authorization(struct openconnect_info *vpninfo, int proxy, struct http_auth_state *auth_state, struct oc_text_buf *buf);

/* library.c */
void nuke_opt_values(struct oc_form_opt *opt);
int process_auth_form(struct openconnect_info *vpninfo, struct oc_auth_form *form);
/* This is private for now since we haven't yet worked out what the API will be */
void openconnect_set_juniper(struct openconnect_info *vpninfo);

/* version.c */
extern const char *openconnect_version_str;

/* strncasecmp() just checks that the first n characters match. This
   function ensures that the first n characters of the left-hand side
   are a *precise* match for the right-hand side. */
static inline int strprefix_match(const char *str, int len, const char *match)
{
	return len == strlen(match) && !strncasecmp(str, match, len);
}

#define STRDUP(res, arg) \
	if (res != arg) {					\
		free(res);					\
		if (arg) {					\
			res = strdup(arg);			\
			if (res == NULL) return -ENOMEM;	\
		} else res = NULL;				\
	} while(0)

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

/* Let's stop open-coding big-endian and little-endian loads/stores.
 *
 * Start with a packed structure so that we can let the compiler
 * decide whether the target CPU can cope with unaligned load/stores
 * or not. Then there are three cases to handle:
 *  - For big-endian loads/stores, just use htons() et al.
 *  - For little-endian when we *know* the CPU is LE, just load/store
 *  - For little-endian otherwise, do the data acess byte-wise
 */
struct oc_packed_uint32_t {
	uint32_t d;
} __attribute__((packed));
struct oc_packed_uint16_t {
	uint16_t d;
} __attribute__((packed));

static inline uint32_t load_be32(const void *_p)
{
	const struct oc_packed_uint32_t *p = _p;
	return ntohl(p->d);
}

static inline uint16_t load_be16(const void *_p)
{
	const struct oc_packed_uint16_t *p = _p;
	return ntohs(p->d);
}

static inline void store_be32(void *_p, uint32_t d)
{
	struct oc_packed_uint32_t *p = _p;
	p->d = htonl(d);
}

static inline void store_be16(void *_p, uint16_t d)
{
	struct oc_packed_uint16_t *p = _p;
	p->d = htons(d);
}

/* It doesn't matter if we don't find one. It'll default to the
 * "not known to be little-endian" case, and do the bytewise
 * load/store. Modern compilers might even spot the pattern and
 * optimise it (see GCC PR#55177 around comment 15). */
#ifdef ENDIAN_HDR
#include ENDIAN_HDR
#endif

#if defined(_WIN32) ||							       \
   (defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)) /* Solaris */ ||	       \
   (defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN) && defined(__BYTE_ORDER) \
    && __BYTE_ORDER == __LITTLE_ENDIAN) /* Linux */ ||			       \
   (defined(LITTLE_ENDIAN) && defined(BIG_ENDIAN) && defined(BYTE_ORDER)       \
    && BYTE_ORDER == LITTLE_ENDIAN) /* *BSD */
static inline uint32_t load_le32(const void *_p)
{
	const struct oc_packed_uint32_t *p = _p;
	return p->d;
}

static inline uint16_t load_le16(const void *_p)
{
	const struct oc_packed_uint16_t *p = _p;
	return p->d;
}

static inline void store_le32(void *_p, uint32_t d)
{
	struct oc_packed_uint32_t *p = _p;
	p->d = d;
}

static inline void store_le16(void *_p, uint16_t d)
{
	struct oc_packed_uint16_t *p = _p;
	p->d = d;
}
#else
static inline uint32_t load_le32(const void *_p)
{
	const unsigned char *p = _p;
	return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline uint16_t load_le16(const void *_p)
{
	const unsigned char *p = _p;
	return p[0] | (p[1] << 8);
}

static inline void store_le32(void *_p, uint32_t d)
{
	unsigned char *p = _p;
	p[0] = d;
	p[1] = d >> 8;
}

static inline void store_le16(void *_p, uint16_t d)
{
	unsigned char *p = _p;
	p[0] = d;
	p[1] = d >> 8;
	p[2] = d >> 16;
	p[3] = d >> 24;
}
#endif /* !Not known to be little-endian */

#endif /* __OPENCONNECT_INTERNAL_H__ */
