/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2013 John Morrissey <jwm@horde.net>
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>
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

#include <config.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#ifdef HAVE_LIBSTOKEN
#include <stoken.h>
#endif

#include <libxml/tree.h>
#include <zlib.h>

#include "openconnect-internal.h"

#if defined(OPENCONNECT_GNUTLS)
#include "gnutls.h"
#endif

struct openconnect_info *openconnect_vpninfo_new(const char *useragent,
						 openconnect_validate_peer_cert_vfn validate_peer_cert,
						 openconnect_write_new_config_vfn write_new_config,
						 openconnect_process_auth_form_vfn process_auth_form,
						 openconnect_progress_vfn progress,
						 void *privdata)
{
	struct openconnect_info *vpninfo = calloc(sizeof(*vpninfo), 1);
#ifdef HAVE_ICONV
	char *charset = nl_langinfo(CODESET);
#endif

	if (!vpninfo)
		return NULL;

#ifdef HAVE_ICONV
	if (charset && strcmp(charset, "UTF-8")) {
		vpninfo->ic_utf8_to_legacy = iconv_open(charset, "UTF-8");
		vpninfo->ic_legacy_to_utf8 = iconv_open("UTF-8", charset);
	} else {
		vpninfo->ic_utf8_to_legacy = (iconv_t)-1;
		vpninfo->ic_legacy_to_utf8 = (iconv_t)-1;
	}
#endif
#ifndef _WIN32
	vpninfo->tun_fd = -1;
#endif
	init_pkt_queue(&vpninfo->incoming_queue);
	init_pkt_queue(&vpninfo->outgoing_queue);
	init_pkt_queue(&vpninfo->oncp_control_queue);
	vpninfo->ssl_fd = vpninfo->dtls_fd = -1;
	vpninfo->cmd_fd = vpninfo->cmd_fd_write = -1;
	vpninfo->tncc_fd = -1;
	vpninfo->cert_expire_warning = 60 * 86400;
	vpninfo->req_compr = COMPR_STATELESS;
	vpninfo->max_qlen = 10;
	vpninfo->localname = strdup("localhost");
	vpninfo->useragent = openconnect_create_useragent(useragent);
	vpninfo->validate_peer_cert = validate_peer_cert;
	vpninfo->write_new_config = write_new_config;
	vpninfo->process_auth_form = process_auth_form;
	vpninfo->progress = progress;
	vpninfo->cbdata = privdata ? : vpninfo;
	vpninfo->xmlpost = 1;
	vpninfo->verbose = PRG_TRACE;
	vpninfo->try_http_auth = 1;
	vpninfo->proxy_auth[AUTH_TYPE_BASIC].state = AUTH_DEFAULT_DISABLED;
	vpninfo->http_auth[AUTH_TYPE_BASIC].state = AUTH_DEFAULT_DISABLED;
	openconnect_set_reported_os(vpninfo, NULL);

	if (!vpninfo->localname || !vpninfo->useragent)
		goto err;

#ifdef ENABLE_NLS
	bindtextdomain("openconnect", LOCALEDIR);
#endif
	openconnect_set_protocol(vpninfo, "anyconnect");
	return vpninfo;

err:
	free(vpninfo->localname);
	free(vpninfo->useragent);
	free(vpninfo);
	return NULL;
}

int openconnect_set_protocol(struct openconnect_info *vpninfo, const char *protocol)
{
	if (!strcmp(protocol, "anyconnect")) {
		vpninfo->proto.vpn_close_session = cstp_bye;
		vpninfo->proto.tcp_connect = cstp_connect;
		vpninfo->proto.tcp_mainloop = cstp_mainloop;
		vpninfo->proto.add_http_headers = cstp_common_headers;
		vpninfo->proto.obtain_cookie = cstp_obtain_cookie;
#ifdef HAVE_DTLS
		vpninfo->proto.udp_setup = dtls_setup;
		vpninfo->proto.udp_mainloop = dtls_mainloop;
		vpninfo->proto.udp_close = dtls_close;
		vpninfo->proto.udp_shutdown = dtls_shutdown;
#else
		vpninfo->dtls_state = DTLS_DISABLED;
#endif
	} else if (!strcmp(protocol, "nc")) {
		vpninfo->proto.vpn_close_session = NULL;
		vpninfo->proto.tcp_connect = oncp_connect;
		vpninfo->proto.tcp_mainloop = oncp_mainloop;
		vpninfo->proto.add_http_headers = oncp_common_headers;
		vpninfo->proto.obtain_cookie = oncp_obtain_cookie;
#if defined(ESP_GNUTLS) || defined(ESP_OPENSSL)
		vpninfo->proto.udp_setup = esp_setup;
		vpninfo->proto.udp_mainloop = esp_mainloop;
		vpninfo->proto.udp_close = esp_close;
		vpninfo->proto.udp_shutdown = esp_shutdown;
#else
		vpninfo->dtls_state = DTLS_DISABLED;
#endif
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown VPN protocol '%s'\n"), protocol);
		return -EINVAL;
	}

	return 0;
}

void openconnect_set_loglevel(struct openconnect_info *vpninfo,
			      int level)
{
	vpninfo->verbose = level;
}

int openconnect_setup_dtls(struct openconnect_info *vpninfo,
			   int attempt_period)

{
	if (vpninfo->proto.udp_setup)
		return vpninfo->proto.udp_setup(vpninfo, attempt_period);

	vpn_progress(vpninfo, PRG_ERR,
		     _("Built against SSL library with no Cisco DTLS support\n"));
	return -EINVAL;
}

int openconnect_obtain_cookie(struct openconnect_info *vpninfo)
{
	return vpninfo->proto.obtain_cookie(vpninfo);
}

int openconnect_make_cstp_connection(struct openconnect_info *vpninfo)
{
	return vpninfo->proto.tcp_connect(vpninfo);
}

int openconnect_set_reported_os(struct openconnect_info *vpninfo,
				const char *os)
{
	if (!os) {
#if defined(__APPLE__)
		os = "mac-intel";
#elif defined(__ANDROID__)
		os = "android";
#else
		os = sizeof(long) > 4 ? "linux-64" : "linux";
#endif
	}

	if (!strcmp(os, "mac-intel"))
		vpninfo->csd_xmltag = "csdMac";
	else if (!strcmp(os, "linux") || !strcmp(os, "linux-64"))
		vpninfo->csd_xmltag = "csdLinux";
	else if (!strcmp(os, "android") || !strcmp(os, "apple-ios")) {
		vpninfo->csd_xmltag = "csdLinux";
		vpninfo->csd_nostub = 1;
	} else if (!strcmp(os, "win"))
		vpninfo->csd_xmltag = "csd";
	else
		return -EINVAL;

	STRDUP(vpninfo->platname, os);
	return 0;
}

int openconnect_set_mobile_info(struct openconnect_info *vpninfo,
				const char *mobile_platform_version,
				const char *mobile_device_type,
				const char *mobile_device_uniqueid)
{
	STRDUP(vpninfo->mobile_platform_version, mobile_platform_version);
	STRDUP(vpninfo->mobile_device_type, mobile_device_type);
	STRDUP(vpninfo->mobile_device_uniqueid, mobile_device_uniqueid);

	return 0;
}

static void free_optlist(struct oc_vpn_option *opt)
{
	struct oc_vpn_option *next;

	for (; opt; opt = next) {
		next = opt->next;
		free(opt->option);
		free(opt->value);
		free(opt);
	}
}

void openconnect_vpninfo_free(struct openconnect_info *vpninfo)
{
	openconnect_close_https(vpninfo, 1);
	if (vpninfo->proto.udp_shutdown)
		vpninfo->proto.udp_shutdown(vpninfo);
	if (vpninfo->tncc_fd != -1)
		closesocket(vpninfo->tncc_fd);
	if (vpninfo->cmd_fd_write != -1) {
		closesocket(vpninfo->cmd_fd);
		closesocket(vpninfo->cmd_fd_write);
	}

#ifdef HAVE_ICONV
	if (vpninfo->ic_utf8_to_legacy != (iconv_t)-1)
		iconv_close(vpninfo->ic_utf8_to_legacy);

	if (vpninfo->ic_legacy_to_utf8 != (iconv_t)-1)
		iconv_close(vpninfo->ic_legacy_to_utf8);
#endif
#ifdef _WIN32
	if (vpninfo->cmd_event)
		CloseHandle(vpninfo->cmd_event);
	if (vpninfo->ssl_event)
		CloseHandle(vpninfo->ssl_event);
	if (vpninfo->dtls_event)
		CloseHandle(vpninfo->dtls_event);
#endif
	free(vpninfo->peer_addr);
	free_optlist(vpninfo->csd_env);
	free_optlist(vpninfo->script_env);
	free_optlist(vpninfo->cookies);
	free_optlist(vpninfo->cstp_options);
	free_optlist(vpninfo->dtls_options);
	free_split_routes(vpninfo);
	free(vpninfo->hostname);
	free(vpninfo->unique_hostname);
	free(vpninfo->urlpath);
	free(vpninfo->redirect_url);
	free(vpninfo->cookie);
	free(vpninfo->proxy_type);
	free(vpninfo->proxy);
	free(vpninfo->proxy_user);
	free(vpninfo->proxy_pass);
	free(vpninfo->vpnc_script);
	free(vpninfo->cafile);
	free(vpninfo->ifname);
	free(vpninfo->dtls_cipher);
#ifdef OPENCONNECT_GNUTLS
	gnutls_free(vpninfo->cstp_cipher); /* In OpenSSL this is const */
#endif
#ifdef DTLS_GNUTLS
	gnutls_free(vpninfo->gnutls_dtls_cipher);
#endif
	free(vpninfo->dtls_addr);

	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
	}
	free(vpninfo->mobile_platform_version);
	free(vpninfo->mobile_device_type);
	free(vpninfo->mobile_device_uniqueid);
	free(vpninfo->csd_token);
	free(vpninfo->csd_ticket);
	free(vpninfo->csd_stuburl);
	free(vpninfo->csd_starturl);
	free(vpninfo->csd_waiturl);
	free(vpninfo->csd_preurl);
	free(vpninfo->platname);
	if (vpninfo->opaque_srvdata)
		xmlFreeNode(vpninfo->opaque_srvdata);
	free(vpninfo->profile_url);
	free(vpninfo->profile_sha1);

	/* These are const in openconnect itself, but for consistency of
	   the library API we do take ownership of the strings we're given,
	   and thus we have to free them too. */
	if (vpninfo->cert != vpninfo->sslkey)
		free((void *)vpninfo->sslkey);
	free((void *)vpninfo->cert);
	if (vpninfo->peer_cert) {
#if defined(OPENCONNECT_OPENSSL)
		X509_free(vpninfo->peer_cert);
#elif defined(OPENCONNECT_GNUTLS)
		gnutls_x509_crt_deinit(vpninfo->peer_cert);
#endif
		vpninfo->peer_cert = NULL;
	}
	while (vpninfo->pin_cache) {
		struct pin_cache *cache = vpninfo->pin_cache;

		free(cache->token);
		memset(cache->pin, 0x5a, strlen(cache->pin));
		free(cache->pin);
		vpninfo->pin_cache = cache->next;
		free(cache);
	}

	free(vpninfo->peer_cert_hash);
	free(vpninfo->localname);
	free(vpninfo->useragent);
	free(vpninfo->authgroup);
#ifdef HAVE_LIBSTOKEN
	if (vpninfo->stoken_pin)
		free(vpninfo->stoken_pin);
	if (vpninfo->stoken_ctx)
		stoken_destroy(vpninfo->stoken_ctx);
#endif
	if (vpninfo->oath_secret) {
#ifdef HAVE_LIBPSKC
		if (vpninfo->pskc)
			pskc_done(vpninfo->pskc);
		else
#endif /* HAVE_LIBPSKC */
		free(vpninfo->oath_secret);
	}
#ifdef HAVE_LIBPCSCLITE
	if (vpninfo->token_mode == OC_TOKEN_MODE_YUBIOATH) {
		SCardDisconnect(vpninfo->pcsc_card, SCARD_LEAVE_CARD);
		SCardReleaseContext(vpninfo->pcsc_ctx);
	}
	memset(vpninfo->yubikey_pwhash, 0, sizeof(vpninfo->yubikey_pwhash));
	free(vpninfo->yubikey_objname);
#endif
#ifdef HAVE_LIBP11
	if (vpninfo->pkcs11_ctx) {
		if (vpninfo->pkcs11_slot_list)
			PKCS11_release_all_slots(vpninfo->pkcs11_ctx,
						 vpninfo->pkcs11_slot_list,
						 vpninfo->pkcs11_slot_count);
		PKCS11_CTX_unload(vpninfo->pkcs11_ctx);
		PKCS11_CTX_free(vpninfo->pkcs11_ctx);
	}
	free(vpninfo->pkcs11_cert_id);
#endif
	/* These check strm->state so they are safe to call multiple times */
	inflateEnd(&vpninfo->inflate_strm);
	deflateEnd(&vpninfo->deflate_strm);

	free(vpninfo->deflate_pkt);
	free(vpninfo->tun_pkt);
	free(vpninfo->dtls_pkt);
	free(vpninfo->cstp_pkt);
	free(vpninfo);
}

const char *openconnect_get_hostname(struct openconnect_info *vpninfo)
{
	return vpninfo->unique_hostname?:vpninfo->hostname;
}

int openconnect_set_hostname(struct openconnect_info *vpninfo,
			     const char *hostname)
{
	UTF8CHECK(hostname);

	STRDUP(vpninfo->hostname, hostname);
	free(vpninfo->unique_hostname);
	vpninfo->unique_hostname = NULL;
	free(vpninfo->peer_addr);
	vpninfo->peer_addr = NULL;

	return 0;
}

char *openconnect_get_urlpath(struct openconnect_info *vpninfo)
{
	return vpninfo->urlpath;
}

int openconnect_set_urlpath(struct openconnect_info *vpninfo,
			    const char *urlpath)
{
	UTF8CHECK(urlpath);

	STRDUP(vpninfo->urlpath, urlpath);
	return 0;
}

void openconnect_set_xmlsha1(struct openconnect_info *vpninfo,
			     const char *xmlsha1, int size)
{
	if (size != sizeof(vpninfo->xmlsha1))
		return;

	memcpy(&vpninfo->xmlsha1, xmlsha1, size);
}

void openconnect_disable_ipv6(struct openconnect_info *vpninfo)
{
	vpninfo->disable_ipv6 = 1;
}

int openconnect_set_cafile(struct openconnect_info *vpninfo, const char *cafile)
{
	UTF8CHECK(cafile);

	STRDUP(vpninfo->cafile, cafile);
	return 0;
}

void openconnect_set_system_trust(struct openconnect_info *vpninfo, unsigned val)
{
	vpninfo->no_system_trust = !val;
}

const char *openconnect_get_ifname(struct openconnect_info *vpninfo)
{
	return vpninfo->ifname;
}

void openconnect_set_reqmtu(struct openconnect_info *vpninfo, int reqmtu)
{
	vpninfo->reqmtu = reqmtu;
}

void openconnect_set_dpd(struct openconnect_info *vpninfo, int min_seconds)
{
	/* Make sure (ka->dpd / 2), our computed midway point, isn't 0 */
	if (!min_seconds || min_seconds >= 2)
		vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = min_seconds;
	else if (min_seconds == 1)
		vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = 2;
}

int openconnect_get_ip_info(struct openconnect_info *vpninfo,
			    const struct oc_ip_info **info,
			    const struct oc_vpn_option **cstp_options,
			    const struct oc_vpn_option **dtls_options)
{
	if (info)
		*info = &vpninfo->ip_info;
	if (cstp_options)
		*cstp_options = vpninfo->cstp_options;
	if (dtls_options)
		*dtls_options = vpninfo->dtls_options;
	return 0;
}

int openconnect_setup_csd(struct openconnect_info *vpninfo, uid_t uid,
			  int silent, const char *wrapper)
{
	vpninfo->uid_csd = uid;
	vpninfo->uid_csd_given = silent ? 2 : 1;
	STRDUP(vpninfo->csd_wrapper, wrapper);

	return 0;
}

void openconnect_set_xmlpost(struct openconnect_info *vpninfo, int enable)
{
	vpninfo->xmlpost = enable;
}

int openconnect_set_client_cert(struct openconnect_info *vpninfo,
				const char *cert, const char *sslkey)
{
	UTF8CHECK(cert);
	UTF8CHECK(sslkey);

	/* Avoid freeing it twice if it's the same */
	if (vpninfo->sslkey == vpninfo->cert)
		vpninfo->sslkey = NULL;

	STRDUP(vpninfo->cert, cert);

	if (sslkey) {
		STRDUP(vpninfo->sslkey, sslkey);
	} else {
		vpninfo->sslkey = vpninfo->cert;
	}

	return 0;
}

int openconnect_get_port(struct openconnect_info *vpninfo)
{
	return vpninfo->port;
}

const char *openconnect_get_cookie(struct openconnect_info *vpninfo)
{
	return vpninfo->cookie;
}

void openconnect_clear_cookie(struct openconnect_info *vpninfo)
{
	if (vpninfo->cookie)
		memset(vpninfo->cookie, 0, strlen(vpninfo->cookie));
}

void openconnect_reset_ssl(struct openconnect_info *vpninfo)
{
	vpninfo->got_cancel_cmd = 0;
	openconnect_close_https(vpninfo, 0);
	if (vpninfo->peer_addr) {
		free(vpninfo->peer_addr);
		vpninfo->peer_addr = NULL;
	}
	openconnect_clear_cookies(vpninfo);
}

int openconnect_parse_url(struct openconnect_info *vpninfo, const char *url)
{
	char *scheme = NULL;
	int ret;

	UTF8CHECK(url);

	openconnect_set_hostname(vpninfo, NULL);
	free(vpninfo->urlpath);
	vpninfo->urlpath = NULL;

	ret = internal_parse_url(url, &scheme, &vpninfo->hostname,
				 &vpninfo->port, &vpninfo->urlpath, 443);

	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse server URL '%s'\n"),
			     url);
		return ret;
	}
	if (scheme && strcmp(scheme, "https")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Only https:// permitted for server URL\n"));
		ret = -EINVAL;
	}
	free(scheme);
	return ret;
}

void openconnect_set_cert_expiry_warning(struct openconnect_info *vpninfo,
					 int seconds)
{
	vpninfo->cert_expire_warning = seconds;
}

void openconnect_set_pfs(struct openconnect_info *vpninfo, unsigned val)
{
	vpninfo->pfs = val;
}

void openconnect_set_cancel_fd(struct openconnect_info *vpninfo, int fd)
{
	vpninfo->cmd_fd = fd;
}

#ifdef _WIN32
# define CMD_PIPE_ERR INVALID_SOCKET
#else
# define CMD_PIPE_ERR -EIO
#endif

OPENCONNECT_CMD_SOCKET openconnect_setup_cmd_pipe(struct openconnect_info *vpninfo)
{
	OPENCONNECT_CMD_SOCKET pipefd[2];

#ifdef _WIN32
	if (dumb_socketpair(pipefd, 0))
		return CMD_PIPE_ERR;
#else
	if (pipe(pipefd) < 0)
		return CMD_PIPE_ERR;
#endif

	if (set_sock_nonblock(pipefd[0]) || set_sock_nonblock(pipefd[1])) {
		closesocket(pipefd[0]);
		closesocket(pipefd[1]);
		return CMD_PIPE_ERR;
	}
	vpninfo->cmd_fd = pipefd[0];
	vpninfo->cmd_fd_write = pipefd[1];
	return vpninfo->cmd_fd_write;
}

const char *openconnect_get_version(void)
{
	return openconnect_version_str;
}

int openconnect_has_pkcs11_support(void)
{
#if defined(OPENCONNECT_GNUTLS) && defined(HAVE_P11KIT)
	return 1;
#elif defined(OPENCONNECT_OPENSSL) && defined(HAVE_LIBP11)
	return 1;
#else
	return 0;
#endif
}

#if defined(OPENCONNECT_OPENSSL) && defined(HAVE_ENGINE)
#include <openssl/engine.h>
#endif
int openconnect_has_tss_blob_support(void)
{
#if defined(OPENCONNECT_OPENSSL) && defined(HAVE_ENGINE)
	ENGINE *e;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("tpm");
	if (e) {
		ENGINE_free(e);
		return 1;
	}
#elif defined(OPENCONNECT_GNUTLS) && defined(HAVE_TROUSERS)
	return 1;
#endif
	return 0;
}

int openconnect_has_stoken_support(void)
{
#ifdef HAVE_LIBSTOKEN
	return 1;
#else
	return 0;
#endif
}

int openconnect_has_oath_support(void)
{
	return 2;
}

int openconnect_has_yubioath_support(void)
{
#ifdef HAVE_LIBPCSCLITE
	return 1;
#else
	return 0;
#endif
}

int openconnect_has_system_key_support(void)
{
#ifdef HAVE_GNUTLS_SYSTEM_KEYS
	return 1;
#else
	return 0;
#endif
}

int openconnect_set_token_callbacks(struct openconnect_info *vpninfo,
				    void *tokdata,
				    openconnect_lock_token_vfn lock,
				    openconnect_unlock_token_vfn unlock)
{
	vpninfo->lock_token = lock;
	vpninfo->unlock_token = unlock;
	vpninfo->tok_cbdata = tokdata;

	return 0;
}

/*
 * Enable software token generation.
 *
 * If token_mode is OC_TOKEN_MODE_STOKEN and token_str is NULL,
 * read the token data from ~/.stokenrc.
 *
 * Return value:
 *  = -EILSEQ, if token_str is not valid UTF-8
 *  = -EOPNOTSUPP, if the underlying library (libstoken, liboath) is not
 *                 available or an invalid token_mode was provided
 *  = -EINVAL, if the token string is invalid (token_str was provided)
 *  = -ENOENT, if token_mode is OC_TOKEN_MODE_STOKEN and ~/.stokenrc is
 *             missing (token_str was NULL)
 *  = -EIO, for other failures in the underlying library (libstoken, liboath)
 *  = 0, on success
 */
int openconnect_set_token_mode(struct openconnect_info *vpninfo,
			       oc_token_mode_t token_mode,
			       const char *token_str)
{
	vpninfo->token_mode = OC_TOKEN_MODE_NONE;

	UTF8CHECK(token_str);

	switch (token_mode) {
	case OC_TOKEN_MODE_NONE:
		return 0;

#ifdef HAVE_LIBSTOKEN
	case OC_TOKEN_MODE_STOKEN:
		return set_libstoken_mode(vpninfo, token_str);
#endif
	case OC_TOKEN_MODE_TOTP:
		return set_totp_mode(vpninfo, token_str);

	case OC_TOKEN_MODE_HOTP:
		return set_hotp_mode(vpninfo, token_str);
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return set_yubikey_mode(vpninfo, token_str);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Enable libstoken token generation if use_stoken == 1.
 *
 * If token_str is not NULL, try to parse the string.  Otherwise, try to read
 * the token data from ~/.stokenrc
 *
 * DEPRECATED: use openconnect_set_stoken_mode() instead.
 *
 * Return value:
 *  = -EILSEQ, if token_str is not valid UTF-8
 *  = -EOPNOTSUPP, if libstoken is not available
 *  = -EINVAL, if the token string is invalid (token_str was provided)
 *  = -ENOENT, if ~/.stokenrc is missing (token_str was NULL)
 *  = -EIO, for other libstoken failures
 *  = 0, on success
 */
int openconnect_set_stoken_mode(struct openconnect_info *vpninfo,
				int use_stoken, const char *token_str)
{
	oc_token_mode_t token_mode = OC_TOKEN_MODE_NONE;

	if (use_stoken)
		token_mode = OC_TOKEN_MODE_STOKEN;

	return openconnect_set_token_mode(vpninfo, token_mode, token_str);
}

void openconnect_set_protect_socket_handler(struct openconnect_info *vpninfo,
					    openconnect_protect_socket_vfn protect_socket)
{
	vpninfo->protect_socket = protect_socket;
}

void openconnect_override_getaddrinfo(struct openconnect_info *vpninfo, openconnect_getaddrinfo_vfn gai_fn)
{
	vpninfo->getaddrinfo_override = gai_fn;
}

void openconnect_set_stats_handler(struct openconnect_info *vpninfo,
				   openconnect_stats_vfn stats_handler)
{
	vpninfo->stats_handler = stats_handler;
}

/* Set up a traditional OS-based tunnel device, optionally specified in 'ifname'. */
int openconnect_setup_tun_device(struct openconnect_info *vpninfo,
				 const char *vpnc_script, const char *ifname)
{
	intptr_t tun_fd;
	char *legacy_ifname;

	UTF8CHECK(vpnc_script);
	UTF8CHECK(ifname);

	STRDUP(vpninfo->vpnc_script, vpnc_script);
	STRDUP(vpninfo->ifname, ifname);

	prepare_script_env(vpninfo);
	script_config_tun(vpninfo, "pre-init");

	tun_fd = os_setup_tun(vpninfo);
	if (tun_fd < 0)
		return tun_fd;

	legacy_ifname = openconnect_utf8_to_legacy(vpninfo, vpninfo->ifname);
	script_setenv(vpninfo, "TUNDEV", legacy_ifname, 0);
	if (legacy_ifname != vpninfo->ifname)
		free(legacy_ifname);
	script_config_tun(vpninfo, "connect");

	return openconnect_setup_tun_fd(vpninfo, tun_fd);
}

static const char *compr_name_map[] = {
	[COMPR_DEFLATE] = "Deflate",
	[COMPR_LZS] = "LZS",
	[COMPR_LZ4] = "LZ4"
};

const char *openconnect_get_cstp_compression(struct openconnect_info * vpninfo)
{
	if (vpninfo->cstp_compr <= 0 || vpninfo->cstp_compr > COMPR_MAX)
		return NULL;

	return compr_name_map[vpninfo->cstp_compr];
}

const char *openconnect_get_dtls_compression(struct openconnect_info * vpninfo)
{
	if (vpninfo->dtls_compr <= 0 || vpninfo->dtls_compr > COMPR_MAX)
		return NULL;

	return compr_name_map[vpninfo->dtls_compr];
}

const char *openconnect_get_dtls_cipher(struct openconnect_info *vpninfo)
{
#if defined(DTLS_GNUTLS)
	if (vpninfo->dtls_state != DTLS_CONNECTED) {
		gnutls_free(vpninfo->gnutls_dtls_cipher);
		vpninfo->gnutls_dtls_cipher = NULL;
		return NULL;
	}
	/* in DTLS rehandshakes don't switch the ciphersuite as only
	 * one is enabled. */
	if (vpninfo->gnutls_dtls_cipher == NULL)
		vpninfo->gnutls_dtls_cipher = get_gnutls_cipher(vpninfo->dtls_ssl);
	return vpninfo->gnutls_dtls_cipher;
#else
	return vpninfo->dtls_cipher;
#endif
}

int openconnect_set_csd_environ(struct openconnect_info *vpninfo,
				const char *name, const char *value)
{
	struct oc_vpn_option *p;

	if (!name) {
		free_optlist(vpninfo->csd_env);
		vpninfo->csd_env = NULL;
		return 0;
	}
	for (p = vpninfo->csd_env; p; p = p->next) {
		if (!strcmp(name, p->option)) {
			char *valdup = strdup(value);
			if (!valdup)
				return -ENOMEM;
			free(p->value);
			p->value = valdup;
			return 0;
		}
	}
	p = malloc(sizeof(*p));
	if (!p)
		return -ENOMEM;
	p->option = strdup(name);
	if (!p->option) {
		free(p);
		return -ENOMEM;
	}
	p->value = strdup(value);
	if (!p->value) {
		free(p->option);
		free(p);
		return -ENOMEM;
	}
	p->next = vpninfo->csd_env;
	vpninfo->csd_env = p;
	return 0;
}

int openconnect_check_peer_cert_hash(struct openconnect_info *vpninfo,
				     const char *old_hash)
{
	char sha1_text[41];
	const char *fingerprint;

	if (strchr(old_hash, ':')) {
		fingerprint = openconnect_get_peer_cert_hash(vpninfo);
		if (!fingerprint)
			return -EIO;
	} else {
		unsigned char *cert;
		int len, i;
		unsigned char sha1_bin[SHA1_SIZE];

		len = openconnect_get_peer_cert_DER(vpninfo, &cert);
		if (len < 0)
			return len;

		if (openconnect_sha1(sha1_bin, cert, len))
			return -EIO;

		for (i = 0; i < sizeof(sha1_bin); i++)
			sprintf(&sha1_text[i*2], "%02x", sha1_bin[i]);

		fingerprint = sha1_text;
	}

	if (strcasecmp(old_hash, fingerprint))
		return 1;

	return 0;
}

const char *openconnect_get_cstp_cipher(struct openconnect_info *vpninfo)
{
	return vpninfo->cstp_cipher;
}

const char *openconnect_get_peer_cert_hash(struct openconnect_info *vpninfo)
{
	return vpninfo->peer_cert_hash;
}

int openconnect_set_compression_mode(struct openconnect_info *vpninfo,
				     oc_compression_mode_t mode)
{
	switch(mode) {
	case OC_COMPRESSION_MODE_NONE:
		vpninfo->req_compr = 0;
		return 0;
	case OC_COMPRESSION_MODE_STATELESS:
		vpninfo->req_compr = COMPR_STATELESS;
		return 0;
	case OC_COMPRESSION_MODE_ALL:
		vpninfo->req_compr = COMPR_ALL;
		return 0;
	default:
		return -EINVAL;
	}
}

void nuke_opt_values(struct oc_form_opt *opt)
{
	for (; opt; opt = opt->next) {
		if (opt->type == OC_FORM_OPT_TEXT ||
		    opt->type == OC_FORM_OPT_PASSWORD) {
			free(opt->_value);
			opt->_value = NULL;
		}
	}
}

int process_auth_form(struct openconnect_info *vpninfo, struct oc_auth_form *form)
{
	int ret;
	struct oc_form_opt_select *grp = form->authgroup_opt;
	struct oc_choice *auth_choice;
	struct oc_form_opt *opt;

	if (!vpninfo->process_auth_form) {
		vpn_progress(vpninfo, PRG_ERR, _("No form handler; cannot authenticate.\n"));
		return OC_FORM_RESULT_ERR;
	}

retry:
	auth_choice = NULL;
	if (grp && grp->nr_choices && !vpninfo->xmlpost) {
		if (vpninfo->authgroup) {
			/* For non-XML-POST, the server doesn't tell us which group is selected */
			int i;
			for (i = 0; i < grp->nr_choices; i++)
				if (!strcmp(grp->choices[i]->name, vpninfo->authgroup))
					form->authgroup_selection = i;
		}
		auth_choice = grp->choices[form->authgroup_selection];
	}

	for (opt = form->opts; opt; opt = opt->next) {
		int second_auth = opt->flags & OC_FORM_OPT_SECOND_AUTH;
		opt->flags &= ~OC_FORM_OPT_IGNORE;

		if (!auth_choice ||
		    (opt->type != OC_FORM_OPT_TEXT && opt->type != OC_FORM_OPT_PASSWORD))
			continue;

		if (auth_choice->noaaa ||
		    (!auth_choice->second_auth && second_auth))
			opt->flags |= OC_FORM_OPT_IGNORE;
		else if (!strcmp(opt->name, "secondary_username") && second_auth) {
			if (auth_choice->secondary_username) {
				free(opt->_value);
				opt->_value = strdup(auth_choice->secondary_username);
			}
			if (!auth_choice->secondary_username_editable)
				opt->flags |= OC_FORM_OPT_IGNORE;
		}
	}

	ret = vpninfo->process_auth_form(vpninfo->cbdata, form);

	if (ret == OC_FORM_RESULT_NEWGROUP &&
	    form->authgroup_opt &&
	    form->authgroup_opt->form._value) {
		free(vpninfo->authgroup);
		vpninfo->authgroup = strdup(form->authgroup_opt->form._value);

		if (!vpninfo->xmlpost)
			goto retry;
	}

	if (ret == OC_FORM_RESULT_CANCELLED || ret < 0)
		nuke_opt_values(form->opts);

	return ret;
}

