/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#ifdef LIBSTOKEN_HDR
#include LIBSTOKEN_HDR
#endif

#include <libxml/tree.h>

#include "openconnect-internal.h"

struct openconnect_info *openconnect_vpninfo_new (char *useragent,
						  openconnect_validate_peer_cert_vfn validate_peer_cert,
						  openconnect_write_new_config_vfn write_new_config,
						  openconnect_process_auth_form_vfn process_auth_form,
						  openconnect_progress_vfn progress,
						  void *privdata)
{
	struct openconnect_info *vpninfo = calloc (sizeof(*vpninfo), 1);

	vpninfo->ssl_fd = -1;
	vpninfo->cert_expire_warning = 60 * 86400;
	vpninfo->useragent = openconnect_create_useragent (useragent);
	vpninfo->validate_peer_cert = validate_peer_cert;
	vpninfo->write_new_config = write_new_config;
	vpninfo->process_auth_form = process_auth_form;
	vpninfo->progress = progress;
	vpninfo->cbdata = privdata?:vpninfo;
	vpninfo->cancel_fd = -1;
	openconnect_set_reported_os(vpninfo, NULL);

#ifdef ENABLE_NLS
	bindtextdomain("openconnect", LOCALEDIR);
#endif

	return vpninfo;
}

int openconnect_set_reported_os (struct openconnect_info *vpninfo, const char *os)
{
	if (!os) {
#if defined(__APPLE__)
		os = "mac";
#else
		os = sizeof(long) > 4 ? "linux-64" : "linux";
#endif
	}

	/* FIXME: is there a special platname for 64-bit Windows? */
	if (!strcmp(os, "mac"))
		vpninfo->csd_xmltag = "csdMac";
	else if (!strcmp(os, "linux") || !strcmp(os, "linux-64"))
		vpninfo->csd_xmltag = "csdLinux";
	else if (!strcmp(os, "win"))
		vpninfo->csd_xmltag = "csd";
	else
		return -EINVAL;

	vpninfo->platname = os;
	return 0;
}

static void free_optlist (struct vpn_option *opt)
{
	struct vpn_option *next;

	for (; opt; opt = next) {
		next = opt->next;
		free(opt->option);
		free(opt->value);
		free(opt);
	}
}

void openconnect_vpninfo_free (struct openconnect_info *vpninfo)
{
	openconnect_close_https(vpninfo, 1);
	free(vpninfo->peer_addr);
	free_optlist(vpninfo->cookies);
	free_optlist(vpninfo->cstp_options);
	free_optlist(vpninfo->dtls_options);
	free(vpninfo->hostname);
	free(vpninfo->urlpath);
	free(vpninfo->redirect_url);
	free(vpninfo->proxy_type);
	free(vpninfo->proxy);

	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
	}
	free(vpninfo->csd_token);
	free(vpninfo->csd_ticket);
	free(vpninfo->csd_stuburl);
	free(vpninfo->csd_starturl);
	free(vpninfo->csd_waiturl);
	free(vpninfo->csd_preurl);
	if (vpninfo->opaque_srvdata)
		xmlFreeNode(vpninfo->opaque_srvdata);

	/* These are const in openconnect itself, but for consistency of
	   the library API we do take ownership of the strings we're given,
	   and thus we have to free them too. */
	free((void *)vpninfo->cafile);
	if (vpninfo->cert != vpninfo->sslkey)
		free((void *)vpninfo->sslkey);
	free((void *)vpninfo->cert);
	if (vpninfo->peer_cert) {
#if defined (OPENCONNECT_OPENSSL)
		X509_free(vpninfo->peer_cert);
#elif defined (OPENCONNECT_GNUTLS)
		gnutls_x509_crt_deinit(vpninfo->peer_cert);
#endif
		vpninfo->peer_cert = NULL;
	}
	free(vpninfo->useragent);
#ifdef LIBSTOKEN_HDR
	if (vpninfo->stoken_pin)
		free(vpninfo->stoken_pin);
	if (vpninfo->stoken_ctx)
		stoken_destroy(vpninfo->stoken_ctx);
#endif
	/* No need to free deflate streams; they weren't initialised */
	free(vpninfo);
}

char *openconnect_get_hostname (struct openconnect_info *vpninfo)
{
	return vpninfo->hostname;
}

void openconnect_set_hostname (struct openconnect_info *vpninfo, char *hostname)
{
	vpninfo->hostname = hostname;
}

char *openconnect_get_urlpath (struct openconnect_info *vpninfo)
{
	return vpninfo->urlpath;
}

void openconnect_set_urlpath (struct openconnect_info *vpninfo, char *urlpath)
{
	vpninfo->urlpath = urlpath;
}

void openconnect_set_xmlsha1 (struct openconnect_info *vpninfo, const char *xmlsha1, int size)
{
	if (size != sizeof (vpninfo->xmlsha1))
		return;

	memcpy (&vpninfo->xmlsha1, xmlsha1, size);
}

void openconnect_set_cafile (struct openconnect_info *vpninfo, char *cafile)
{
	vpninfo->cafile = cafile;
}

void openconnect_setup_csd (struct openconnect_info *vpninfo, uid_t uid, int silent, char *wrapper)
{
	vpninfo->uid_csd = uid;
	vpninfo->uid_csd_given = silent?2:1;
	vpninfo->csd_wrapper = wrapper;
}

void openconnect_set_client_cert (struct openconnect_info *vpninfo, char *cert, char *sslkey)
{
	vpninfo->cert = cert;
	if (sslkey)
		vpninfo->sslkey = sslkey;
	else
		vpninfo->sslkey = cert;
}

OPENCONNECT_X509 *openconnect_get_peer_cert (struct openconnect_info *vpninfo)
{
	return vpninfo->peer_cert;
}

int openconnect_get_port (struct openconnect_info *vpninfo)
{
	return vpninfo->port;
}

char *openconnect_get_cookie (struct openconnect_info *vpninfo)
{
	return vpninfo->cookie;
}

void openconnect_clear_cookie (struct openconnect_info *vpninfo)
{
	if (vpninfo->cookie)
		memset(vpninfo->cookie, 0, strlen(vpninfo->cookie));
}

void openconnect_reset_ssl (struct openconnect_info *vpninfo)
{
	openconnect_close_https(vpninfo, 0);
	if (vpninfo->peer_addr) {
		free(vpninfo->peer_addr);
		vpninfo->peer_addr = NULL;
	}
}

int openconnect_parse_url (struct openconnect_info *vpninfo, char *url)
{
	char *scheme = NULL;
	int ret;

	if (vpninfo->peer_addr) {
		free(vpninfo->peer_addr);
		vpninfo->peer_addr = NULL;
	}

	free(vpninfo->hostname);
	vpninfo->hostname = NULL;
	free(vpninfo->urlpath);
	vpninfo->urlpath = NULL;

	ret = internal_parse_url (url, &scheme, &vpninfo->hostname,
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

void openconnect_set_cert_expiry_warning (struct openconnect_info *vpninfo,
					  int seconds)
{
	vpninfo->cert_expire_warning = seconds;
}

void openconnect_set_cancel_fd (struct openconnect_info *vpninfo, int fd)
{
	vpninfo->cancel_fd = fd;
}

const char *openconnect_get_version (void)
{
	return openconnect_version_str;
}

int openconnect_has_pkcs11_support(void)
{
#if defined (OPENCONNECT_GNUTLS) && defined (HAVE_P11KIT)
	return 1;
#else
	return 0;
#endif
}

#if defined (OPENCONNECT_OPENSSL) && defined (HAVE_ENGINE)
#include <openssl/engine.h>
#endif
int openconnect_has_tss_blob_support(void)
{
#if defined (OPENCONNECT_OPENSSL) && defined (HAVE_ENGINE)
	ENGINE *e;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("tpm");
	if (e) {
		ENGINE_free(e);
		return 1;
	}
#elif defined (OPENCONNECT_GNUTLS) && defined (HAVE_TROUSERS)
	return 1;
#endif
	return 0;
}

int openconnect_has_stoken_support(void)
{
#ifdef LIBSTOKEN_HDR
	return 1;
#else
	return 0;
#endif
}

/*
 * Enable software token generation if use_stoken == 1.
 *
 * If token_str is not NULL, try to parse the string.  Otherwise, try to read
 * the token data from ~/.stokenrc
 *
 * Return value:
 *  = -EOPNOTSUPP, if libstoken is not available
 *  = -EINVAL, if the token string is invalid (token_str was provided)
 *  = -ENOENT, if ~/.stokenrc is missing (token_str was NULL)
 *  = -EIO, for other libstoken failures
 *  = 0, on success
 */
int openconnect_set_stoken_mode (struct openconnect_info *vpninfo,
				 int use_stoken, const char *token_str)
{
#ifdef LIBSTOKEN_HDR
	int ret;

	vpninfo->use_stoken = 0;
	if (!use_stoken)
		return 0;

	if (!vpninfo->stoken_ctx) {
		vpninfo->stoken_ctx = stoken_new();
		if (!vpninfo->stoken_ctx)
			return -EIO;
	}

	ret = token_str ?
	      stoken_import_string(vpninfo->stoken_ctx, token_str) :
	      stoken_import_rcfile(vpninfo->stoken_ctx, NULL);
	if (ret)
		return ret;

	vpninfo->use_stoken = 1;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}
