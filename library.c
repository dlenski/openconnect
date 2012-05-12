/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2011 Intel Corporation.
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

#include "openconnect-internal.h"

struct openconnect_info *openconnect_vpninfo_new_with_cbdata (char *useragent,
						  openconnect_validate_peer_cert_vfn validate_peer_cert,
						  openconnect_write_new_config_vfn write_new_config,
						  openconnect_process_auth_form_vfn process_auth_form,
						  openconnect_progress_vfn progress,
						  void *privdata)
{
	struct openconnect_info *vpninfo = calloc (sizeof(*vpninfo), 1);

	vpninfo->mtu = 1406;
	vpninfo->ssl_fd = -1;
	vpninfo->cert_expire_warning = 60 * 86400;
	vpninfo->useragent = openconnect_create_useragent (useragent);
	vpninfo->validate_peer_cert = validate_peer_cert;
	vpninfo->write_new_config = write_new_config;
	vpninfo->process_auth_form = process_auth_form;
	vpninfo->progress = progress;
	vpninfo->cbdata = privdata?:vpninfo;
	vpninfo->cancel_fd = -1;

#ifdef ENABLE_NLS
	bindtextdomain("openconnect", LOCALEDIR);
#endif

	return vpninfo;
}

struct openconnect_info *openconnect_vpninfo_new (char *useragent,
						  openconnect_validate_peer_cert_fn validate_peer_cert,
						  openconnect_write_new_config_fn write_new_config,
						  openconnect_process_auth_form_fn process_auth_form,
						  openconnect_progress_fn progress)
{
	return openconnect_vpninfo_new_with_cbdata (useragent,
						    (void *)validate_peer_cert,
						    (void *)write_new_config,
						    (void *)process_auth_form,
						    (void *)progress, NULL);
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
	openconnect_reset_ssl(vpninfo);
	free_optlist(vpninfo->cookies);
	free_optlist(vpninfo->cstp_options);
	free_optlist(vpninfo->dtls_options);
	free(vpninfo->hostname);
	free(vpninfo->urlpath);
	free(vpninfo->redirect_url);
	free(vpninfo->proxy_type);
	free(vpninfo->proxy);
	free(vpninfo->csd_scriptname);
	free(vpninfo->csd_stuburl);
	/* These are const in openconnect itself, but for consistency of
	   the library API we do take ownership of the strings we're given,
	   and thus we have to free them too. */
	free((void *)vpninfo->cafile);
	if (vpninfo->cert != vpninfo->sslkey)
		free((void *)vpninfo->sslkey);
	free((void *)vpninfo->cert);
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

void openconnect_set_xmlsha1 (struct openconnect_info *vpninfo, char *xmlsha1, int size)
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

struct x509_st *openconnect_get_peer_cert (struct openconnect_info *vpninfo)
{
	return SSL_get_peer_certificate(vpninfo->https_ssl);
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
	if (vpninfo->https_ssl) {
		openconnect_close_https(vpninfo);
	}
	if (vpninfo->peer_addr) {
		free(vpninfo->peer_addr);
		vpninfo->peer_addr = NULL;
	}
	if (vpninfo->https_ctx) {
		SSL_CTX_free(vpninfo->https_ctx);
		vpninfo->https_ctx = NULL;
	}
}

int openconnect_parse_url (struct openconnect_info *vpninfo, char *url)
{
	if (vpninfo->peer_addr) {
		free(vpninfo->peer_addr);
		vpninfo->peer_addr = NULL;
	}

	return internal_parse_url (url, NULL, &vpninfo->hostname,
				   &vpninfo->port, &vpninfo->urlpath, 443);
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
