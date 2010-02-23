/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2010 Intel Corporation.
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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#if defined(__linux__)
#include <sys/vfs.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <sys/param.h>
#include <sys/mount.h>
#elif defined (__sun__)
#include <sys/statvfs.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#include "openconnect.h"

/* OSX < 1.6 doesn't have AI_NUMERICSERV */
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

/* Helper functions for reading/writing lines over SSL.
   We could use cURL for the HTTP stuff, but it's overkill */

int  __attribute__ ((format (printf, 2, 3)))
	openconnect_SSL_printf(SSL *ssl, const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	buf[1023] = 0;

	va_start(args, fmt);
	vsnprintf(buf, 1023, fmt, args);
	va_end(args);
	return SSL_write(ssl, buf, strlen(buf));

}

static int print_err(const char *str, size_t len, void *ptr)
{
	struct openconnect_info *vpninfo = ptr;

	vpninfo->progress(vpninfo, PRG_ERR, "%s", str);
	return 0;
}

void report_ssl_errors(struct openconnect_info *vpninfo)
{
	ERR_print_errors_cb(print_err, vpninfo);
}

int openconnect_SSL_gets(SSL *ssl, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while ( (ret = SSL_read(ssl, buf + i, 1)) == 1) {
		if (buf[i] == '\n') {
			buf[i] = 0;
			if (i && buf[i-1] == '\r') {
				buf[i-1] = 0;
				i--;
			}
			return i;
		}
		i++;

		if (i >= len - 1) {
			buf[i] = 0;
			return i;
		}
	}
	if (ret == 0) {
		ret = -SSL_get_error(ssl, ret);
	}
	buf[i] = 0;
	return i ?: ret;
}

static int pem_pw_cb(char *buf, int len, int w, void *v)
{
	struct openconnect_info *vpninfo = v;

	/* Only try the provided password once... */
	SSL_CTX_set_default_passwd_cb(vpninfo->https_ctx, NULL);
	SSL_CTX_set_default_passwd_cb_userdata(vpninfo->https_ctx, NULL);

	if (len <= strlen(vpninfo->cert_password)) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "PEM password too long (%zd >= %d)\n",
				  strlen(vpninfo->cert_password), len);
		return -1;
	}
	strcpy(buf, vpninfo->cert_password);
	return strlen(vpninfo->cert_password);
}

static int load_pkcs12_certificate(struct openconnect_info *vpninfo, PKCS12 *p12)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = sk_X509_new_null();
	int ret = 0;
	char pass[PEM_BUFSIZE];

	if (!vpninfo->cert_password) {
		if (EVP_read_pw_string(pass, PEM_BUFSIZE,
				       "Enter PKCS#12 pass phrase:", 0))
			return -EINVAL;
	}
	if (!PKCS12_parse(p12, vpninfo->cert_password?:pass, &pkey, &cert, &ca)) {
		vpninfo->progress(vpninfo, PRG_ERR, "Parse PKCS#12 failed\n");
		report_ssl_errors(vpninfo);
		PKCS12_free(p12);
		return -EINVAL;
	}
	if (cert) {
		SSL_CTX_use_certificate(vpninfo->https_ctx, cert);
		X509_free(cert);
	} else {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "PKCS#12 contained no certificate!");
		ret = -EINVAL;
	}

	if (pkey) {
		SSL_CTX_use_PrivateKey(vpninfo->https_ctx, pkey);
		EVP_PKEY_free(pkey);
	} else {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "PKCS#12 contained no private key!");
		ret = -EINVAL;
	}

	/* Only include supporting certificates which are actually necessary */
	if (ca) {
		int i;
	next:
		for (i = 0; i < sk_X509_num(ca); i++) {
			X509 *cert2 = sk_X509_value(ca, i);
			if (X509_check_issued(cert2, cert) == X509_V_OK) {
				char buf[200];

				if (cert2 == cert)
					break;

				X509_NAME_oneline(X509_get_subject_name(cert2),
						  buf, sizeof(buf));
				vpninfo->progress(vpninfo, PRG_DEBUG,
						  "Extra cert from PKCS#12: '%s'\n", buf);
				SSL_CTX_add_extra_chain_cert(vpninfo->https_ctx, cert2);
				cert = cert2;
				goto next;
			}
		}
		sk_X509_free(ca);
	}

	PKCS12_free(p12);
	return ret;
}

static int load_tpm_certificate(struct openconnect_info *vpninfo)
{
	ENGINE *e;
	EVP_PKEY *key;
	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("tpm");
	if (!e) {
		vpninfo->progress(vpninfo, PRG_ERR, "Can't load TPM engine.\n");
		report_ssl_errors(vpninfo);
		return -EINVAL;
	}
	if (!ENGINE_init(e) || !ENGINE_set_default_RSA(e) ||
	    !ENGINE_set_default_RAND(e)) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to init TPM engine\n");
		report_ssl_errors(vpninfo);
		ENGINE_free(e);
		return -EINVAL;
	}

	if (vpninfo->cert_password) {
		if (!ENGINE_ctrl_cmd(e, "PIN", strlen(vpninfo->cert_password),
				     vpninfo->cert_password, NULL, 0)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Failed to set TPM SRK password\n");
			report_ssl_errors(vpninfo);
		}
	}
	key = ENGINE_load_private_key(e, vpninfo->sslkey, NULL, NULL);
	if (!key) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Failed to load TPM private key\n");
		report_ssl_errors(vpninfo);
		ENGINE_free(e);
		ENGINE_finish(e);
		return -EINVAL;
	}
	if (!SSL_CTX_use_PrivateKey(vpninfo->https_ctx, key)) {
		vpninfo->progress(vpninfo, PRG_ERR, "Add key from TPM failed\n");
		report_ssl_errors(vpninfo);
		ENGINE_free(e);
		ENGINE_finish(e);
		return -EINVAL;
	}
	return 0;
}

static int load_certificate(struct openconnect_info *vpninfo)
{
	vpninfo->progress(vpninfo, PRG_TRACE,
			  "Using certificate file %s\n", vpninfo->cert);

	if (vpninfo->cert_type == CERT_TYPE_PKCS12 ||
	    vpninfo->cert_type == CERT_TYPE_UNKNOWN) {
		FILE *f;
		PKCS12 *p12;

		f = fopen(vpninfo->cert, "r");
		if (!f) {
			vpninfo->progress(vpninfo, PRG_ERR,
					  "Failed to open certificate file %s: %s\n",
					  vpninfo->cert, strerror(errno));
			return -ENOENT;
		}
		p12 = d2i_PKCS12_fp(f, NULL);
		fclose(f);
		if (p12)
			return load_pkcs12_certificate(vpninfo, p12);

		/* Not PKCS#12 */
		if (vpninfo->cert_type == CERT_TYPE_PKCS12) {
			vpninfo->progress(vpninfo, PRG_ERR, "Read PKCS#12 failed\n");
			report_ssl_errors(vpninfo);
			return -EINVAL;
		}
		/* Clear error and fall through to see if it's a PEM file... */
		ERR_clear_error();
	}

	/* It's PEM or TPM now, and either way we need to load the plain cert: */
	if (!SSL_CTX_use_certificate_chain_file(vpninfo->https_ctx,
						vpninfo->cert)) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Loading certificate failed\n");
		report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	if (vpninfo->cert_type == CERT_TYPE_UNKNOWN) {
		FILE *f = fopen(vpninfo->sslkey, "r");
		char buf[256];

		if (!f) {
			vpninfo->progress(vpninfo, PRG_ERR,
					  "Failed to open private key file %s: %s\n",
					  vpninfo->cert, strerror(errno));
			return -ENOENT;
		}

		buf[255] = 0;
		while (fgets(buf, 255, f)) {
			if (!strcmp(buf, "-----BEGIN TSS KEY BLOB-----\n")) {
				vpninfo->cert_type = CERT_TYPE_TPM;
				break;
			} else if (!strcmp(buf, "-----BEGIN RSA PRIVATE KEY-----\n") ||
				   !strcmp(buf, "-----BEGIN DSA PRIVATE KEY-----\n") ||
				   !strcmp(buf, "-----BEGIN ENCRYPTED PRIVATE KEY-----\n")) {
				vpninfo->cert_type = CERT_TYPE_PEM;
				break;
			}
		}
		fclose(f);
		if (vpninfo->cert_type == CERT_TYPE_UNKNOWN) {
			vpninfo->progress(vpninfo, PRG_ERR,
					  "Failed to identify private key type in '%s'\n",
					  vpninfo->sslkey);
			return -EINVAL;
		}
	}

	if (vpninfo->cert_type == CERT_TYPE_TPM)
		return load_tpm_certificate(vpninfo);

	/* Standard PEM certificate */
	if (vpninfo->cert_password) {
		SSL_CTX_set_default_passwd_cb(vpninfo->https_ctx,
					      pem_pw_cb);
		SSL_CTX_set_default_passwd_cb_userdata(vpninfo->https_ctx,
						       vpninfo);
	}
 again:
	if (!SSL_CTX_use_RSAPrivateKey_file(vpninfo->https_ctx, vpninfo->sslkey,
					    SSL_FILETYPE_PEM)) {
		unsigned long err = ERR_peek_error();
		
		vpninfo->progress(vpninfo, PRG_ERR, "Loading private key failed\n");
		report_ssl_errors(vpninfo);

#ifndef EVP_F_EVP_DECRYPTFINAL_EX
#define EVP_F_EVP_DECRYPTFINAL_EX EVP_F_EVP_DECRYPTFINAL
#endif
		/* If the user fat-fingered the passphrase, try again */
		if (ERR_GET_LIB(err) == ERR_LIB_EVP &&
		    ERR_GET_FUNC(err) == EVP_F_EVP_DECRYPTFINAL_EX &&
		    ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT)
			goto again;
		
		return -EINVAL;
	}
	return 0;
}

enum cert_hash_type {
	EVP_MD5,
	EVP_SHA1
};

static int get_cert_fingerprint(struct openconnect_info *vpninfo,
				X509 *cert, enum cert_hash_type hash,
				char *buf)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int i, n;

	switch (hash) {
	case EVP_MD5:
		if (!X509_digest(cert, EVP_md5(), md, &n))
			return -ENOMEM;
		break;
	case EVP_SHA1:
		if (!X509_digest(cert, EVP_sha1(), md, &n))
			return -ENOMEM;
		break;
	default:
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Unsupported SSL certificate hash function type\n");
	}

	for (i=0; i < n; i++) {
		sprintf(&buf[i*2], "%02X", md[i]);
	}
	return 0;
}

int get_cert_md5_fingerprint(struct openconnect_info *vpninfo,
			     X509 *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, EVP_MD5, buf);
}

int get_cert_sha1_fingerprint(struct openconnect_info *vpninfo,
			      X509 *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, EVP_SHA1, buf);
}

static int check_server_cert(struct openconnect_info *vpninfo, X509 *cert)
{
	char fingerprint[EVP_MAX_MD_SIZE * 2 + 1];
	int ret;

	ret = get_cert_sha1_fingerprint(vpninfo, cert, fingerprint);
	if (ret)
		return ret;

	if (strcasecmp(vpninfo->servercert, fingerprint)) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Server SSL certificate didn't match: %s\n", fingerprint);
		return -EINVAL;
	}
	return 0;
}

static int verify_peer(struct openconnect_info *vpninfo, SSL *https_ssl)
{
	X509 *peer_cert;

	if (vpninfo->cafile) {
		int vfy = SSL_get_verify_result(https_ssl);

		if (vfy != X509_V_OK) {
			vpninfo->progress(vpninfo, PRG_ERR, "Server certificate verify failed: %s\n",
				X509_verify_cert_error_string(vfy));
			return -EINVAL;
		}
		return 0;
	}

	peer_cert = SSL_get_peer_certificate(https_ssl);

	if (vpninfo->servercert)
		return check_server_cert(vpninfo, peer_cert);

	if (vpninfo->validate_peer_cert)
		return vpninfo->validate_peer_cert(vpninfo, peer_cert);

	/* If no validation function, just let it succeed */
	return 0;
}

void workaround_openssl_certchain_bug(struct openconnect_info *vpninfo,
				      SSL *ssl)
{
	/* OpenSSL has problems with certificate chains -- if there are
	   multiple certs with the same name, it doesn't necessarily
	   choose the _right_ one. (RT#1942)
	   Pick the right ones for ourselves and add them manually. */
	X509 *cert = SSL_get_certificate(ssl);
	X509 *cert2;
	X509_STORE *store = SSL_CTX_get_cert_store(vpninfo->https_ctx);
	X509_STORE_CTX ctx;

	if (!cert || !store)
		return;

	/* If we already have 'supporting' certs, don't add them again */
	if (vpninfo->https_ctx->extra_certs)
		return;

	if (!X509_STORE_CTX_init(&ctx, store, NULL, NULL))
		return;

	while (ctx.get_issuer(&cert2, &ctx, cert) == 1) {
		char buf[200];
		if (cert2 == cert)
			break;
		cert = cert2;
		X509_NAME_oneline(X509_get_subject_name(cert),
				  buf, sizeof(buf));
		vpninfo->progress(vpninfo, PRG_DEBUG,
				  "Extra cert from cafile: '%s'\n", buf);
		SSL_CTX_add_extra_chain_cert(vpninfo->https_ctx, cert);
	}
	X509_STORE_CTX_cleanup(&ctx);
}

int openconnect_open_https(struct openconnect_info *vpninfo)
{
	method_const SSL_METHOD *ssl3_method;
	SSL *https_ssl;
	BIO *https_bio;
	int ssl_sock = -1;
	int err;

	if (!vpninfo->port)
		vpninfo->port = 443;

	if (vpninfo->peer_addr) {
		ssl_sock = socket(vpninfo->peer_addr->sa_family, SOCK_STREAM, IPPROTO_IP);
		if (ssl_sock < 0) {
		reconn_err:
			vpninfo->progress(vpninfo, PRG_ERR, "Failed to reconnect to %s %s\n",
					  vpninfo->proxy?"proxy":"host",
					  vpninfo->proxy?:vpninfo->hostname);
			return -EINVAL;
		}
		if (connect(ssl_sock, vpninfo->peer_addr, vpninfo->peer_addrlen))
			goto reconn_err;
		
	} else {
		struct addrinfo hints, *result, *rp;
		char *hostname;
		char port[6];

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
		hints.ai_protocol = 0;
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		/* The 'port' variable is a string because it's easier
		   this way than if we pass NULL to getaddrinfo() and
		   then try to fill in the numeric value into
		   different types of returned sockaddr_in{6,}. */
#ifdef OPENCONNECT_LIBPROXY
		if (vpninfo->proxy_factory) {
			char *url;
			char **proxies;
			int i = 0;

			free(vpninfo->proxy_type);
			vpninfo->proxy_type = NULL;
			free(vpninfo->proxy);
			vpninfo->proxy = NULL;

			if (vpninfo->port == 443)
				i = asprintf(&url, "https://%s/%s", vpninfo->hostname,
					     vpninfo->urlpath?:"");
			else
				i = asprintf(&url, "https://%s:%d/%s", vpninfo->hostname,
					     vpninfo->port, vpninfo->urlpath?:"");
			if (i == -1)
				return -ENOMEM;

			proxies = px_proxy_factory_get_proxies(vpninfo->proxy_factory,
							       url);

			while (proxies && proxies[i]) {
				if (!vpninfo->proxy &&
				    (!strncmp(proxies[i], "http://", 7) ||
				     !strncmp(proxies[i], "socks://", 8) ||
				     !strncmp(proxies[i], "socks5://", 9)))
					parse_url(proxies[i], &vpninfo->proxy_type,
						  &vpninfo->proxy, &vpninfo->proxy_port,
						  NULL, 0);
				i++;
			}
			free(url);
			free(proxies);
			if (vpninfo->proxy)
				vpninfo->progress(vpninfo, PRG_TRACE, "Proxy from libproxy: %s://%s:%d/\n",
						  vpninfo->proxy_type, vpninfo->proxy, vpninfo->port);
		}
#endif
		if (vpninfo->proxy) {
			hostname = vpninfo->proxy;
			snprintf(port, 6, "%d", vpninfo->proxy_port);
		} else {
			hostname = vpninfo->hostname;
			snprintf(port, 6, "%d", vpninfo->port);
		}

		if (hostname[0] == '[' && hostname[strlen(hostname)-1] == ']') {
			/* Solaris has no strndup(). */
			int len = strlen(hostname) - 2;
			char *new_hostname = malloc(len + 1);
			if (!new_hostname)
				return -ENOMEM;
			memcpy(new_hostname, hostname + 1, len);
			new_hostname[len] = 0;

			hostname = new_hostname;
			hints.ai_flags |= AI_NUMERICHOST;
		}

		err = getaddrinfo(hostname, port, &hints, &result);
		if (hints.ai_flags & AI_NUMERICHOST)
			free(hostname);

		if (err) {
			vpninfo->progress(vpninfo, PRG_ERR, "getaddrinfo failed: %s\n",
					  gai_strerror(err));
			return -EINVAL;
		}

		for (rp = result; rp ; rp = rp->ai_next) {
			char host[80];

			if (!getnameinfo(rp->ai_addr, rp->ai_addrlen, host,
					 sizeof(host), NULL, 0, NI_NUMERICHOST))
				vpninfo->progress(vpninfo, PRG_INFO,
						  "Attempting to connect to %s%s%s:%s\n",
						  rp->ai_family == AF_INET6?"[":"",
						  host,
						  rp->ai_family == AF_INET6?"]":"",
						  port);
			
			ssl_sock = socket(rp->ai_family, rp->ai_socktype,
					  rp->ai_protocol);
			if (ssl_sock < 0)
				continue;
			if (connect(ssl_sock, rp->ai_addr, rp->ai_addrlen) >= 0) {
				/* Store the peer address we actually used, so that DTLS can
				   use it again later */
				vpninfo->peer_addr = malloc(rp->ai_addrlen);
				if (!vpninfo->peer_addr) {
					vpninfo->progress(vpninfo, PRG_ERR, "Failed to allocate sockaddr storage\n");
					close(ssl_sock);
					return -ENOMEM;
				}
				vpninfo->peer_addrlen = rp->ai_addrlen;
				memcpy(vpninfo->peer_addr, rp->ai_addr, rp->ai_addrlen);
				break;
			}
			close(ssl_sock);
			ssl_sock = -1;
		}
		freeaddrinfo(result);
		
		if (ssl_sock < 0) {
			vpninfo->progress(vpninfo, PRG_ERR, "Failed to connect to host %s\n",
					  vpninfo->proxy?:vpninfo->hostname);
			return -EINVAL;
		}
	}
	fcntl(ssl_sock, F_SETFD, FD_CLOEXEC);

	if (vpninfo->proxy) {
		err = process_proxy(vpninfo, ssl_sock);
		if (err) {
			close(ssl_sock);
			return err;
		}
	}

	ssl3_method = TLSv1_client_method();
	if (!vpninfo->https_ctx) {
		vpninfo->https_ctx = SSL_CTX_new(ssl3_method);

		if (vpninfo->cert) {
			err = load_certificate(vpninfo);
			if (err) {
				vpninfo->progress(vpninfo, PRG_ERR,
						  "Loading certificate failed. Aborting.\n");
				return err;
			}
		}

		/* We've seen certificates in the wild which don't have the
		   purpose fields filled in correctly */
		SSL_CTX_set_purpose(vpninfo->https_ctx, X509_PURPOSE_ANY);
		SSL_CTX_set_default_verify_paths(vpninfo->https_ctx);

		if (vpninfo->cafile)
			SSL_CTX_load_verify_locations(vpninfo->https_ctx, vpninfo->cafile, NULL);

	}
	https_ssl = SSL_new(vpninfo->https_ctx);
	workaround_openssl_certchain_bug(vpninfo, https_ssl);

	https_bio = BIO_new_socket(ssl_sock, BIO_NOCLOSE);
	SSL_set_bio(https_ssl, https_bio, https_bio);

	vpninfo->progress(vpninfo, PRG_INFO,
			  "SSL negotiation with %s\n", vpninfo->hostname);

	if (SSL_connect(https_ssl) <= 0) {
		vpninfo->progress(vpninfo, PRG_ERR, "SSL connection failure\n");
		report_ssl_errors(vpninfo);
		SSL_free(https_ssl);
		close(ssl_sock);
		return -EINVAL;
	}

	if (verify_peer(vpninfo, https_ssl)) {
		SSL_free(https_ssl);
		close(ssl_sock);
		return -EINVAL;
	}

	vpninfo->ssl_fd = ssl_sock;
	vpninfo->https_ssl = https_ssl;

	vpninfo->progress(vpninfo, PRG_INFO,
			  "Connected to HTTPS on %s\n", vpninfo->hostname);

	return 0;
}

void openconnect_close_https(struct openconnect_info *vpninfo)
{
	SSL_free(vpninfo->https_ssl);
	vpninfo->https_ssl = NULL;
	close(vpninfo->ssl_fd);
	FD_CLR(vpninfo->ssl_fd, &vpninfo->select_rfds);
	FD_CLR(vpninfo->ssl_fd, &vpninfo->select_wfds);
	FD_CLR(vpninfo->ssl_fd, &vpninfo->select_efds);
	vpninfo->ssl_fd = -1;
}

void openconnect_init_openssl(void)
{
	SSL_library_init ();
	ERR_clear_error ();
	SSL_load_error_strings ();
	OpenSSL_add_all_algorithms ();
}

#ifdef __sun__
int passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	struct statvfs buf;

	if (statvfs(vpninfo->sslkey, &buf)) {
		int err = errno;
		vpninfo->progress(vpninfo, PRG_ERR, "statvfs: %s\n", strerror(errno));
		return -err;
	}
	if (asprintf(&vpninfo->cert_password, "%lx", buf.f_fsid))
		return -ENOMEM;
	return 0;
}
#else
int passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	struct statfs buf;
	unsigned *fsid = (unsigned *)&buf.f_fsid;
	unsigned long long fsid64;

	if (statfs(vpninfo->sslkey, &buf)) {
		int err = errno;
		vpninfo->progress(vpninfo, PRG_ERR, "statfs: %s\n", strerror(errno));
		return -err;
	}
	fsid64 = ((unsigned long long)fsid[0] << 32) | fsid[1];

	if (asprintf(&vpninfo->cert_password, "%llx", fsid64))
		return -ENOMEM;
	return 0;
}
#endif
