/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008 Intel Corporation.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/vfs.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#include "openconnect.h"

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
					  "Failed to open certificate file %s\n",
					  vpninfo->cert);
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
	if (!SSL_CTX_use_certificate_file(vpninfo->https_ctx, vpninfo->cert,
					  SSL_FILETYPE_PEM)) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Load certificate failed\n");
		report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	if (vpninfo->cert_type == CERT_TYPE_UNKNOWN) {
		FILE *f = fopen(vpninfo->sslkey, "r");
		char buf[256];

		if (!f) {
			vpninfo->progress(vpninfo, PRG_ERR,
					  "Failed to open certificate file %s\n",
					  vpninfo->cert);
			return -ENOENT;
		}

		buf[255] = 0;
		while (fgets(buf, 255, f)) {
			if (!strcmp(buf, "-----BEGIN TSS KEY BLOB-----\n")) {
				vpninfo->cert_type = CERT_TYPE_TPM;
				break;
			} else if (!strcmp(buf, "-----BEGIN RSA PRIVATE KEY-----\n") ||
				   !strcmp(buf, "-----BEGIN DSA PRIVATE KEY-----\n")) {
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
		
		vpninfo->progress(vpninfo, PRG_ERR, "Private key failed\n");
		report_ssl_errors(vpninfo);

		/* If the user fat-fingered the passphrase, try again */
		if (ERR_GET_LIB(err) == ERR_LIB_EVP &&
		    ERR_GET_FUNC(err) == EVP_F_EVP_DECRYPTFINAL_EX &&
		    ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT)
			goto again;
		
		return -EINVAL;
	}
	return 0;
}

static int verify_callback(X509_STORE_CTX *ctx, void *arg)
{
	/* We've seen certificates in the wild which don't have the
	   purpose fields filled in correctly */
	ctx->param->purpose = 0;

	/* If it succeeds, all well and good... */
	return X509_verify_cert(ctx);
}

static int check_server_cert(struct openconnect_info *vpninfo, X509 *cert)
{
	BIO *bp = BIO_new(BIO_s_mem());
	char zero = 0;
	char *tmp1, *tmp2;
	BUF_MEM *sig;
	int result = 0;

	i2a_ASN1_STRING(bp, cert->signature, V_ASN1_OCTET_STRING);
	BIO_write(bp, &zero, 1);
	BIO_get_mem_ptr(bp, &sig);
	tmp1 = sig->data;
	while ((tmp2 = strchr(tmp1, '\\'))) {
		tmp1 = tmp2++;
		while (isspace(*tmp2))
			tmp2++;
		memmove(tmp1, tmp2, strlen(tmp2) + 1);
	}

	if (strcmp(vpninfo->servercert, sig->data)) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Server SSL certificate didn't match\n");
		result = -EINVAL;
	}

	BIO_free(bp);
	return result;
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

	if (!X509_STORE_CTX_init(&ctx, store, NULL, NULL))
		return;

	while (ctx.get_issuer(&cert2, &ctx, cert) == 1) {
		char buf[200];
		if (cert2 == cert)
			break;
		X509_free(cert);
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
	SSL_METHOD *ssl3_method;
	SSL *https_ssl;
	BIO *https_bio;
	int ssl_sock;
	int err;
	struct addrinfo hints, *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	err = getaddrinfo(vpninfo->hostname, "https", &hints, &result);
	if (err) {
		vpninfo->progress(vpninfo, PRG_ERR, "getaddrinfo failed: %s\n", gai_strerror(err));
		return -EINVAL;
	}

	vpninfo->progress(vpninfo, PRG_INFO,
			  "Attempting to connect to %s\n", vpninfo->hostname);

	for (rp = result; rp ; rp = rp->ai_next) {
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
	}
	freeaddrinfo(result);

	if (!rp) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to connect to host %s\n", vpninfo->hostname);
		return -EINVAL;
	}
	fcntl(ssl_sock, F_SETFD, FD_CLOEXEC);

	ssl3_method = TLSv1_client_method();
	if (!vpninfo->https_ctx) {
		vpninfo->https_ctx = SSL_CTX_new(ssl3_method);

		err = -EPERM;
		if (vpninfo->cert)
			err = load_certificate(vpninfo);

		if (err && vpninfo->nopasswd) {
			vpninfo->progress(vpninfo, PRG_ERR, "No certificate and nopasswd set. Aborting\n");
			return err;
		}

		SSL_CTX_set_cert_verify_callback(vpninfo->https_ctx, verify_callback, vpninfo);
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

int passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	struct statfs buf;
	unsigned *fsid = (unsigned *)&buf.f_fsid;
	unsigned long long fsid64;

	vpninfo->cert_password = malloc(17);
	if (!vpninfo->cert_password)
		return -ENOMEM;

	if (statfs(vpninfo->sslkey, &buf)) {
		int err = errno;
		vpninfo->progress(vpninfo, PRG_ERR, "statfs: %s\n", strerror(errno));
		return -err;
	}
	fsid64 = ((unsigned long long)fsid[0] << 32) | fsid[1];
	sprintf(vpninfo->cert_password, "%llx", fsid64);
	return 0;
}
