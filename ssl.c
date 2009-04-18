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
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

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


static int load_certificate(struct openconnect_info *vpninfo)
{
	vpninfo->progress(vpninfo, PRG_TRACE,
			  "Using certificate file %s\n", vpninfo->cert);

	if (!SSL_CTX_use_certificate_file(vpninfo->https_ctx, vpninfo->cert,
					  SSL_FILETYPE_PEM)) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Load certificate failed\n");
		ERR_print_errors_fp(stderr);
		return -EINVAL;
	}

	if (vpninfo->tpm) {
		ENGINE *e;
		EVP_PKEY *key;
		ENGINE_load_builtin_engines();

		e = ENGINE_by_id("tpm");
		if (!e) {
			vpninfo->progress(vpninfo, PRG_ERR, "Can't load TPM engine.\n");
			ERR_print_errors_fp(stderr);
			return -EINVAL;
		}
		if (!ENGINE_init(e) || !ENGINE_set_default_RSA(e) ||
		    !ENGINE_set_default_RAND(e)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Failed to init TPM engine\n");
			ERR_print_errors_fp(stderr);
			ENGINE_free(e);
			return -EINVAL;
		}

		if (vpninfo->tpmpass) {
			if (!ENGINE_ctrl_cmd(e, "PIN", strlen(vpninfo->tpmpass),
					     vpninfo->tpmpass, NULL, 0)) {
				vpninfo->progress(vpninfo, PRG_ERR, "Failed to set TPM SRK password\n");
				ERR_print_errors_fp(stderr);
			}
		}
		key = ENGINE_load_private_key(e, vpninfo->sslkey, NULL, NULL);
		if (!key) {
			vpninfo->progress(vpninfo, PRG_ERR,
				"Failed to load TPM private key\n");
			ERR_print_errors_fp(stderr);
			ENGINE_free(e);
			ENGINE_finish(e);
			return -EINVAL;
		}
		if (!SSL_CTX_use_PrivateKey(vpninfo->https_ctx, key)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Add key from TPM failed\n");
			ERR_print_errors_fp(stderr);
			ENGINE_free(e);
			ENGINE_finish(e);
			return -EINVAL;
		}
	} else {
		if (!SSL_CTX_use_RSAPrivateKey_file(vpninfo->https_ctx,
						    vpninfo->sslkey,
						    SSL_FILETYPE_PEM)) {
			vpninfo->progress(vpninfo, PRG_ERR, "Private key failed\n");
			ERR_print_errors_fp(stderr);
			return -EINVAL;
		}
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

	if (vpninfo->validate_peer_cert)
		return vpninfo->validate_peer_cert(vpninfo, peer_cert);

	/* If no validation function, just let it succeed */
	return 0;
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

	https_bio = BIO_new_socket(ssl_sock, BIO_NOCLOSE);
	SSL_set_bio(https_ssl, https_bio, https_bio);

	vpninfo->progress(vpninfo, PRG_INFO,
			  "SSL negotiation with %s\n", vpninfo->hostname);

	if (SSL_connect(https_ssl) <= 0) {
		vpninfo->progress(vpninfo, PRG_ERR, "SSL connection failure\n");
		ERR_print_errors_fp(stderr);
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

