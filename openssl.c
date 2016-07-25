/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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

#include <config.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "openconnect-internal.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/ui.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_up_ref(x) 	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509)
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#define X509_STORE_CTX_get0_chain(ctx) ((ctx)->chain)
#define X509_STORE_CTX_get0_untrusted(ctx) ((ctx)->untrusted)
#define X509_STORE_CTX_get0_cert(ctx) ((ctx)->cert)
typedef int (*X509_STORE_CTX_get_issuer_fn)(X509 **issuer,
					    X509_STORE_CTX *ctx, X509 *x);
#define X509_STORE_CTX_get_get_issuer(ctx) ((ctx)->get_issuer)
#endif

int openconnect_sha1(unsigned char *result, void *data, int len)
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();

	if (!c)
		return -ENOMEM;

	EVP_Digest(data, len, result, NULL, EVP_sha1(), NULL);
	EVP_MD_CTX_free(c);

	return 0;
}

int openconnect_md5(unsigned char *result, void *data, int len)
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();

	if (!c)
		return -ENOMEM;

	EVP_Digest(data, len, result, NULL, EVP_md5(), NULL);
	EVP_MD_CTX_free(c);

	return 0;
}

int openconnect_get_peer_cert_DER(struct openconnect_info *vpninfo,
				  unsigned char **buf)
{
	BIO *bp = BIO_new(BIO_s_mem());
	BUF_MEM *certinfo;
	size_t l;

	if (!i2d_X509_bio(bp, vpninfo->peer_cert)) {
		BIO_free(bp);
		return -EIO;
	}

	BIO_get_mem_ptr(bp, &certinfo);
	l = certinfo->length;
	*buf = malloc(l);
	if (!*buf) {
		BIO_free(bp);
		return -ENOMEM;
	}
	memcpy(*buf, certinfo->data, l);
	BIO_free(bp);
	return l;
}

int openconnect_random(void *bytes, int len)
{
	if (RAND_bytes(bytes, len) != 1)
		return -EIO;
	return 0;
}

/* Helper functions for reading/writing lines over SSL.
   We could use cURL for the HTTP stuff, but it's overkill */

static int openconnect_openssl_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	size_t orig_len = len;

	while (len) {
		int done = SSL_write(vpninfo->https_ssl, buf, len);

		if (done > 0)
			len -= done;
		else {
			int err = SSL_get_error(vpninfo->https_ssl, done);
			fd_set wr_set, rd_set;
			int maxfd = vpninfo->ssl_fd;

			FD_ZERO(&wr_set);
			FD_ZERO(&rd_set);

			if (err == SSL_ERROR_WANT_READ)
				FD_SET(vpninfo->ssl_fd, &rd_set);
			else if (err == SSL_ERROR_WANT_WRITE)
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else {
				vpn_progress(vpninfo, PRG_ERR, _("Failed to write to SSL socket\n"));
				openconnect_report_ssl_errors(vpninfo);
				return -EIO;
			}
			cmd_fd_set(vpninfo, &rd_set, &maxfd);
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (is_cancel_pending(vpninfo, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL write cancelled\n"));
				return -EINTR;
			}
		}
	}
	return orig_len;
}

static int openconnect_openssl_read(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int done;

	while ((done = SSL_read(vpninfo->https_ssl, buf, len)) == -1) {
		int err = SSL_get_error(vpninfo->https_ssl, done);
		fd_set wr_set, rd_set;
		int maxfd = vpninfo->ssl_fd;

		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);

		if (err == SSL_ERROR_WANT_READ)
			FD_SET(vpninfo->ssl_fd, &rd_set);
		else if (err == SSL_ERROR_WANT_WRITE)
			FD_SET(vpninfo->ssl_fd, &wr_set);
		else {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to read from SSL socket\n"));
			openconnect_report_ssl_errors(vpninfo);
			return -EIO;
		}
		cmd_fd_set(vpninfo, &rd_set, &maxfd);
		select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
		if (is_cancel_pending(vpninfo, &rd_set)) {
			vpn_progress(vpninfo, PRG_ERR, _("SSL read cancelled\n"));
			return -EINTR;
		}
	}
	return done;
}

static int openconnect_openssl_gets(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while (1) {
		ret = SSL_read(vpninfo->https_ssl, buf + i, 1);
		if (ret == 1) {
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
		} else {
			fd_set rd_set, wr_set;
			int maxfd = vpninfo->ssl_fd;

			FD_ZERO(&rd_set);
			FD_ZERO(&wr_set);

			ret = SSL_get_error(vpninfo->https_ssl, ret);
			if (ret == SSL_ERROR_WANT_READ)
				FD_SET(vpninfo->ssl_fd, &rd_set);
			else if (ret == SSL_ERROR_WANT_WRITE)
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else {
				vpn_progress(vpninfo, PRG_ERR, _("Failed to read from SSL socket\n"));
				openconnect_report_ssl_errors(vpninfo);
				ret = -EIO;
				break;
			}
			cmd_fd_set(vpninfo, &rd_set, &maxfd);
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (is_cancel_pending(vpninfo, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL read cancelled\n"));
				ret = -EINTR;
				break;
			}
		}
	}
	buf[i] = 0;
	return i ?: ret;
}

int ssl_nonblock_read(struct openconnect_info *vpninfo, void *buf, int maxlen)
{
	int len, ret;

	len = SSL_read(vpninfo->https_ssl, buf, maxlen);
	if (len > 0)
		return len;

	ret = SSL_get_error(vpninfo->https_ssl, len);
	if (ret == SSL_ERROR_SYSCALL || ret == SSL_ERROR_ZERO_RETURN) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("SSL read error %d (server probably closed connection); reconnecting.\n"),
			     ret);
		return -EIO;
	}
	return 0;
}

int ssl_nonblock_write(struct openconnect_info *vpninfo, void *buf, int buflen)
{
	int ret;

	ret = SSL_write(vpninfo->https_ssl, buf, buflen);
	if (ret > 0)
		return ret;

	ret = SSL_get_error(vpninfo->https_ssl, ret);
	switch (ret) {
	case SSL_ERROR_WANT_WRITE:
		/* Waiting for the socket to become writable -- it's
		   probably stalled, and/or the buffers are full */
		monitor_write_fd(vpninfo, ssl);
	case SSL_ERROR_WANT_READ:
		return 0;

	default:
		vpn_progress(vpninfo, PRG_ERR, _("SSL_write failed: %d\n"), ret);
		openconnect_report_ssl_errors(vpninfo);
		return -1;
	}
}

/* UI handling. All this just to handle the PIN callback from the TPM ENGINE,
   and turn it into a call to our ->process_auth_form function */

struct ui_data {
	struct openconnect_info *vpninfo;
	struct oc_form_opt **last_opt;
	struct oc_auth_form form;
};

struct ui_form_opt {
	struct oc_form_opt opt;
	UI_STRING *uis;
};

#ifdef HAVE_ENGINE
 /* Ick. But there is no way to pass this sanely through OpenSSL */
static struct openconnect_info *ui_vpninfo;

static int ui_open(UI *ui)
{
	struct openconnect_info *vpninfo = ui_vpninfo; /* Ick */
	struct ui_data *ui_data;

	if (!vpninfo || !vpninfo->process_auth_form)
		return 0;

	ui_data = malloc(sizeof(*ui_data));
	if (!ui_data)
		return 0;

	memset(ui_data, 0, sizeof(*ui_data));
	ui_data->last_opt = &ui_data->form.opts;
	ui_data->vpninfo = vpninfo;
	ui_data->form.auth_id = (char *)"openssl_ui";
	UI_add_user_data(ui, ui_data);

	return 1;
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	struct ui_data *ui_data = UI_get0_user_data(ui);
	struct ui_form_opt *opt;

	switch (UI_get_string_type(uis)) {
	case UIT_ERROR:
		ui_data->form.error = (char *)UI_get0_output_string(uis);
		break;
	case UIT_INFO:
		ui_data->form.message = (char *)UI_get0_output_string(uis);
		break;
	case UIT_PROMPT:
		opt = malloc(sizeof(*opt));
		if (!opt)
			return 1;
		memset(opt, 0, sizeof(*opt));
		opt->uis = uis;
		opt->opt.label = opt->opt.name = (char *)UI_get0_output_string(uis);
		if (UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO)
			opt->opt.type = OC_FORM_OPT_TEXT;
		else
			opt->opt.type = OC_FORM_OPT_PASSWORD;
		*(ui_data->last_opt) = &opt->opt;
		ui_data->last_opt = &opt->opt.next;
		break;

	default:
		vpn_progress(ui_data->vpninfo, PRG_ERR,
			     _("Unhandled SSL UI request type %d\n"),
			     UI_get_string_type(uis));
		return 0;
	}
	return 1;
}

static int ui_flush(UI *ui)
{
	struct ui_data *ui_data = UI_get0_user_data(ui);
	struct openconnect_info *vpninfo = ui_data->vpninfo;
	struct ui_form_opt *opt;
	int ret;

	ret = process_auth_form(vpninfo, &ui_data->form);
	if (ret)
		return 0;

	for (opt = (struct ui_form_opt *)ui_data->form.opts; opt;
	     opt = (struct ui_form_opt *)opt->opt.next) {
		if (opt->opt._value && opt->uis)
			UI_set_result(ui, opt->uis, opt->opt._value);
	}
	return 1;
}

static int ui_close(UI *ui)
{
	struct ui_data *ui_data = UI_get0_user_data(ui);
	struct ui_form_opt *opt, *next_opt;

	opt = (struct ui_form_opt *)ui_data->form.opts;
	while (opt) {
		next_opt = (struct ui_form_opt *)opt->opt.next;
		if (opt->opt._value)
			free(opt->opt._value);
		free(opt);
		opt = next_opt;
	}
	free(ui_data);
	UI_add_user_data(ui, NULL);

	return 1;
}

static UI_METHOD *create_openssl_ui(struct openconnect_info *vpninfo)
{
	UI_METHOD *ui_method = UI_create_method((char *)"AnyConnect VPN UI");

	/* There is a race condition here because of the use of the
	   static ui_vpninfo pointer. This sucks, but it's OpenSSL's
	   fault and in practice it's *never* going to hurt us.

	   This UI is only used for loading certificates from a TPM; for
	   PKCS#12 and PEM files we hook the passphrase request differently.
	   The ui_vpninfo variable is set here, and is used from ui_open()
	   when the TPM ENGINE decides it needs to ask the user for a PIN.

	   The race condition exists because theoretically, there
	   could be more than one thread using libopenconnect and
	   trying to authenticate to a VPN server, within the *same*
	   process. And if *both* are using certificates from the TPM,
	   and *both* manage to be within that short window of time
	   between setting ui_vpninfo and invoking ui_open() to fetch
	   the PIN, then one connection's ->process_auth_form() could
	   get a PIN request for the *other* connection.

	   However, the only thing that ever does run libopenconnect more
	   than once from the same process is KDE's NetworkManager support,
	   and NetworkManager doesn't *support* having more than one VPN
	   connected anyway, so first that would have to be fixed and then
	   you'd have to connect to two VPNs simultaneously by clicking
	   'connect' on both at *exactly* the same time and then getting
	   *really* unlucky.

	   Oh, and the KDE support won't be using OpenSSL anyway because of
	   licensing conflicts... so although this sucks, I'm not going to
	   lose sleep over it.
	*/
	ui_vpninfo = vpninfo;

	/* Set up a UI method of our own for password/passphrase requests */
	UI_method_set_opener(ui_method, ui_open);
	UI_method_set_writer(ui_method, ui_write);
	UI_method_set_flusher(ui_method, ui_flush);
	UI_method_set_closer(ui_method, ui_close);

	return ui_method;
}
#endif

static int pem_pw_cb(char *buf, int len, int w, void *v)
{
	struct openconnect_info *vpninfo = v;
	char *pass = NULL;
	int plen;

	if (vpninfo->cert_password) {
		pass = vpninfo->cert_password;
		vpninfo->cert_password = NULL;
	} else if (request_passphrase(vpninfo, "openconnect_pem",
				      &pass, _("Enter PEM pass phrase:")))
		return -1;

	plen = strlen(pass);

	if (len <= plen) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PEM password too long (%d >= %d)\n"),
			     plen, len);
		free(pass);
		return -1;
	}

	memcpy(buf, pass, plen+1);
	free(pass);
	return plen;
}

static int install_extra_certs(struct openconnect_info *vpninfo, const char *source,
			       STACK_OF(X509) *ca)
{
	X509 *cert = vpninfo->cert_x509;
	int i;

 next:
	for (i = 0; i < sk_X509_num(ca); i++) {
		X509 *cert2 = sk_X509_value(ca, i);
		if (X509_check_issued(cert2, cert) == X509_V_OK) {
			char buf[200];

			if (cert2 == cert)
				break;
			if (X509_check_issued(cert2, cert2) == X509_V_OK)
				break;

			X509_NAME_oneline(X509_get_subject_name(cert2),
					  buf, sizeof(buf));
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Extra cert from %s: '%s'\n"), source, buf);
			X509_up_ref(cert2);
			SSL_CTX_add_extra_chain_cert(vpninfo->https_ctx, cert2);
			cert = cert2;
			goto next;
		}
	}
	sk_X509_pop_free(ca, X509_free);

	return 0;
}

static int load_pkcs12_certificate(struct openconnect_info *vpninfo, PKCS12 *p12)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca;
	int ret = 0;
	char *pass;

	pass = vpninfo->cert_password;
	vpninfo->cert_password = NULL;
 retrypass:
	/* We do this every time round the loop, to work around a bug in
	   OpenSSL < 1.0.0-beta2 -- where the stack at *ca will be freed
	   when PKCS12_parse() returns an error, but *ca is left pointing
	   to the freed memory. */
	ca = NULL;
	if (!PKCS12_parse(p12, pass, &pkey, &cert, &ca)) {
		unsigned long err = ERR_peek_error();

		if (ERR_GET_LIB(err) == ERR_LIB_PKCS12 &&
		    ERR_GET_FUNC(err) == PKCS12_F_PKCS12_PARSE &&
		    ERR_GET_REASON(err) == PKCS12_R_MAC_VERIFY_FAILURE) {
			if (pass)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to decrypt PKCS#12 certificate file\n"));
			free(pass);
			if (request_passphrase(vpninfo, "openconnect_pkcs12", &pass,
					       _("Enter PKCS#12 pass phrase:")) < 0) {
				PKCS12_free(p12);
				return -EINVAL;
			}

			goto retrypass;
		}

		openconnect_report_ssl_errors(vpninfo);

		vpn_progress(vpninfo, PRG_ERR,
			     _("Parse PKCS#12 failed (see above errors)\n"));
		PKCS12_free(p12);
		free(pass);
		return -EINVAL;
	}
	free(pass);
	if (cert) {
		char buf[200];
		vpninfo->cert_x509 = cert;
		SSL_CTX_use_certificate(vpninfo->https_ctx, cert);
		X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
		vpn_progress(vpninfo, PRG_INFO,
			     _("Using client certificate '%s'\n"), buf);
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PKCS#12 contained no certificate!"));
		ret = -EINVAL;
	}

	if (pkey) {
		SSL_CTX_use_PrivateKey(vpninfo->https_ctx, pkey);
		EVP_PKEY_free(pkey);
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PKCS#12 contained no private key!"));
		ret = -EINVAL;
	}

	if (ca)
		install_extra_certs(vpninfo, _("PKCS#12"), ca);

	PKCS12_free(p12);
	return ret;
}

#ifdef HAVE_ENGINE
static int load_tpm_certificate(struct openconnect_info *vpninfo)
{
	ENGINE *e;
	EVP_PKEY *key;
	UI_METHOD *meth = NULL;
	int ret = 0;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("tpm");
	if (!e) {
		vpn_progress(vpninfo, PRG_ERR, _("Can't load TPM engine.\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}
	if (!ENGINE_init(e) || !ENGINE_set_default_RSA(e) ||
	    !ENGINE_set_default_RAND(e)) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to init TPM engine\n"));
		openconnect_report_ssl_errors(vpninfo);
		ENGINE_free(e);
		return -EINVAL;
	}

	if (vpninfo->cert_password) {
		if (!ENGINE_ctrl_cmd(e, "PIN", strlen(vpninfo->cert_password),
				     vpninfo->cert_password, NULL, 0)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to set TPM SRK password\n"));
			openconnect_report_ssl_errors(vpninfo);
		}
		vpninfo->cert_password = NULL;
		free(vpninfo->cert_password);
	} else {
		/* Provide our own UI method to handle the PIN callback. */
		meth = create_openssl_ui(vpninfo);
	}
	key = ENGINE_load_private_key(e, vpninfo->sslkey, meth, NULL);
	if (meth)
		UI_destroy_method(meth);
	if (!key) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load TPM private key\n"));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EINVAL;
		goto out;
	}
	if (!SSL_CTX_use_PrivateKey(vpninfo->https_ctx, key)) {
		vpn_progress(vpninfo, PRG_ERR, _("Add key from TPM failed\n"));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EINVAL;
	}
	EVP_PKEY_free(key);
 out:
	ENGINE_finish(e);
	ENGINE_free(e);
	return ret;
}
#else
static int load_tpm_certificate(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without TPM support\n"));
	return -EINVAL;
}
#endif

/* This is a reimplementation of SSL_CTX_use_certificate_chain_file().
 * We do this for three reasons:
 *
 * - Firstly, we have no way to obtain the primary X509 certificate
 *   after SSL_CTX_use_certificate_chain_file() has loaded it, and we
 *   need to inspect it to check for expiry and report its name etc.
 *   So in the past we've opened the cert file again and read the cert
 *   again in a reload_pem_cert() function which was a partial
 *   reimplementation anyway.
 *
 * - Secondly, on Windows, OpenSSL only partially handles UTF-8 filenames.
 *   Specifically, BIO_new_file() will convert UTF-8 to UTF-16 and attempt
 *   to use _wfopen() to open the file, but BIO_read_filename() will not.
 *   It is BIO_read_filename() which the SSL_CTX_*_file functions use, and
 *   thus they don't work with UTF-8 file names. This is filed as RT#3479:
 *   http://rt.openssl.org/Ticket/Display.html?id=3479
 *
 * - Finally, and least importantly, it does actually matter which supporting
 *   certs we offer on the wire because of RT#1942. Doing this for ourselves
 *   allows us to explicitly print the supporting certs that we're using,
 *   which may assist in diagnosing problems.
 */
static int load_cert_chain_file(struct openconnect_info *vpninfo)
{
	BIO *b;
	FILE *f = openconnect_fopen_utf8(vpninfo, vpninfo->cert, "rb");
	STACK_OF(X509) *extra_certs = NULL;
	char buf[200];

	if (!f) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open certificate file %s: %s\n"),
			     vpninfo->cert, strerror(errno));
		return -ENOENT;
	}

	b = BIO_new_fp(f, 1);
	if (!b) {
		fclose(f);
	err:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Loading certificate failed\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}
	vpninfo->cert_x509 = PEM_read_bio_X509_AUX(b, NULL, NULL, NULL);
	if (!vpninfo->cert_x509) {
		BIO_free(b);
		goto err;
	}

	X509_NAME_oneline(X509_get_subject_name(vpninfo->cert_x509), buf, sizeof(buf));
	vpn_progress(vpninfo, PRG_INFO,
			     _("Using client certificate '%s'\n"), buf);

	if (!SSL_CTX_use_certificate(vpninfo->https_ctx, vpninfo->cert_x509)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to install certificate in OpenSSL context\n"));
		openconnect_report_ssl_errors(vpninfo);
		BIO_free(b);
		return -EIO;
	}

	while (1) {
		X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
		if (!x) {
			unsigned long err = ERR_peek_last_error();
			if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
			    ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
				ERR_clear_error();
			else
				goto err_extra;
			break;
		}
		if (!extra_certs)
			extra_certs = sk_X509_new_null();
		if (!extra_certs) {
		err_extra:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to process all supporting certs. Trying anyway...\n"));
			openconnect_report_ssl_errors(vpninfo);
			X509_free(x);
			/* It might work without... */
			break;
		}
		if (!sk_X509_push(extra_certs, x))
			goto err_extra;
	}

	BIO_free(b);

	if (extra_certs)
		install_extra_certs(vpninfo, _("PEM file"), extra_certs);

	return 0;
}

#ifdef ANDROID_KEYSTORE
static BIO *BIO_from_keystore(struct openconnect_info *vpninfo, const char *item)
{
	unsigned char *content;
	BIO *b;
	int len;
	const char *p = item + 9;

	/* Skip first two slashes if the user has given it as
	   keystore://foo ... */
	if (*p == '/')
		p++;
	if (*p == '/')
		p++;

	len = keystore_fetch(p, &content);
	if (len < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load item '%s' from keystore: %s\n"),
			     p, keystore_strerror(len));
		return NULL;
	}
	if (!(b = BIO_new(BIO_s_mem())) || BIO_write(b, content, len) != len) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create BIO for keystore item '%s'\n"),
			       p);
		free(content);
		BIO_free(b);
		return NULL;
	}
	free(content);
	return b;
}
#endif

static int is_pem_password_error(struct openconnect_info *vpninfo)
{
	unsigned long err = ERR_peek_error();

	openconnect_report_ssl_errors(vpninfo);

#ifndef EVP_F_EVP_DECRYPTFINAL_EX
#define EVP_F_EVP_DECRYPTFINAL_EX EVP_F_EVP_DECRYPTFINAL
#endif
	/* If the user fat-fingered the passphrase, try again */
	if (ERR_GET_LIB(err) == ERR_LIB_EVP &&
	    ERR_GET_FUNC(err) == EVP_F_EVP_DECRYPTFINAL_EX &&
	    ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Loading private key failed (wrong passphrase?)\n"));
		ERR_clear_error();
		return 1;
	}

	vpn_progress(vpninfo, PRG_ERR,
		     _("Loading private key failed (see above errors)\n"));
	return 0;
}

static int load_certificate(struct openconnect_info *vpninfo)
{
	FILE *f;
	char buf[256];

	if (!strncmp(vpninfo->cert, "pkcs11:", 7)) {
		int ret = load_pkcs11_certificate(vpninfo);
		if (ret)
			return ret;
		goto got_cert;
	}

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Using certificate file %s\n"), vpninfo->cert);

	if (strncmp(vpninfo->cert, "keystore:", 9)) {
		PKCS12 *p12;

		f = openconnect_fopen_utf8(vpninfo, vpninfo->cert, "rb");
		if (!f) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open certificate file %s: %s\n"),
				     vpninfo->cert, strerror(errno));
			return -ENOENT;
		}
		p12 = d2i_PKCS12_fp(f, NULL);
		fclose(f);
		if (p12)
			return load_pkcs12_certificate(vpninfo, p12);

		/* Not PKCS#12. Clear error and fall through to see if it's a PEM file... */
		ERR_clear_error();
	}

	/* It's PEM or TPM now, and either way we need to load the plain cert: */
#ifdef ANDROID_KEYSTORE
	if (!strncmp(vpninfo->cert, "keystore:", 9)) {
		BIO *b = BIO_from_keystore(vpninfo, vpninfo->cert);
		if (!b)
			return -EINVAL;
		vpninfo->cert_x509 = PEM_read_bio_X509_AUX(b, NULL, pem_pw_cb, vpninfo);
		BIO_free(b);
		if (!vpninfo->cert_x509) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to load X509 certificate from keystore\n"));
			openconnect_report_ssl_errors(vpninfo);
			return -EINVAL;
		}
		if (!SSL_CTX_use_certificate(vpninfo->https_ctx, vpninfo->cert_x509)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to use X509 certificate from keystore\n"));
			openconnect_report_ssl_errors(vpninfo);
			X509_free(vpninfo->cert_x509);
			vpninfo->cert_x509 = NULL;
			return -EINVAL;
		}
	} else
#endif /* ANDROID_KEYSTORE */
	{
		int ret = load_cert_chain_file(vpninfo);
		if (ret)
			return ret;
	}

 got_cert:
#ifdef ANDROID_KEYSTORE
	if (!strncmp(vpninfo->sslkey, "keystore:", 9)) {
		EVP_PKEY *key;
		BIO *b;

	again_android:
		b = BIO_from_keystore(vpninfo, vpninfo->sslkey);
		if (!b)
			return -EINVAL;
		key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb, vpninfo);
		BIO_free(b);
		if (!key) {
			if (is_pem_password_error(vpninfo))
				goto again_android;
			return -EINVAL;
		}
		if (!SSL_CTX_use_PrivateKey(vpninfo->https_ctx, key)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to use private key from keystore\n"));
			EVP_PKEY_free(key);
			X509_free(vpninfo->cert_x509);
			vpninfo->cert_x509 = NULL;
			return -EINVAL;
		}
		return 0;
	}
#endif /* ANDROID_KEYSTORE */
	if (!strncmp(vpninfo->sslkey, "pkcs11:", 7))
		return load_pkcs11_key(vpninfo);

	f = openconnect_fopen_utf8(vpninfo, vpninfo->sslkey, "rb");
	if (!f) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open private key file %s: %s\n"),
			     vpninfo->cert, strerror(errno));
		return -ENOENT;
	}

	buf[255] = 0;
	while (fgets(buf, 255, f)) {
		if (!strcmp(buf, "-----BEGIN TSS KEY BLOB-----\n")) {
			fclose(f);
			return load_tpm_certificate(vpninfo);
		} else if (!strcmp(buf, "-----BEGIN RSA PRIVATE KEY-----\n") ||
			   !strcmp(buf, "-----BEGIN DSA PRIVATE KEY-----\n") ||
			   !strcmp(buf, "-----BEGIN ENCRYPTED PRIVATE KEY-----\n") ||
			   !strcmp(buf, "-----BEGIN PRIVATE KEY-----\n")) {
			RSA *key;
			BIO *b = BIO_new_fp(f, BIO_CLOSE);

			if (!b) {
				fclose(f);
				vpn_progress(vpninfo, PRG_ERR,
					     _("Loading private key failed\n"));
				openconnect_report_ssl_errors(vpninfo);
			}
		again:
			fseek(f, 0, SEEK_SET);
			key = PEM_read_bio_RSAPrivateKey(b, NULL, pem_pw_cb, vpninfo);
			if (!key) {
				if (is_pem_password_error(vpninfo))
					goto again;
				BIO_free(b);
				return -EINVAL;
			}
			SSL_CTX_use_RSAPrivateKey(vpninfo->https_ctx, key);
			RSA_free(key);
			BIO_free(b);
			return 0;
		}
	}
	fclose(f);

	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to identify private key type in '%s'\n"),
		     vpninfo->sslkey);
	return -EINVAL;
}

static int get_cert_fingerprint(struct openconnect_info *vpninfo,
				X509 *cert, const EVP_MD *type,
				char *buf)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int i, n;

	if (!X509_digest(cert, type, md, &n))
		return -ENOMEM;

	for (i = 0; i < n; i++)
		sprintf(&buf[i*2], "%02X", md[i]);

	return 0;
}

int get_cert_md5_fingerprint(struct openconnect_info *vpninfo,
			     void *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, EVP_md5(), buf);
}

static int set_peer_cert_hash(struct openconnect_info *vpninfo)
{
	unsigned char sha1[SHA1_SIZE];
	EVP_PKEY *pkey;
	BIO *bp = BIO_new(BIO_s_mem());
	BUF_MEM *keyinfo;
	int i;

	/* We can't use X509_pubkey_digest() because it only hashes the
	   subjectPublicKey BIT STRING, and not the whole of the
	   SubjectPublicKeyInfo SEQUENCE. */
	pkey = X509_get_pubkey(vpninfo->peer_cert);

	if (!i2d_PUBKEY_bio(bp, pkey)) {
		EVP_PKEY_free(pkey);
		BIO_free(bp);
		return -ENOMEM;
	}
	EVP_PKEY_free(pkey);

	BIO_get_mem_ptr(bp, &keyinfo);

	openconnect_sha1(sha1, keyinfo->data, keyinfo->length);

	BIO_free(bp);

	vpninfo->peer_cert_hash = malloc(SHA1_SIZE * 2 + 6);
	if (vpninfo->peer_cert_hash) {
		snprintf(vpninfo->peer_cert_hash, 6, "sha1:");
		for (i = 0; i < sizeof(sha1); i++)
			sprintf(&vpninfo->peer_cert_hash[i*2 + 5], "%02x", sha1[i]);
	}

	return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10002000L
static int match_hostname_elem(const char *hostname, int helem_len,
			       const char *match, int melem_len)
{
	if (!helem_len && !melem_len)
		return 0;

	if (!helem_len || !melem_len)
		return -1;


	if (match[0] == '*') {
		int i;

		for (i = 1 ; i <= helem_len; i++) {
			if (!match_hostname_elem(hostname + i, helem_len - i,
						 match + 1, melem_len - 1))
				return 0;
		}
		return -1;
	}

	/* From the NetBSD (5.1) man page for ctype(3):
	   Values of type char or signed char must first be cast to unsigned char,
	   to ensure that the values are within the correct range.  The result
	   should then be cast to int to avoid warnings from some compilers.
	   We do indeed get warning "array subscript has type 'char'" without
	   the casts. Ick. */
	if (toupper((int)(unsigned char)hostname[0]) ==
	    toupper((int)(unsigned char)match[0]))
		return match_hostname_elem(hostname + 1, helem_len - 1,
					   match + 1, melem_len - 1);

	return -1;
}

static int match_hostname(const char *hostname, const char *match)
{
	while (*match) {
		const char *h_dot, *m_dot;
		int helem_len, melem_len;

		h_dot = strchr(hostname, '.');
		m_dot = strchr(match, '.');

		if (h_dot && m_dot) {
			helem_len = h_dot - hostname + 1;
			melem_len = m_dot - match + 1;
		} else if (!h_dot && !m_dot) {
			helem_len = strlen(hostname);
			melem_len = strlen(match);
		} else
			return -1;


		if (match_hostname_elem(hostname, helem_len,
					match, melem_len))
			return -1;

		hostname += helem_len;
		match += melem_len;
	}
	if (*hostname)
		return -1;

	return 0;
}

/* cf. RFC2818 and RFC2459 */
static int match_cert_hostname(struct openconnect_info *vpninfo, X509 *peer_cert,
			       const unsigned char *ipaddr, int ipaddrlen)
{
	STACK_OF(GENERAL_NAME) *altnames;
	X509_NAME *subjname;
	ASN1_STRING *subjasn1;
	char *subjstr = NULL;
	int i, altdns = 0;
	int ret;

	altnames = X509_get_ext_d2i(peer_cert, NID_subject_alt_name,
				    NULL, NULL);
	for (i = 0; i < sk_GENERAL_NAME_num(altnames); i++) {
		const GENERAL_NAME *this = sk_GENERAL_NAME_value(altnames, i);

		if (this->type == GEN_DNS) {
			char *str;

			int len = ASN1_STRING_to_UTF8((void *)&str, this->d.ia5);
			if (len < 0)
				continue;

			altdns = 1;

			/* We don't like names with embedded NUL */
			if (strlen(str) != len)
				continue;

			if (!match_hostname(vpninfo->hostname, str)) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Matched DNS altname '%s'\n"),
					     str);
				GENERAL_NAMES_free(altnames);
				OPENSSL_free(str);
				return 0;
			} else {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("No match for altname '%s'\n"),
					     str);
			}
			OPENSSL_free(str);
		} else if (this->type == GEN_IPADD && ipaddrlen) {
			char host[80];
			int family;

			if (this->d.ip->length == 4) {
				family = AF_INET;
			} else if (this->d.ip->length == 16) {
				family = AF_INET6;
			} else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Certificate has GEN_IPADD altname with bogus length %d\n"),
					     this->d.ip->length);
				continue;
			}

			/* We only do this for the debug messages */
			inet_ntop(family, this->d.ip->data, host, sizeof(host));

			if (this->d.ip->length == ipaddrlen &&
			    !memcmp(ipaddr, this->d.ip->data, ipaddrlen)) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Matched %s address '%s'\n"),
					     (family == AF_INET6) ? "IPv6" : "IPv4",
					     host);
				GENERAL_NAMES_free(altnames);
				return 0;
			} else {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("No match for %s address '%s'\n"),
					     (family == AF_INET6) ? "IPv6" : "IPv4",
					     host);
			}
		} else if (this->type == GEN_URI) {
			char *str;
			char *url_proto, *url_host, *url_path, *url_host2;
			int url_port;
			int len = ASN1_STRING_to_UTF8((void *)&str, this->d.ia5);

			if (len < 0)
				continue;

			/* We don't like names with embedded NUL */
			if (strlen(str) != len)
				continue;

			if (internal_parse_url(str, &url_proto, &url_host, &url_port, &url_path, 0)) {
				OPENSSL_free(str);
				continue;
			}

			if (!url_proto || strcasecmp(url_proto, "https"))
				goto no_uri_match;

			if (url_port != vpninfo->port)
				goto no_uri_match;

			/* Leave url_host as it was so that it can be freed */
			url_host2 = url_host;
			if (ipaddrlen == 16 && vpninfo->hostname[0] != '[' &&
			    url_host[0] == '[' && url_host[strlen(url_host)-1] == ']') {
				/* Cope with https://[IPv6]/ when the hostname is bare IPv6 */
				url_host[strlen(url_host)-1] = 0;
				url_host2++;
			}

			if (strcasecmp(vpninfo->hostname, url_host2))
				goto no_uri_match;

			if (url_path) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("URI '%s' has non-empty path; ignoring\n"),
					     str);
				goto no_uri_match_silent;
			}
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Matched URI '%s'\n"),
				     str);
			free(url_proto);
			free(url_host);
			free(url_path);
			OPENSSL_free(str);
			GENERAL_NAMES_free(altnames);
			return 0;

		no_uri_match:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("No match for URI '%s'\n"),
				     str);
		no_uri_match_silent:
			free(url_proto);
			free(url_host);
			free(url_path);
			OPENSSL_free(str);
		}
	}
	GENERAL_NAMES_free(altnames);

	/* According to RFC2818, we don't use the legacy subject name if
	   there was an altname with DNS type. */
	if (altdns) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No altname in peer cert matched '%s'\n"),
			     vpninfo->hostname);
		return -EINVAL;
	}

	subjname = X509_get_subject_name(peer_cert);
	if (!subjname) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No subject name in peer cert!\n"));
		return -EINVAL;
	}

	/* Find the _last_ (most specific) commonName */
	i = -1;
	while (1) {
		int j = X509_NAME_get_index_by_NID(subjname, NID_commonName, i);
		if (j >= 0)
			i = j;
		else
			break;
	}

	subjasn1 = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subjname, i));

	i = ASN1_STRING_to_UTF8((void *)&subjstr, subjasn1);

	if (!subjstr || strlen(subjstr) != i) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse subject name in peer cert\n"));
		return -EINVAL;
	}
	ret = 0;

	if (match_hostname(vpninfo->hostname, subjstr)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Peer cert subject mismatch ('%s' != '%s')\n"),
			     subjstr, vpninfo->hostname);
		ret = -EINVAL;
	} else {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Matched peer certificate subject name '%s'\n"),
			     subjstr);
	}

	OPENSSL_free(subjstr);
	return ret;
}
#else
static int match_cert_hostname(struct openconnect_info *vpninfo, X509 *peer_cert,
			       const unsigned char *ipaddr, int ipaddrlen)
{
	char *matched = NULL;

	if (ipaddrlen && X509_check_ip(peer_cert, ipaddr, ipaddrlen, 0)) {
		if (vpninfo->verbose >= PRG_DEBUG) {
			char host[80];
			int family;

			if (ipaddrlen == 4)
				family = AF_INET;
			else
				family = AF_INET6;

			inet_ntop(family, ipaddr, host, sizeof(host));
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Matched %s address '%s'\n"),
				     (family == AF_INET6) ? "IPv6" : "IPv4",
				     host);
		}
		return 0;
	}
	if (X509_check_host(peer_cert, vpninfo->hostname, 0, 0, &matched)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Matched peer certificate subject name '%s'\n"),
			     matched);
		OPENSSL_free(matched);
		return 0;
	}

	/* We do it like this because these two strings are already
	 * translated in gnutls.c */
	vpn_progress(vpninfo, PRG_INFO,
		     _("Server certificate verify failed: %s\n"),
		     _("certificate does not match hostname"));

	return -EINVAL;
}
#endif /* OpenSSL < 1.0.2 */

/* Before OpenSSL 1.1 we could do this directly. And needed to. */
#ifndef SSL_CTX_get_extra_chain_certs_only
#define SSL_CTX_get_extra_chain_certs_only(ctx, st) \
	do { *(st) = (ctx)->extra_certs; } while(0)
#endif

static void workaround_openssl_certchain_bug(struct openconnect_info *vpninfo,
					     SSL *ssl)
{
	/* OpenSSL has problems with certificate chains -- if there are
	   multiple certs with the same name, it doesn't necessarily
	   choose the _right_ one. (RT#1942)
	   Pick the right ones for ourselves and add them manually. */
	X509 *cert = SSL_get_certificate(ssl);
	X509 *cert2;
	X509_STORE *store = SSL_CTX_get_cert_store(vpninfo->https_ctx);
	X509_STORE_CTX *ctx;
	void *extra_certs;
	X509_STORE_CTX_get_issuer_fn issuer_fn;

	if (!cert || !store)
		return;

	/* If we already have 'supporting' certs, don't add them again */
	SSL_CTX_get_extra_chain_certs_only(vpninfo->https_ctx, &extra_certs);
	if (extra_certs)
		return;

	ctx = X509_STORE_CTX_new();
	if (!ctx)
		return;
	if (X509_STORE_CTX_init(ctx, store, NULL, NULL))
		goto out;

	issuer_fn = X509_STORE_CTX_get_get_issuer(ctx);

	while (issuer_fn(&cert2, ctx, cert) == 1) {
		char buf[200];
		if (cert2 == cert)
			break;
		if (X509_check_issued(cert2, cert2) == X509_V_OK)
			break;
		cert = cert2;
		X509_NAME_oneline(X509_get_subject_name(cert),
				  buf, sizeof(buf));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Extra cert from cafile: '%s'\n"), buf);
		SSL_CTX_add_extra_chain_cert(vpninfo->https_ctx, cert);
	}
 out:
	X509_STORE_CTX_free(ctx);
}

int openconnect_get_peer_cert_chain(struct openconnect_info *vpninfo,
				    struct oc_cert **chainp)
{
	struct oc_cert *chain, *p;
	X509_STORE_CTX *ctx = vpninfo->cert_list_handle;
	STACK_OF(X509) *untrusted = X509_STORE_CTX_get0_untrusted(ctx);
	int i, cert_list_size;

	if (!ctx)
		return -EINVAL;

	cert_list_size = sk_X509_num(untrusted);
	if (!cert_list_size)
		return -EIO;

	p = chain = calloc(cert_list_size, sizeof(struct oc_cert));
	if (!chain)
		return -ENOMEM;

	for (i = 0; i < cert_list_size; i++, p++) {
		X509 *cert = sk_X509_value(untrusted, i);

		p->der_len = i2d_X509(cert, &p->der_data);
		if (p->der_len < 0) {
			openconnect_free_peer_cert_chain(vpninfo, chain);
			return -ENOMEM;
		}
	}

	*chainp = chain;
	return cert_list_size;
}

void openconnect_free_peer_cert_chain(struct openconnect_info *vpninfo,
				      struct oc_cert *chain)
{
	int i;

	for (i = 0; i < vpninfo->cert_list_size; i++)
		OPENSSL_free(chain[i].der_data);
	free(chain);
}

static int ssl_app_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
	struct openconnect_info *vpninfo = arg;
	const char *err_string = NULL;
	X509 *cert = X509_STORE_CTX_get0_cert(ctx);

	if (vpninfo->peer_cert) {
		/* This is a *rehandshake*. Require that the server
		 * presents exactly the same certificate as the
		 * first time. */
		if (X509_cmp(cert, vpninfo->peer_cert)) {
			vpn_progress(vpninfo, PRG_ERR, _("Server presented different cert on rehandshake\n"));
			return 0;
		}
		vpn_progress(vpninfo, PRG_TRACE, _("Server presented identical cert on rehandshake\n"));
		return 1;
	}
	vpninfo->peer_cert = cert;
	X509_up_ref(cert);

	set_peer_cert_hash(vpninfo);

	if (!X509_verify_cert(ctx)) {
		err_string = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
	} else {
		unsigned char addrbuf[sizeof(struct in6_addr)];
		int addrlen = 0;

		if (inet_pton(AF_INET, vpninfo->hostname, addrbuf) > 0)
			addrlen = 4;
		else if (inet_pton(AF_INET6, vpninfo->hostname, addrbuf) > 0)
			addrlen = 16;
		else if (vpninfo->hostname[0] == '[' &&
			 vpninfo->hostname[strlen(vpninfo->hostname)-1] == ']') {
			char *p = &vpninfo->hostname[strlen(vpninfo->hostname)-1];
			*p = 0;
			if (inet_pton(AF_INET6, vpninfo->hostname + 1, addrbuf) > 0)
				addrlen = 16;
			*p = ']';
		}

		if (match_cert_hostname(vpninfo, vpninfo->peer_cert, addrbuf, addrlen))
			err_string = _("certificate does not match hostname");
		else
			return 1;
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Server certificate verify failed: %s\n"),
		     err_string);

	if (vpninfo->validate_peer_cert) {
		int ret;

		vpninfo->cert_list_handle = ctx;
		ret = vpninfo->validate_peer_cert(vpninfo->cbdata, err_string);
		vpninfo->cert_list_handle = NULL;

		if (!ret)
			return 1;
	}

	return 0;
}

static int check_certificate_expiry(struct openconnect_info *vpninfo)
{
	ASN1_TIME *notAfter;
	const char *reason = NULL;
	time_t t;
	int i;

	if (!vpninfo->cert_x509)
		return 0;

	t = time(NULL);
	notAfter = X509_get_notAfter(vpninfo->cert_x509);
	i = X509_cmp_time(notAfter, &t);
	if (!i) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error in client cert notAfter field\n"));
		return -EINVAL;
	} else if (i < 0) {
		reason = _("Client certificate has expired at");
	} else {
		t += vpninfo->cert_expire_warning;
		i = X509_cmp_time(notAfter, &t);
		if (i < 0)
			reason = _("Client certificate expires soon at");
	}
	if (reason) {
		BIO *bp = BIO_new(BIO_s_mem());
		BUF_MEM *bm;
		const char *expiry = _("<error>");
		char zero = 0;

		if (bp) {
			ASN1_TIME_print(bp, notAfter);
			BIO_write(bp, &zero, 1);
			BIO_get_mem_ptr(bp, &bm);
			expiry = bm->data;
		}
		vpn_progress(vpninfo, PRG_ERR, "%s: %s\n", reason, expiry);
		if (bp)
			BIO_free(bp);
	}
	return 0;
}

int openconnect_open_https(struct openconnect_info *vpninfo)
{
	method_const SSL_METHOD *ssl3_method;
	SSL *https_ssl;
	BIO *https_bio;
	int ssl_sock;
	int err;

	if (vpninfo->https_ssl)
		return 0;

	if (vpninfo->peer_cert) {
		X509_free(vpninfo->peer_cert);
		vpninfo->peer_cert = NULL;
	}
	free (vpninfo->peer_cert_hash);
	vpninfo->peer_cert_hash = NULL;
	vpninfo->cstp_cipher = NULL;

	ssl_sock = connect_https_socket(vpninfo);
	if (ssl_sock < 0)
		return ssl_sock;

	ssl3_method = TLSv1_client_method();
	if (!vpninfo->https_ctx) {
		vpninfo->https_ctx = SSL_CTX_new(ssl3_method);

		/* Some servers (or their firewalls) really don't like seeing
		   extensions. */
#ifdef SSL_OP_NO_TICKET
		SSL_CTX_set_options(vpninfo->https_ctx, SSL_OP_NO_TICKET);
#endif

		if (vpninfo->cert) {
			err = load_certificate(vpninfo);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Loading certificate failed. Aborting.\n"));
				SSL_CTX_free(vpninfo->https_ctx);
				vpninfo->https_ctx = NULL;
				closesocket(ssl_sock);
				return err;
			}
			check_certificate_expiry(vpninfo);
		}

		/* We've seen certificates in the wild which don't have the
		   purpose fields filled in correctly */
		SSL_CTX_set_purpose(vpninfo->https_ctx, X509_PURPOSE_ANY);
		SSL_CTX_set_cert_verify_callback(vpninfo->https_ctx,
						 ssl_app_verify_callback, vpninfo);

		if (!vpninfo->no_system_trust)
			SSL_CTX_set_default_verify_paths(vpninfo->https_ctx);

		if (vpninfo->pfs)
			SSL_CTX_set_cipher_list(vpninfo->https_ctx, "HIGH:!aNULL:!eNULL:-RSA");

#ifdef ANDROID_KEYSTORE
		if (vpninfo->cafile && !strncmp(vpninfo->cafile, "keystore:", 9)) {
			STACK_OF(X509_INFO) *stack;
			X509_STORE *store;
			X509_INFO *info;
			BIO *b = BIO_from_keystore(vpninfo, vpninfo->cafile);

			if (!b) {
				SSL_CTX_free(vpninfo->https_ctx);
				vpninfo->https_ctx = NULL;
				closesocket(ssl_sock);
				return -EINVAL;
			}

			stack = PEM_X509_INFO_read_bio(b, NULL, NULL, NULL);
			BIO_free(b);

			if (!stack) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to read certs from CA file '%s'\n"),
					     vpninfo->cafile);
				openconnect_report_ssl_errors(vpninfo);
				SSL_CTX_free(vpninfo->https_ctx);
				vpninfo->https_ctx = NULL;
				closesocket(ssl_sock);
				return -ENOENT;
			}

			store = SSL_CTX_get_cert_store(vpninfo->https_ctx);

			while ((info = sk_X509_INFO_pop(stack))) {
				if (info->x509)
					X509_STORE_add_cert(store, info->x509);
				if (info->crl)
					X509_STORE_add_crl(store, info->crl);
				X509_INFO_free(info);
			}
			sk_X509_INFO_free(stack);
		} else
#endif
		if (vpninfo->cafile) {
			/* OpenSSL does actually manage to cope with UTF-8 for
			   this one, under Windows. So only convert for legacy
			   UNIX. */
			char *cafile = openconnect_utf8_to_legacy(vpninfo,
								  vpninfo->cafile);
			err = SSL_CTX_load_verify_locations(vpninfo->https_ctx,
							    cafile, NULL);
			if (cafile != vpninfo->cafile)
				free(cafile);
			if (!err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to open CA file '%s'\n"),
					     vpninfo->cafile);
				openconnect_report_ssl_errors(vpninfo);
				SSL_CTX_free(vpninfo->https_ctx);
				vpninfo->https_ctx = NULL;
				closesocket(ssl_sock);
				return -EINVAL;
			}
		}

	}
	https_ssl = SSL_new(vpninfo->https_ctx);
	workaround_openssl_certchain_bug(vpninfo, https_ssl);

	https_bio = BIO_new_socket(ssl_sock, BIO_NOCLOSE);
	BIO_set_nbio(https_bio, 1);
	SSL_set_bio(https_ssl, https_bio, https_bio);
	/*
	 * If a ClientHello is between 256 and 511 bytes, the
	 * server cannot distinguish between a SSLv2 formatted
	 * packet and a SSLv3 formatted packet.
	 *
	 * F5 BIG-IP reverse proxies in particular will
	 * silently drop an ambiguous ClientHello.
	 *
	 * OpenSSL fixes this in v1.0.1g+ by padding ClientHello
	 * packets to at least 512 bytes.
	 *
	 * For older versions of OpenSSL, we try to avoid long
	 * packets by silently disabling extensions such as SNI.
	 *
	 * Discussion:
	 * http://www.ietf.org/mail-archive/web/tls/current/msg10423.html
	 *
	 * OpenSSL commits:
	 * 4fcdd66fff5fea0cfa1055c6680a76a4303f28a2
	 * cd6bd5ffda616822b52104fee0c4c7d623fd4f53
	 */
#if OPENSSL_VERSION_NUMBER >= 0x10001070
	if (string_is_hostname(vpninfo->hostname))
		SSL_set_tlsext_host_name(https_ssl, vpninfo->hostname);
#endif
	SSL_set_verify(https_ssl, SSL_VERIFY_PEER, NULL);

	vpn_progress(vpninfo, PRG_INFO, _("SSL negotiation with %s\n"),
		     vpninfo->hostname);

	while ((err = SSL_connect(https_ssl)) <= 0) {
		fd_set wr_set, rd_set;
		int maxfd = ssl_sock;

		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);

		err = SSL_get_error(https_ssl, err);
		if (err == SSL_ERROR_WANT_READ)
			FD_SET(ssl_sock, &rd_set);
		else if (err == SSL_ERROR_WANT_WRITE)
			FD_SET(ssl_sock, &wr_set);
		else {
			vpn_progress(vpninfo, PRG_ERR, _("SSL connection failure\n"));
			openconnect_report_ssl_errors(vpninfo);
			SSL_free(https_ssl);
			closesocket(ssl_sock);
			return -EINVAL;
		}

		cmd_fd_set(vpninfo, &rd_set, &maxfd);
		select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
		if (is_cancel_pending(vpninfo, &rd_set)) {
			vpn_progress(vpninfo, PRG_ERR, _("SSL connection cancelled\n"));
			SSL_free(https_ssl);
			closesocket(ssl_sock);
			return -EINVAL;
		}
	}

	vpninfo->cstp_cipher = (char *)SSL_get_cipher_name(https_ssl);

	vpninfo->ssl_fd = ssl_sock;
	vpninfo->https_ssl = https_ssl;

	vpninfo->ssl_read = openconnect_openssl_read;
	vpninfo->ssl_write = openconnect_openssl_write;
	vpninfo->ssl_gets = openconnect_openssl_gets;


	vpn_progress(vpninfo, PRG_INFO, _("Connected to HTTPS on %s\n"),
		     vpninfo->hostname);

	return 0;
}

int cstp_handshake(struct openconnect_info *vpninfo, unsigned init)
{
	return -EOPNOTSUPP;
}

void openconnect_close_https(struct openconnect_info *vpninfo, int final)
{
	if (vpninfo->https_ssl) {
		SSL_free(vpninfo->https_ssl);
		vpninfo->https_ssl = NULL;
	}
	if (vpninfo->ssl_fd != -1) {
		closesocket(vpninfo->ssl_fd);
		unmonitor_read_fd(vpninfo, ssl);
		unmonitor_write_fd(vpninfo, ssl);
		unmonitor_except_fd(vpninfo, ssl);
		vpninfo->ssl_fd = -1;
	}
	if (final) {
		if (vpninfo->https_ctx) {
			SSL_CTX_free(vpninfo->https_ctx);
			vpninfo->https_ctx = NULL;
		}
		if (vpninfo->cert_x509) {
			X509_free(vpninfo->cert_x509);
			vpninfo->cert_x509 = NULL;
		}
	}
}

int openconnect_init_ssl(void)
{
#ifdef _WIN32
	int ret = openconnect__win32_sock_init();
	if (ret)
		return ret;
#endif
	SSL_library_init();
	ERR_clear_error();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	return 0;
}

char *openconnect_get_peer_cert_details(struct openconnect_info *vpninfo)
{
	BIO *bp = BIO_new(BIO_s_mem());
	BUF_MEM *certinfo;
	char zero = 0;
	char *ret;

	X509_print_ex(bp, vpninfo->peer_cert, 0, 0);
	BIO_write(bp, &zero, 1);
	BIO_get_mem_ptr(bp, &certinfo);

	ret = strdup(certinfo->data);
	BIO_free(bp);
	return ret;
}

void openconnect_free_cert_info(struct openconnect_info *vpninfo,
				void *buf)
{
	free(buf);
}

int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf)
{
	buf[0] = 0;

	if (!vpninfo->cert_x509)
		return -EIO;

	if (get_cert_md5_fingerprint(vpninfo, vpninfo->cert_x509, buf))
		return -EIO;

	return 0;
}

#ifdef HAVE_LIBPCSCLITE
int openconnect_hash_yubikey_password(struct openconnect_info *vpninfo,
				      const char *password, int pwlen,
				      const void *ident, int id_len)
{
	if (!PKCS5_PBKDF2_HMAC_SHA1(password, pwlen, ident, id_len, 1000, 16,
				    vpninfo->yubikey_pwhash))
		return -EIO;

	return 0;
}

int openconnect_yubikey_chalresp(struct openconnect_info *vpninfo,
				  const void *challenge, int chall_len, void *result)
{
	unsigned int mdlen = SHA1_SIZE;

	if (!HMAC(EVP_sha1(), vpninfo->yubikey_pwhash, 16, challenge, chall_len, result, &mdlen))
		return -EIO;

	return 0;
}
#endif

int hotp_hmac(struct openconnect_info *vpninfo, const void *challenge)
{
	unsigned char hash[64]; /* Enough for a SHA256 */
	unsigned int hashlen = sizeof(hash);
	const EVP_MD *alg;

	switch(vpninfo->oath_hmac_alg) {
	case OATH_ALG_HMAC_SHA1:
		alg = EVP_sha1();
		break;
	case OATH_ALG_HMAC_SHA256:
		alg = EVP_sha256();
		break;
	case OATH_ALG_HMAC_SHA512:
		alg = EVP_sha512();
		break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unsupported OATH HMAC algorithm\n"));
		return -EINVAL;
	}
	if (!HMAC(alg, vpninfo->oath_secret, vpninfo->oath_secret_len,
		  challenge, 8, hash, &hashlen)) {
		vpninfo->progress(vpninfo, PRG_ERR,
				  _("Failed to calculate OATH HMAC\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	hashlen = hash[hashlen - 1] & 15;
	return load_be32(&hash[hashlen]) & 0x7fffffff;
}
