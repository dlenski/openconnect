/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <gnutls/pkcs12.h>
#include <gnutls/abstract.h>

#ifdef HAVE_TROUSERS
#include <trousers/tss.h>
#include <trousers/trousers.h>
#endif
#ifdef HAVE_P11KIT
#include <p11-kit/p11-kit.h>
#include <p11-kit/pkcs11.h>
#include <p11-kit/pin.h>

static P11KitPin *pin_callback(const char *pin_source, P11KitUri *pin_uri,
			       const char *pin_description,
			       P11KitPinFlags flags,
			       void *_vpninfo);
#endif

#include "openconnect-internal.h"

/* Helper functions for reading/writing lines over SSL.
   We could use cURL for the HTTP stuff, but it's overkill */

int openconnect_SSL_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	size_t orig_len = len;

	while (len) {
		int done = gnutls_record_send(vpninfo->https_sess, buf, len);
		if (done > 0)
			len -= done;
		else if (done != GNUTLS_E_AGAIN) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to write to SSL socket: %s"),
				     gnutls_strerror(done));
			return -EIO;
		} else {
			fd_set wr_set, rd_set;
			int maxfd = vpninfo->ssl_fd;

			FD_ZERO(&wr_set);
			FD_ZERO(&rd_set);
			
			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			if (vpninfo->cancel_fd != -1) {
				FD_SET(vpninfo->cancel_fd, &rd_set);
				if (vpninfo->cancel_fd > vpninfo->ssl_fd)
					maxfd = vpninfo->cancel_fd;
			}
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (vpninfo->cancel_fd != -1 &&
			    FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL write cancelled\n"));
				return -EINTR;
			}
		}
	}
	return orig_len;
}

int openconnect_SSL_read(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int done;

	while ((done = gnutls_record_recv(vpninfo->https_sess, buf, len)) < 0) {
		fd_set wr_set, rd_set;
		int maxfd = vpninfo->ssl_fd;

		if (done != GNUTLS_E_AGAIN) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to read from SSL socket: %s"),
				     gnutls_strerror(done));
			return -EIO;
		} else {
			FD_ZERO(&wr_set);
			FD_ZERO(&rd_set);
			
			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			if (vpninfo->cancel_fd != -1) {
				FD_SET(vpninfo->cancel_fd, &rd_set);
				if (vpninfo->cancel_fd > vpninfo->ssl_fd)
					maxfd = vpninfo->cancel_fd;
			}
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (vpninfo->cancel_fd != -1 &&
			    FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL read cancelled\n"));
				return -EINTR;
			}
		}
	}
	return done;
}

int openconnect_SSL_gets(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while (1) {
		ret = gnutls_record_recv(vpninfo->https_sess, buf + i, 1);
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
		} else if (ret != GNUTLS_E_AGAIN) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to read from SSL socket: %s\n"),
				     gnutls_strerror(ret));
			ret = -EIO;
			break;
		} else {
			fd_set rd_set, wr_set;
			int maxfd = vpninfo->ssl_fd;
			
			FD_ZERO(&rd_set);
			FD_ZERO(&wr_set);
			
			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			if (vpninfo->cancel_fd != -1) {
				FD_SET(vpninfo->cancel_fd, &rd_set);
				if (vpninfo->cancel_fd > vpninfo->ssl_fd)
					maxfd = vpninfo->cancel_fd;
			}
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (vpninfo->cancel_fd != -1 &&
			    FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL read cancelled\n"));
				ret = -EINTR;
				break;
			}
		}
	}
	buf[i] = 0;
	return i ?: ret;
}

static int check_certificate_expiry(struct openconnect_info *vpninfo, gnutls_x509_crt_t cert)
{
	const char *reason = NULL;
	time_t expires = gnutls_x509_crt_get_expiration_time(cert);
	time_t now = time(NULL);

	if (expires == -1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Could not extract expiration time of certificate\n"));
		return -EINVAL;
	}

	if (expires < now)
		reason = _("Client certificate has expired at");
	else if (expires < now + vpninfo->cert_expire_warning)
		reason = _("Client certificate expires soon at");

	if (reason) {
		struct tm tm;
		char buf[80];

		gmtime_r(&expires, &tm);
		strftime(buf, 80, "%a, %d %b %Y %T %Z", &tm);

		vpn_progress(vpninfo, PRG_ERR, "%s: %s\n", reason, buf);
	}
	return 0;
}

/* For systems that don't support O_CLOEXEC, just don't bother.
   It's not open for long anyway. */
#ifndef O_CLOEXEC
#define O_CLOEXEC
#endif

static int load_datum(struct openconnect_info *vpninfo,
		      gnutls_datum_t *datum, const char *fname)
{
	struct stat st;
	int fd, err;

	fd = open(fname, O_RDONLY|O_CLOEXEC);
	if (fd == -1) {
		err = errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open key/certificate file %s: %s\n"),
			     fname, strerror(err));
		return -ENOENT;
	}
	if (fstat(fd, &st)) {
		err = errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to stat key/certificate file %s: %s\n"),
			     fname, strerror(err));
		close(fd);
		return -EIO;
	}
	datum->size = st.st_size;
	datum->data = gnutls_malloc(st.st_size + 1);
	if (!datum->data) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate certificate buffer\n"));
		close(fd);
		return -ENOMEM;
	}
	errno = EAGAIN;
	if (read(fd, datum->data, datum->size) != datum->size) {
		err = errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read certificate into memory: %s\n"),
			     strerror(err));
		close(fd);
		gnutls_free(datum->data);
		return -EIO;
	}
	datum->data[st.st_size] = 0;
	close(fd);
	return 0;
}

#ifndef HAVE_GNUTLS_PKCS12_SIMPLE_PARSE
/* If we're using a version of GnuTLS from before this was 
   exported, pull in our local copy. */
#include "gnutls_pkcs12.c"
#endif

/* A non-zero, non-error return to make load_certificate() continue and
   interpreting the file as other types */
#define NOT_PKCS12	1

static int load_pkcs12_certificate(struct openconnect_info *vpninfo,
				   gnutls_datum_t *datum,
				   gnutls_x509_privkey_t *key,
				   gnutls_x509_crt_t **chain,
				   unsigned int *chain_len,
				   gnutls_x509_crt_t **extra_certs,
				   unsigned int *extra_certs_len,
				   gnutls_x509_crl_t *crl)
{
	gnutls_pkcs12_t p12;
	char *pass;
	int err;

	err = gnutls_pkcs12_init(&p12);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to setup PKCS#12 data structure: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	err = gnutls_pkcs12_import(p12, datum, GNUTLS_X509_FMT_DER, 0);
	if (err) {
		gnutls_pkcs12_deinit(p12);
		if (vpninfo->cert_type == CERT_TYPE_UNKNOWN)
			return NOT_PKCS12;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to import PKCS#12 file: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}

	pass = vpninfo->cert_password;
	while ((err = gnutls_pkcs12_verify_mac(p12, pass)) == GNUTLS_E_MAC_VERIFY_FAILED) {
		if (pass)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to decrypt PKCS#12 certificate file\n"));
		free(pass);
		vpninfo->cert_password = NULL;
		err = request_passphrase(vpninfo, &pass,
					 _("Enter PKCS#12 pass phrase:"));
		if (err) {
			gnutls_pkcs12_deinit(p12);
			return -EINVAL;
		}
	}
	/* If it wasn't GNUTLS_E_MAC_VERIFY_FAILED, then the problem wasn't just a
	   bad password. Give up. */
	if (err) {
		int level = PRG_ERR;
		int ret = -EINVAL;

		gnutls_pkcs12_deinit(p12);

		/* If the first attempt, and we didn't know for sure it was PKCS#12
		   anyway, bail out and try loading it as something different. */
		if (pass == vpninfo->cert_password &&
		    vpninfo->cert_type == CERT_TYPE_UNKNOWN) {
			/* Make it non-fatal... */
			level = PRG_TRACE;
			ret = NOT_PKCS12;
		}

		vpn_progress(vpninfo, level,
			     _("Failed to process PKCS#12 file: %s\n"),
			       gnutls_strerror(err));
		return ret;
	}
	err = gnutls_pkcs12_simple_parse(p12, pass, key, chain, chain_len,
					 extra_certs, extra_certs_len, crl, 0);
	free(pass);
	vpninfo->cert_password = NULL;

	gnutls_pkcs12_deinit(p12);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load PKCS#12 certificate: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}
	return 0;
}

/* Older versions of GnuTLS didn't actually bother to check this, so we'll
   do it for them. */
static int check_issuer_sanity(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer)
{
#if GNUTLS_VERSION_NUMBER > 0x300014
	return 0;
#else
	unsigned char id1[512], id2[512];
	size_t id1_size = 512, id2_size = 512;
	int err;

	err = gnutls_x509_crt_get_authority_key_id(cert, id1, &id1_size, NULL);
	if (err)
		return 0;

	err = gnutls_x509_crt_get_subject_key_id(issuer, id2, &id2_size, NULL);
	if (err)
		return 0;
	if (id1_size == id2_size && !memcmp(id1, id2, id1_size))
		return 0;

	/* EEP! */
	return -EIO;
#endif
}

static int count_x509_certificates(gnutls_datum_t *datum)
{
	int count = 0;
	char *p = (char *)datum->data;

	while (p) {
		p = strstr(p, "-----BEGIN ");
		if (!p)
			break;
		p += 11;
		if (!strncmp(p, "CERTIFICATE", 11) ||
		    !strncmp(p, "X509 CERTIFICATE", 16))
		    count++;
	}
	return count;
}

static int get_cert_name(gnutls_x509_crt_t cert, char *name, size_t namelen)
{
	if (gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME,
					  0, 0, name, &namelen) &&
	    gnutls_x509_crt_get_dn(cert, name, &namelen)) {
		name[namelen-1] = 0;
		snprintf(name, namelen-1, "<unknown>");
		return -EINVAL;
	}
	return 0;
}

#ifdef HAVE_TROUSERS

/* TPM code based on client-tpm.c from Carolin Latze <latze@angry-red-pla.net>
   and Tobias Soder */
static int tpm_sign_fn(gnutls_privkey_t key, void *_vpninfo,
		       const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	struct openconnect_info *vpninfo = _vpninfo;
	TSS_HHASH hash;
	int err;

	vpn_progress(vpninfo, PRG_TRACE,
		     _("TPM sign function called for %d bytes.\n"),
		     data->size);

	err = Tspi_Context_CreateObject(vpninfo->tpm_context, TSS_OBJECT_TYPE_HASH,
					TSS_HASH_OTHER, &hash);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create TPM hash object.\n"));
		return GNUTLS_E_PK_SIGN_FAILED;
	}
	err = Tspi_Hash_SetHashValue(hash, data->size, data->data);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set value in TPM hash object.\n"));
		Tspi_Context_CloseObject(vpninfo->tpm_context, hash);
		return GNUTLS_E_PK_SIGN_FAILED;
	}
	err = Tspi_Hash_Sign(hash, vpninfo->tpm_key, &sig->size, &sig->data);
	Tspi_Context_CloseObject(vpninfo->tpm_context, hash);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM hash signature failed\n"));
		return GNUTLS_E_PK_SIGN_FAILED;
	}
	return 0;
}

static int load_tpm_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata, gnutls_privkey_t *pkey)
{
	static const TSS_UUID SRK_UUID = TSS_UUID_SRK;
	gnutls_datum_t asn1;
	unsigned int tss_len;
	char *pass;
	int ofs, err;

	err = gnutls_pem_base64_decode_alloc("TSS KEY BLOB", fdata, &asn1);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error decoding TSS key blob: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}
	/* Ick. We have to parse the ASN1 OCTET_STRING for ourselves. */
	if (asn1.size < 2 || asn1.data[0] != 0x04 /* OCTET_STRING */) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error in TSS key blob\n"));
		goto out_blob;
	}

	tss_len = asn1.data[1];
	ofs = 2;
	if (tss_len & 0x80) {
		int lenlen = tss_len & 0x7f;

		if (asn1.size < 2 + lenlen || lenlen > 3) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error in TSS key blob\n"));
			goto out_blob;
		}

		tss_len = 0;
		while (lenlen) {
			tss_len <<= 8;
			tss_len |= asn1.data[ofs++];
			lenlen--;
		}
	}
	if (tss_len + ofs != asn1.size) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error in TSS key blob\n"));
		goto out_blob;
	}

	err = Tspi_Context_Create(&vpninfo->tpm_context);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create TPM context: %s\n"),
			     Trspi_Error_String(err));
		goto out_blob;
	}
	err = Tspi_Context_Connect(vpninfo->tpm_context, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to connect TPM context: %s\n"),
			     Trspi_Error_String(err));
		goto out_context;
	}
	err = Tspi_Context_LoadKeyByUUID(vpninfo->tpm_context, TSS_PS_TYPE_SYSTEM,
					 SRK_UUID, &vpninfo->srk);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load TPM SRK key: %s\n"),
			     Trspi_Error_String(err));
		goto out_context;
	}
	err = Tspi_GetPolicyObject(vpninfo->srk, TSS_POLICY_USAGE, &vpninfo->srk_policy);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load TPM SRK policy object: %s\n"),
			     Trspi_Error_String(err));
		goto out_srk;
	}

	pass = vpninfo->cert_password;
	vpninfo->cert_password = NULL;
	while (1) {
		if (!pass) {
			err = request_passphrase(vpninfo, &pass, _("Enter TPM SRK PIN:"));
			if (err)
				goto out_srkpol;
		}
		/* We don't seem to get the error here... */
		err = Tspi_Policy_SetSecret(vpninfo->srk_policy, TSS_SECRET_MODE_PLAIN,
					    strlen(pass), (void *)pass);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to set TPM PIN: %s\n"),
				     Trspi_Error_String(err));
			goto out_srkpol;
		}

		free(pass);
		pass = NULL;

		/* ... we get it here instead. */
		err = Tspi_Context_LoadKeyByBlob(vpninfo->tpm_context, vpninfo->srk,
						 tss_len, asn1.data + ofs, &vpninfo->tpm_key);
		if (!err)
			break;

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load TPM key blob: %s\n"),
			     Trspi_Error_String(err));

		if (err != TPM_E_AUTHFAIL)
			goto out_srkpol;
	}

	gnutls_privkey_init(pkey);
	/* This would be nicer if there was a destructor callback. I could
	   allocate a data structure with the TPM handles and the vpninfo
	   pointer, and destroy that properly when the key is destroyed. */
	gnutls_privkey_import_ext(*pkey, GNUTLS_PK_RSA, vpninfo, tpm_sign_fn, NULL, 0);

	/* FIXME: Get key id using TSS_TSPATTRIB_KEYINFO_RSA_MODULUS etc. so
	   that we can ensure we have a matching cert. */
	free (asn1.data);
	return 0;

 out_srkpol:
	Tspi_Context_CloseObject(vpninfo->tpm_context, vpninfo->srk_policy);
	vpninfo->srk_policy = 0;
 out_srk:
	Tspi_Context_CloseObject(vpninfo->tpm_context, vpninfo->srk);
	vpninfo->srk = 0;
 out_context:
	Tspi_Context_Close(vpninfo->tpm_context);
	vpninfo->tpm_context = 0;
 out_blob:
	free (asn1.data);
	return -EIO;
}
#endif /* HAVE_TROUSERS */

static int load_certificate(struct openconnect_info *vpninfo)
{
	gnutls_datum_t fdata;
	gnutls_x509_privkey_t key = NULL;
#ifdef HAVE_GNUTLS_CERTIFICATE_SET_KEY
	gnutls_privkey_t pkey = NULL;
#endif
#ifdef HAVE_P11KIT
	char *cert_url = (char *)vpninfo->cert;
	char *key_url = (char *)vpninfo->sslkey;
#endif
	gnutls_x509_crl_t crl = NULL;
	gnutls_x509_crt_t last_cert, cert = NULL;
	gnutls_x509_crt_t *extra_certs = NULL, *supporting_certs = NULL;
	unsigned int nr_supporting_certs = 0, nr_extra_certs = 0;
	unsigned int certs_to_free = 0; /* How many of supporting_certs */
	int err; /* GnuTLS error */
	int ret = 0; /* our error (zero or -errno) */
	int i;
	int cert_is_p11 = 0, key_is_p11 = 0;
	unsigned char key_id[20];
	size_t key_id_size = sizeof(key_id);
	char name[80];

	fdata.data = NULL;

	key_is_p11 = !strncmp(vpninfo->sslkey, "pkcs11:", 7);
	cert_is_p11 = !strncmp(vpninfo->cert, "pkcs11:", 7);

	/* Install PIN handler if either certificate or key are coming from PKCS#11 */
	if (key_is_p11 || cert_is_p11) {
#ifdef HAVE_P11KIT
		CK_OBJECT_CLASS class;
		CK_ATTRIBUTE attr;
		char pin_source[40];
		P11KitUri *uri;

		sprintf(pin_source, "openconnect:%p", vpninfo);
		p11_kit_pin_register_callback(pin_source, pin_callback, vpninfo, NULL);

		uri = p11_kit_uri_new();

		attr.type = CKA_CLASS;
		attr.pValue = &class;
		attr.ulValueLen = sizeof(class);

		/* Add appropriate pin-source and object-type attributes to
		   both certificate and key URLs, unless they already exist. */
		if (cert_is_p11 &&
		    !p11_kit_uri_parse(cert_url, P11_KIT_URI_FOR_OBJECT, uri)) {
			if (!p11_kit_uri_get_pin_source(uri))
				p11_kit_uri_set_pin_source(uri, pin_source);
			if (!p11_kit_uri_get_attribute(uri, CKA_CLASS)) {
				class = CKO_CERTIFICATE;
				p11_kit_uri_set_attribute(uri, &attr);
			}
			p11_kit_uri_format(uri, P11_KIT_URI_FOR_OBJECT, &cert_url);
		}

		if (key_is_p11 &&
		    !p11_kit_uri_parse(key_url, P11_KIT_URI_FOR_OBJECT, uri)) {
			if (!p11_kit_uri_get_pin_source(uri))
				p11_kit_uri_set_pin_source(uri, pin_source);
			if (!p11_kit_uri_get_attribute(uri, CKA_CLASS)) {
				class = CKO_PRIVATE_KEY;
				p11_kit_uri_set_attribute(uri, &attr);
			}
			p11_kit_uri_format(uri, P11_KIT_URI_FOR_OBJECT, &key_url);
		}

		p11_kit_uri_free(uri);
#else
		vpn_progress(vpninfo, PRG_ERR,
			     _("This binary built without PKCS#11 support\n"));
		return -EINVAL;
#endif
	}

	/* Load certificate(s) first... */
#ifdef HAVE_P11KIT
#ifndef HAVE_GNUTLS_CERTIFICATE_SET_KEY
	if (key_is_p11) {
		/* With GnuTLS 2.12 we can't *see* the key so we can't
		   do the expiry check or fill in intermediate CAs. */
		err = gnutls_certificate_set_x509_key_file(vpninfo->https_cred,
							   cert_url, key_url,
							   GNUTLS_X509_FMT_PEM);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error loading PKCS#11 certificate: %s\n"),
				     gnutls_strerror(err));
			ret = -EIO;
			goto out;
		}
		ret = 0;
		goto out;
	}
#endif /* PKCS#11 for GnuTLS v2.12 */

	/* GnuTLS 2.12 *can* handle the cert being in PKCS#11, if the key
	   isn't. Although it's not clear why anyone would ever do that. */
	if (cert_is_p11) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Using PKCS#11 certificate %s\n"), cert_url);

		err = gnutls_x509_crt_init(&cert);
		if (err) {
			ret = -ENOMEM;
			goto out;
		}
		err = gnutls_x509_crt_import_pkcs11_url(cert, cert_url, 0);
		if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			err = gnutls_x509_crt_import_pkcs11_url(cert, cert_url,
								GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error loading certificate from PKCS#11: %s\n"),
				     gnutls_strerror(err));
			ret = -EIO;
			goto out;
		}
		goto got_certs;
	}
#endif /* HAVE_P11KIT */

	vpn_progress(vpninfo, PRG_TRACE,
		     _("Using certificate file %s\n"), vpninfo->cert);

	ret = load_datum(vpninfo, &fdata, vpninfo->cert);
	if (ret)
		return ret;

	if (!key_is_p11 && (vpninfo->cert_type == CERT_TYPE_PKCS12 ||
			    vpninfo->cert_type == CERT_TYPE_UNKNOWN)) {
		/* PKCS#12 should actually contain certificates *and* private key */
		ret = load_pkcs12_certificate(vpninfo, &fdata, &key,
					      &supporting_certs, &nr_supporting_certs,
					      &extra_certs, &nr_extra_certs,
					      &crl);
		if (ret < 0)
			goto out;
		else if (!ret) {
			if (nr_supporting_certs) {
				cert = supporting_certs[0];
				goto got_key;
			}
			vpn_progress(vpninfo, PRG_ERR,
				     _("PKCS#11 file contained no certificate\n"));
			ret = -EINVAL;
			goto out;
		}

		/* It returned NOT_PKCS12.
		   Fall through to try PEM formats. */
	}

	/* We need to know how many there are in *advance*; it won't just allocate
	   the array for us :( */
	nr_extra_certs = count_x509_certificates(&fdata);
	if (!nr_extra_certs)
		nr_extra_certs = 1; /* wtf? Oh well, we'll fail later... */

	extra_certs = calloc(nr_extra_certs, sizeof(cert));
	if (!extra_certs) {
		nr_extra_certs = 0;
		ret = -ENOMEM;
		goto out;
	}
	err = gnutls_x509_crt_list_import(extra_certs, &nr_extra_certs, &fdata,
					  GNUTLS_X509_FMT_PEM, 0);
	if (err <= 0) {
		const char *reason;
		if (!err || err == GNUTLS_E_NO_CERTIFICATE_FOUND)
			reason = _("No certificate found in file");
		else
			reason = gnutls_strerror(err);

		vpn_progress(vpninfo, PRG_ERR,
			     _("Loading certificate failed: %s\n"),
			     reason);
		ret = -EINVAL;
		goto out;
	}
	nr_extra_certs = err;
	err = 0;

	goto got_certs;
 got_certs:
	/* Now we have the certificate(s) and we're looking for the private key... */
#if defined (HAVE_P11KIT) && defined (HAVE_GNUTLS_CERTIFICATE_SET_KEY)
	if (key_is_p11) {
		gnutls_pkcs11_privkey_t p11key = NULL;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Using PKCS#11 key %s\n"), key_url);

		err = gnutls_pkcs11_privkey_init(&p11key);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error initialising PKCS#11 key structure: %s\n"),
				     gnutls_strerror(err));
			ret = -EIO;
			goto out;
		}

		err = gnutls_pkcs11_privkey_import_url(p11key, key_url, 0);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error importing PKCS#11 URL %s: %s\n"),
				     key_url, gnutls_strerror(err));
			gnutls_pkcs11_privkey_deinit(p11key);
			ret = -EIO;
			goto out;
		}

		err = gnutls_privkey_init(&pkey);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error initialising private key structure: %s\n"),
				     gnutls_strerror(err));
			gnutls_pkcs11_privkey_deinit(p11key);
			ret = -EIO;
			goto out;
		}

		err = gnutls_privkey_import_pkcs11(pkey, p11key, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error importing PKCS#11 key into private key structure: %s\n"),
				     gnutls_strerror(err));
			gnutls_pkcs11_privkey_deinit(p11key);
			ret = -EIO;
			goto out;
		}

		goto match_cert;
	}
#endif

	/* We're loading the private key from a file. Load the file into memory
	   unless it's the same as the certificate and we already loaded that. */
	if (!fdata.data || vpninfo->sslkey != vpninfo->cert) {
		gnutls_free(fdata.data);
		fdata.data = NULL;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Using private key file %s\n"), vpninfo->sslkey);

		ret = load_datum(vpninfo, &fdata, vpninfo->sslkey);
		if (ret)
			goto out;
	}

	if (vpninfo->cert_type == CERT_TYPE_TPM ||
	    (vpninfo->cert_type == CERT_TYPE_UNKNOWN &&
	     strstr((char *)fdata.data, "-----BEGIN TSS KEY BLOB-----"))) {
#ifndef HAVE_TROUSERS
		vpn_progress(vpninfo, PRG_ERR,
			     _("This version of OpenConnect was built without TPM support\n"));
		return -EINVAL;
#else
		ret = load_tpm_key(vpninfo, &fdata, &pkey);
		if (ret)
			goto out;

		goto match_cert;
#endif
	}

	gnutls_x509_privkey_init(&key);
	/* Try PKCS#1 (and PKCS#8 without password) first. GnuTLS doesn't
	   support OpenSSL's old PKCS#1-based encrypted format. We should
	   probably check for it and give a more coherent failure mode. */
	err = gnutls_x509_privkey_import(key, &fdata, GNUTLS_X509_FMT_PEM);
	if (err) {
		/* If that fails, try PKCS#8 */
		char *pass = vpninfo->cert_password;

		/* Yay, just for fun this is *different* to PKCS#12. Where we could
		   try an empty password there, in this case the empty-password case
		   has already been *tried* by gnutls_x509_privkey_import(). If we
		   just call gnutls_x509_privkey_import_pkcs8() with a NULL password,
		   it'll SEGV. You have to set the GNUTLS_PKCS_PLAIN flag if you want
		   to try without a password. Passing NULL evidently isn't enough of
		   a hint. And in GnuTLS 3.1 where that crash has been fixed, passing
		   NULL will cause it to return GNUTLS_E_ENCRYPTED_STRUCTURE (a new
		   error code) rather than GNUTLS_E_DECRYPTION_FAILED. So just pass ""
		   instead of NULL, and don't worry about either case. */
		while ((err = gnutls_x509_privkey_import_pkcs8(key, &fdata,
							       GNUTLS_X509_FMT_PEM,
							       pass?pass:"", 0))) {
			if (err != GNUTLS_E_DECRYPTION_FAILED) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to load private key as PKCS#8: %s\n"),
					     gnutls_strerror(err));
				ret = -EINVAL;
				goto out;
			}
			vpninfo->cert_password = NULL;
			if (pass) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to decrypt PKCS#8 certificate file\n"));
				free(pass);
			}
			err = request_passphrase(vpninfo, &pass,
						 _("Enter PEM pass phrase:"));
			if (err) {
				ret = -EINVAL;
				goto out;
			}
		}
		free(pass);
		vpninfo->cert_password = NULL;
	}

	/* Now attempt to make sure we use the *correct* certificate, to match the key */
	err = gnutls_x509_privkey_get_key_id(key, 0, key_id, &key_id_size);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to get key ID: %s\n"),
			     gnutls_strerror(err));
		goto out;
	}
	for (i = 0; i < (extra_certs?nr_extra_certs:1); i++) {
		unsigned char cert_id[20];
		size_t cert_id_size = sizeof(cert_id);

		err = gnutls_x509_crt_get_key_id(extra_certs?extra_certs[i]:cert, 0, cert_id, &cert_id_size);
		if (err)
			continue;

		if (cert_id_size == key_id_size && !memcmp(cert_id, key_id, key_id_size)) {
			if (extra_certs) {
				cert = extra_certs[i];

				/* Move the rest of the array down */
				for (; i < nr_extra_certs - 1; i++)
					extra_certs[i] = extra_certs[i+1];

				nr_extra_certs--;
			}
			goto got_key;
		}
	}
	/* There's no pkey (there's an x509 key), so we'll fall straight through the
	 * bit at match_cert: below, and go directly to the bit where it prints the
	 * 'no match found' error and exits. */

#ifdef HAVE_GNUTLS_CERTIFICATE_SET_KEY
 match_cert:
	/* We only get here if we have a key in pkey from PKCS#11 or TPM anyway, but
	   the check makes it clearer... and allows us to define some local variables. */
	if (pkey) {
		gnutls_datum_t input;
		gnutls_datum_t sig;

		input.data = (void *)&load_certificate;
		input.size = 20;

		err = gnutls_privkey_sign_data(pkey, GNUTLS_DIG_SHA1, 0,
					       &input, &sig);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error signing test data with private key: %s\n"),
				       gnutls_strerror(err));
			goto out;
		}

		for (i=0; i < (extra_certs?nr_extra_certs:1); i++) {
			gnutls_pubkey_t pubkey;

			gnutls_pubkey_init(&pubkey);
			err = gnutls_pubkey_import_x509(pubkey, extra_certs?extra_certs[i]:cert, 0);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error validating signature against certificate: %s\n"),
					     gnutls_strerror(err));
				/* We'll probably fail shortly if we don't find it. */
				gnutls_pubkey_deinit(pubkey);
				continue;
			}
			err = gnutls_pubkey_verify_data(pubkey, 0, &input, &sig);
			gnutls_pubkey_deinit(pubkey);

			if (err >= 0) {
				if (extra_certs) {
					cert = extra_certs[i];

					/* Move the rest of the array down */
					for (; i < nr_extra_certs - 1; i++)
						extra_certs[i] = extra_certs[i+1];

					nr_extra_certs--;
				}
				gnutls_free(sig.data);
				goto got_key;
			}
		}
		gnutls_free(sig.data);
	}
#endif
	/* We shouldn't reach this. It means that we didn't find *any* matching cert */
	vpn_progress(vpninfo, PRG_ERR,
		     _("No SSL certificate found to match private key\n"));
	ret = -EINVAL;
	goto out;

	/********************************************************************/
 got_key:
	/* Now we have both cert(s) and key, and we should be ready to go. */
	check_certificate_expiry(vpninfo, cert);
	get_cert_name(cert, name, sizeof(name));
	vpn_progress(vpninfo, PRG_INFO, _("Using client certificate '%s'\n"),
		     name);

	if (crl) {
		err = gnutls_certificate_set_x509_crl(vpninfo->https_cred, &crl, 1);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Setting certificate recovation list failed: %s\n"),
				     gnutls_strerror(err));
			goto out;
		}
	}

	/* OpenSSL has problems with certificate chains — if there are
	   multiple certs with the same name, it doesn't necessarily
	   choose the _right_ one. (RT#1942)
	   Pick the right ones for ourselves and add them manually. */

	if (nr_supporting_certs) {
		/* We already got a bunch of certs from PKCS#12 file. 
		   Remember how many need to be freed when we're done,
		   since we'll expand the supporting_certs array with
		   more from the cafile if we can. */
		last_cert = supporting_certs[nr_supporting_certs-1];
		certs_to_free = nr_supporting_certs;
	} else {
		last_cert = cert;
		certs_to_free = nr_supporting_certs = 1;
	}
	while (1) {
		gnutls_x509_crt_t issuer;

		for (i = 0; i < nr_extra_certs; i++) {
			if (gnutls_x509_crt_check_issuer(last_cert, extra_certs[i]) &&
			    !check_issuer_sanity(last_cert, extra_certs[i]))
				break;
		}

		if (i < nr_extra_certs) {
			issuer = extra_certs[i];
		} else {
			err = gnutls_certificate_get_issuer(vpninfo->https_cred,
							    last_cert, &issuer, 0);
			if (err)
 				break;
		}

		/* The check_issuer_sanity() function works fine as a workaround where
		   it was used above, but when gnutls_certificate_get_issuer() returns
		   a bogus cert, there's nothing we can do to fix it up. We don't get
		   to iterate over all the available certs like we can over our own
		   list. */
		if (check_issuer_sanity(last_cert, issuer)) {
			/* Hm, is there a bug reference for this? Or just the git commit
			   reference (c1ef7efb in master, 5196786c in gnutls_3_0_x-2)? */
			vpn_progress(vpninfo, PRG_ERR,
				     _("WARNING: GnuTLS returned incorrect issuer certs; authentication may fail!\n"));
			break;
		}

		if (issuer == last_cert) {
			/* Don't actually include the root CA. If they don't already trust it,
			   then handing it to them isn't going to help. But don't omit the
			   original certificate if it's self-signed. */
			if (nr_supporting_certs > 1)
				nr_supporting_certs--;
			break;
		}

		/* OK, we found a new cert to add to our chain. */
		supporting_certs = gnutls_realloc(supporting_certs,
						  sizeof(cert) * ++nr_supporting_certs);
		if (!supporting_certs) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to allocate memory for supporting certificates\n"));
			/* The world is probably about to end, but try without them anyway */
			certs_to_free = 0;
			ret = -ENOMEM;
			goto out;
		}

		/* First time we actually allocated an array? Copy the first cert into it */
		if (nr_supporting_certs == 2)
			supporting_certs[0] = cert;

		/* Append the new one */
		supporting_certs[nr_supporting_certs-1] = issuer;
		last_cert = issuer;

	}
	for (i = 1; i < nr_supporting_certs; i++) {
		get_cert_name(supporting_certs[i], name, sizeof(name));

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Adding supporting CA '%s'\n"), name);
	}

#if defined(HAVE_GNUTLS_CERTIFICATE_SET_KEY)
	if (pkey) {
		/* Ug. If we got a gnutls_privkey_t from PKCS#11 rather than the
		   gnutls_x509_privkey_t that we get from PEM or PKCS#12 files, then
		   we can't use gnutls_certificate_set_x509_key(). Instead we have
		   to convert our chain of X509 certificates to gnutls_pcert_st and
		   then use gnutls_certificate_set_key() with that instead. */
		gnutls_pcert_st *pcerts = calloc(nr_supporting_certs, sizeof(*pcerts));

		if (!pcerts) {
			ret = -ENOMEM;
			goto out;
		}

		for (i=0 ; i < nr_supporting_certs; i++) {
			err = gnutls_pcert_import_x509(pcerts + i, supporting_certs?supporting_certs[i]:cert, 0);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Importing X509 certificate failed: %s\n"),
					     gnutls_strerror(err));
				goto free_pcerts;
			}
		}

		err = gnutls_certificate_set_key(vpninfo->https_cred, NULL, 0, pcerts, nr_supporting_certs, pkey);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Setting PKCS#11 certificate failed: %s\n"),
				     gnutls_strerror(err));
		free_pcerts:
			for (i=0 ; i < nr_supporting_certs; i++)
				gnutls_pcert_deinit(pcerts + i);
			free (pcerts);
			ret = -EIO;
			goto out;
		}
		pkey = NULL; /* we gave it away, along with pcerts */
	} else
#endif
		err = gnutls_certificate_set_x509_key(vpninfo->https_cred,
						      supporting_certs ? supporting_certs : &cert,
						      supporting_certs ? nr_supporting_certs : 1,
						      key);

	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Setting certificate failed: %s\n"),
			     gnutls_strerror(err));
		ret = -EIO;
	}
 out:
	if (crl)
		gnutls_x509_crl_deinit(crl);
	if (key)
		gnutls_x509_privkey_deinit(key);
	if (cert)
		gnutls_x509_crt_deinit(cert);
	/* From 1 because cert is the first one (and might exist
	   even if supporting_certs is NULL) */
	for (i = 1; i < certs_to_free; i++) {
		if (supporting_certs[i])
			gnutls_x509_crt_deinit(supporting_certs[i]);
	}
	for (i = 0; i < nr_extra_certs; i++) {
		if (extra_certs[i])
			gnutls_x509_crt_deinit(extra_certs[i]);
	}
	gnutls_free(extra_certs);
	gnutls_free(supporting_certs);
	gnutls_free(fdata.data);
#ifdef HAVE_GNUTLS_CERTIFICATE_SET_KEY
	if (pkey)
		gnutls_privkey_deinit(pkey);
#endif
#ifdef HAVE_P11KIT
	if (cert_url != vpninfo->cert)
		free(cert_url);
	if (key_url != vpninfo->sslkey)
		free(key_url);
#endif
	return ret;
}

static int get_cert_fingerprint(struct openconnect_info *vpninfo,
				gnutls_x509_crt_t cert,
				gnutls_digest_algorithm_t algo,
				char *buf)
{
	unsigned char md[256];
	size_t md_size = sizeof(md);
	unsigned int i;

	if (gnutls_x509_crt_get_fingerprint(cert, algo, md, &md_size))
		return -EIO;

	for (i=0; i < md_size; i++)
		sprintf(&buf[i*2], "%02X", md[i]);

	return 0;
}

int get_cert_md5_fingerprint(struct openconnect_info *vpninfo,
			     OPENCONNECT_X509 *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, GNUTLS_DIG_MD5, buf);
}

int openconnect_get_cert_sha1(struct openconnect_info *vpninfo,
			      OPENCONNECT_X509 *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, GNUTLS_DIG_SHA1, buf);
}

char *openconnect_get_cert_details(struct openconnect_info *vpninfo,
				   OPENCONNECT_X509 *cert)
{
	gnutls_datum_t buf;
	char *ret;

	if (gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_FULL, &buf))
		return NULL;
	
	/* Just in case gnutls_free() isn't free(), we can't steal it. */
	ret = strdup((char *)buf.data);
	gnutls_free(buf.data);
	
	return ret;
}

int openconnect_get_cert_DER(struct openconnect_info *vpninfo,
			     OPENCONNECT_X509 *cert, unsigned char **buf)
{
	size_t l = 0;
	unsigned char *ret = NULL;

	if (gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, ret, &l) != 
	    GNUTLS_E_SHORT_MEMORY_BUFFER)
		return -EIO;

	ret = malloc(l);
	if (!ret)
		return -ENOMEM;

	if (gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, ret, &l)) {
		free(ret);
 		return -EIO;
	}
	*buf = ret;
	return l;
}

static int verify_peer(gnutls_session_t session)
{
	struct openconnect_info *vpninfo = gnutls_session_get_ptr(session);
	const gnutls_datum_t *cert_list;
	gnutls_x509_crt_t cert;
	unsigned int status, cert_list_size;
	const char *reason = NULL;
	int err;

	if (vpninfo->peer_cert) {
		gnutls_x509_crt_deinit(vpninfo->peer_cert);
		vpninfo->peer_cert = NULL;
	}

	cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
	if (!cert_list) {
		vpn_progress(vpninfo, PRG_ERR, _("Server presented no certificate\n"));
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (vpninfo->servercert) {
		unsigned char sha1bin[SHA1_SIZE];
		char fingerprint[(SHA1_SIZE * 2) + 1];
		int i;
		
		err = openconnect_sha1(sha1bin, cert_list[0].data, cert_list[0].size);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Could not calculate SHA1 of server's certificate\n"));
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
		for (i=0; i < SHA1_SIZE; i++)
			sprintf(&fingerprint[i*2], "%02X", sha1bin[i]);

		if (strcasecmp(vpninfo->servercert, fingerprint)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Server SSL certificate didn't match: %s\n"), fingerprint);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
		return 0;
	}

	err = gnutls_certificate_verify_peers2 (session, &status);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR, _("Error checking server cert status\n"));
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (status & GNUTLS_CERT_REVOKED)
		reason = _("certificate revoked");
	else if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		reason = _("signer not found");
	else if (status & GNUTLS_CERT_SIGNER_NOT_CA)
		reason = _("signer not a CA certificate");
	else if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
		reason = _("insecure algorithm");
	else if (status & GNUTLS_CERT_NOT_ACTIVATED)
		reason = _("certificate not yet activated");
	else if (status & GNUTLS_CERT_EXPIRED)
		reason = _("certificate expired");
	else if (status & GNUTLS_CERT_INVALID)
		/* If this is set and no other reason, it apparently means
		   that signature verification failed. Not entirely sure
		   why we don't just set a bit for that too. */
		reason = _("signature verification failed");

	err = gnutls_x509_crt_init(&cert);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR, _("Error initialising X509 cert structure\n"));
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	err = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR, _("Error importing server's cert\n"));
		gnutls_x509_crt_deinit(cert);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (!reason && !gnutls_x509_crt_check_hostname(cert, vpninfo->hostname))
		reason = _("certificate does not match hostname");

	if (reason) {
		vpn_progress(vpninfo, PRG_INFO, "Server certificate verify failed: %s\n",
			     reason);
		if (vpninfo->validate_peer_cert)
			err = vpninfo->validate_peer_cert(vpninfo->cbdata,
							  cert,
							  reason) ? GNUTLS_E_CERTIFICATE_ERROR : 0;
		else
			err = GNUTLS_E_CERTIFICATE_ERROR;
	}

	vpninfo->peer_cert = cert;

	return err;
}


int openconnect_open_https(struct openconnect_info *vpninfo)
{
	int ssl_sock = -1;
	int err;

	if (vpninfo->https_sess)
		return 0;

	ssl_sock = connect_https_socket(vpninfo);
	if (ssl_sock < 0)
		return ssl_sock;

	if (!vpninfo->https_cred) {
		gnutls_certificate_allocate_credentials(&vpninfo->https_cred);
#ifdef HAVE_GNUTLS_CERTIFICATE_SET_X509_SYSTEM_TRUST
		gnutls_certificate_set_x509_system_trust(vpninfo->https_cred);
#else
		gnutls_certificate_set_x509_trust_file(vpninfo->https_cred,
						       "/etc/pki/tls/certs/ca-bundle.crt",
						       GNUTLS_X509_FMT_PEM);
#endif
		gnutls_certificate_set_verify_function (vpninfo->https_cred,
							verify_peer);

		if (vpninfo->cafile) {
			err = gnutls_certificate_set_x509_trust_file(vpninfo->https_cred,
								     vpninfo->cafile,
								     GNUTLS_X509_FMT_PEM);
			if (err < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to open CA file '%s': %s\n"),
					     vpninfo->cafile, gnutls_strerror(err));
				close(ssl_sock);
				return -EINVAL;
			}
		}

		if (vpninfo->cert) {
			err = load_certificate(vpninfo);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Loading certificate failed. Aborting.\n"));
				return err;
			}
		}
	}
	gnutls_init (&vpninfo->https_sess, GNUTLS_CLIENT);
	gnutls_session_set_ptr (vpninfo->https_sess, (void *) vpninfo);
	err = gnutls_priority_set_direct (vpninfo->https_sess, "NONE:+VERS-TLS1.0:+SHA1:+AES-128-CBC:+RSA:+COMP-NULL:%COMPAT:%DISABLE_SAFE_RENEGOTIATION", NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set TLS priority string: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	gnutls_record_disable_padding (vpninfo->https_sess);
	gnutls_credentials_set (vpninfo->https_sess, GNUTLS_CRD_CERTIFICATE, vpninfo->https_cred);
	gnutls_transport_set_ptr(vpninfo->https_sess, /* really? */(gnutls_transport_ptr_t)(long) ssl_sock);

	vpn_progress(vpninfo, PRG_INFO, _("SSL negotiation with %s\n"),
		     vpninfo->hostname);

	while ((err = gnutls_handshake (vpninfo->https_sess))) {
		if (err == GNUTLS_E_AGAIN) {
			fd_set rd_set, wr_set;
			int maxfd = ssl_sock;
			
			FD_ZERO(&rd_set);
			FD_ZERO(&wr_set);
			
			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(ssl_sock, &wr_set);
			else
				FD_SET(ssl_sock, &rd_set);

			if (vpninfo->cancel_fd != -1) {
				FD_SET(vpninfo->cancel_fd, &rd_set);
				if (vpninfo->cancel_fd > ssl_sock)
					maxfd = vpninfo->cancel_fd;
			}
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (vpninfo->cancel_fd != -1 &&
			    FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL connection cancelled\n"));
				gnutls_deinit(vpninfo->https_sess);
				vpninfo->https_sess = NULL;
				close(ssl_sock);
				return -EINTR;
			}
		} else if (err == GNUTLS_E_INTERRUPTED || gnutls_error_is_fatal(err)) {
			vpn_progress(vpninfo, PRG_ERR, _("SSL connection failure: %s\n"),
							 gnutls_strerror(err));
			gnutls_deinit(vpninfo->https_sess);
			vpninfo->https_sess = NULL;
			close(ssl_sock);
			return -EIO;
		} else {
			/* non-fatal error or warning. Ignore it and continue */
			vpn_progress(vpninfo, PRG_TRACE,
				     _("GnuTLS non-fatal return during handshake: %s\n"),
				     gnutls_strerror(err));
		}
	}

	vpninfo->ssl_fd = ssl_sock;

	vpn_progress(vpninfo, PRG_INFO, _("Connected to HTTPS on %s\n"),
		     vpninfo->hostname);

	return 0;
}

void openconnect_close_https(struct openconnect_info *vpninfo, int final)
{
	if (vpninfo->peer_cert) {
		gnutls_x509_crt_deinit(vpninfo->peer_cert);
		vpninfo->peer_cert = NULL;
	}
	if (vpninfo->https_sess) {
		gnutls_deinit(vpninfo->https_sess);
		vpninfo->https_sess = NULL;
	}
	if (vpninfo->ssl_fd != -1) {
		close(vpninfo->ssl_fd);
		FD_CLR(vpninfo->ssl_fd, &vpninfo->select_rfds);
		FD_CLR(vpninfo->ssl_fd, &vpninfo->select_wfds);
		FD_CLR(vpninfo->ssl_fd, &vpninfo->select_efds);
		vpninfo->ssl_fd = -1;
	}
	if (final && vpninfo->https_cred) {
		gnutls_certificate_free_credentials(vpninfo->https_cred);
		vpninfo->https_cred = NULL;
#ifdef HAVE_P11KIT
		if (!strncmp(vpninfo->cert, "pkcs11:", 7) ||
		    !strncmp(vpninfo->sslkey, "pkcs11:", 7)) {
			char pin_source[40];

			sprintf(pin_source, "openconnect:%p", vpninfo);
			p11_kit_pin_unregister_callback(pin_source, pin_callback, vpninfo);

			while (vpninfo->pin_cache) {
				struct pin_cache *cache = vpninfo->pin_cache;

				free(cache->token);
				memset(cache->pin, 0x5a, strlen(cache->pin));
				free(cache->pin);
				vpninfo->pin_cache = cache->next;
				free(cache);
			}
		}
#endif
#ifdef HAVE_TROUSERS
		if (vpninfo->tpm_key) {
			Tspi_Context_CloseObject(vpninfo->tpm_context, vpninfo->tpm_key);
			vpninfo->tpm_key = 0;
		}
		if (vpninfo->srk_policy) {
			Tspi_Context_CloseObject(vpninfo->tpm_context, vpninfo->srk_policy);
			vpninfo->srk_policy = 0;
		}
		if (vpninfo->srk) {
			Tspi_Context_CloseObject(vpninfo->tpm_context, vpninfo->srk);
			vpninfo->srk = 0;
		}
		if (vpninfo->tpm_context) {
			Tspi_Context_Close(vpninfo->tpm_context);
			vpninfo->tpm_context = 0;
		}
#endif
	}
}

void openconnect_init_ssl(void)
{
	gnutls_global_init();
}

int openconnect_sha1(unsigned char *result, void *data, int datalen)
{
	gnutls_datum_t d;
	size_t shalen = SHA1_SIZE;

	d.data = data;
	d.size = datalen;
	if (gnutls_fingerprint(GNUTLS_DIG_SHA1, &d, result, &shalen))
		return -1;

	return 0;
}

int openconnect_random(void *bytes, int len)
{
	if (gnutls_rnd(GNUTLS_RND_RANDOM, bytes, len))
		return -EIO;
	return 0;
}

int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf)
{
	const gnutls_datum_t *d;
	size_t md5len = 16;

	buf[0] = 0;

	d = gnutls_certificate_get_ours(vpninfo->https_sess);
	if (!d)
		return -EIO;

	if (gnutls_fingerprint(GNUTLS_DIG_MD5, d, buf, &md5len))
		return -EIO;

	return 0;
}

#ifdef HAVE_P11KIT
static P11KitPin *pin_callback(const char *pin_source, P11KitUri *pin_uri,
			const char *pin_description,
			P11KitPinFlags flags,
			void *_vpninfo)
{
	struct openconnect_info *vpninfo = _vpninfo;
	struct pin_cache **cache = &vpninfo->pin_cache;
	struct oc_auth_form f;
	struct oc_form_opt o;
	char message[1024];
	char *uri;
	P11KitPin *pin;
	int ret;

	if (!vpninfo || !vpninfo->process_auth_form)
		return NULL;

	if (p11_kit_uri_format(pin_uri, P11_KIT_URI_FOR_TOKEN, &uri))
		return NULL;
	
	while (*cache) {
		if (!strcmp(uri, (*cache)->token)) {
			free(uri);
			uri = NULL;
			if ((*cache)->pin) {
				if ((flags & P11_KIT_PIN_FLAGS_RETRY) != P11_KIT_PIN_FLAGS_RETRY)
					return p11_kit_pin_new_for_string((*cache)->pin);
				memset((*cache)->pin, 0x5a, strlen((*cache)->pin));
				free((*cache)->pin);
				(*cache)->pin = NULL;
			}
			break;
		}
	}
	if (!*cache) {
		*cache = calloc(1, sizeof(struct pin_cache));
		if (!*cache) {
			free(uri);
			return NULL;
		}
		(*cache)->token = uri;
	}

	memset(&f, 0, sizeof(f));
	f.auth_id = (char *)"pkcs11_pin";
	f.opts = &o;

	message[sizeof(message)-1] = 0;
	snprintf(message, sizeof(message) - 1, _("PIN required for %s"), pin_description);
	f.message = message;
	
	/* 
	 * In p11-kit <= 0.12, these flags are *odd*.
	 * RETRY is 0xa, FINAL_TRY is 0x14 and MANY_TRIES is 0x28.
	 * So don't treat it like a sane bitmask. Fixed in
	 * http://cgit.freedesktop.org/p11-glue/p11-kit/commit/?id=59774b11
	 */
	if ((flags & P11_KIT_PIN_FLAGS_RETRY) == P11_KIT_PIN_FLAGS_RETRY)
		f.error = (char *)_("Wrong PIN");

	if ((flags & P11_KIT_PIN_FLAGS_FINAL_TRY) == P11_KIT_PIN_FLAGS_FINAL_TRY)
		f.banner = (char *)_("This is the final try before locking!");
	else if ((flags & P11_KIT_PIN_FLAGS_MANY_TRIES) == P11_KIT_PIN_FLAGS_MANY_TRIES)
		f.banner = (char *)_("Only a few tries left before locking!");

	o.next = NULL;
	o.type = OC_FORM_OPT_PASSWORD;
	o.name = (char *)"pkcs11_pin";
	o.label = (char *)_("Enter PIN:");
	o.value = NULL;

	ret = vpninfo->process_auth_form(vpninfo->cbdata, &f);
	if (ret || !o.value)
		return NULL;

	pin = p11_kit_pin_new_for_string(o.value);
	(*cache)->pin = o.value;

	return pin;
}
#endif
