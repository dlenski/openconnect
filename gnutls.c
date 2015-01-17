/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

#ifndef HAVE_GNUTLS_CERTIFICATE_SET_KEY
/* Shut up about gnutls_sign_callback_set() being deprecated. We only use it
   in the GnuTLS 2.12 case, and there just isn't another way of doing it. */
#define GNUTLS_INTERNAL_BUILD 1
#endif

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
#endif

#if defined(HAVE_P11KIT) || defined(HAVE_GNUTLS_SYSTEM_KEYS)
static int gnutls_pin_callback(void *priv, int attempt, const char *uri,
			       const char *token_label, unsigned int flags,
			       char *pin, size_t pin_max);

#ifndef HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION
/* If we don't have this (3.1.0+) then we'll use p11-kit callbacks instead
 * because the old GnuTLS callback was global rather than context-specific,
 * which makes it basically unusable from libopenconnect. The p11-kit
 * callback function is a simple wrapper around the GnuTLS native version. */
typedef enum {
        GNUTLS_PIN_USER = (1 << 0),
        GNUTLS_PIN_SO = (1 << 1),
        GNUTLS_PIN_FINAL_TRY = (1 << 2),
        GNUTLS_PIN_COUNT_LOW = (1 << 3),
        GNUTLS_PIN_CONTEXT_SPECIFIC = (1 << 4),
        GNUTLS_PIN_WRONG = (1 << 5)
} gnutls_pin_flag_t;

static P11KitPin *p11kit_pin_callback(const char *pin_source, P11KitUri *pin_uri,
				      const char *pin_description,
				      P11KitPinFlags flags,
				      void *_vpninfo);
#endif /* !HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION */
#endif /* HAVE_P11KIT || HAVE_GNUTLS_SYSTEM_KEYS */

#include "gnutls.h"
#include "openconnect-internal.h"

/* Helper functions for reading/writing lines over SSL. */
static int openconnect_gnutls_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	size_t orig_len = len;

	while (len) {
		int done = gnutls_record_send(vpninfo->https_sess, buf, len);
		if (done > 0)
			len -= done;
		else if (done == GNUTLS_E_AGAIN) {
			/* Wait for something to happen on the socket, or on cmd_fd */
			fd_set wr_set, rd_set;
			int maxfd = vpninfo->ssl_fd;

			FD_ZERO(&wr_set);
			FD_ZERO(&rd_set);

			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			cmd_fd_set(vpninfo, &rd_set, &maxfd);
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (is_cancel_pending(vpninfo, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL write cancelled\n"));
				return -EINTR;
			}
		} else {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to write to SSL socket: %s\n"),
				     gnutls_strerror(done));
			return -EIO;
		}
	}
	return orig_len;
}

static int openconnect_gnutls_read(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int done;

	while ((done = gnutls_record_recv(vpninfo->https_sess, buf, len)) < 0) {
		if (done == GNUTLS_E_AGAIN) {
			/* Wait for something to happen on the socket, or on cmd_fd */
			fd_set wr_set, rd_set;
			int maxfd = vpninfo->ssl_fd;

			FD_ZERO(&wr_set);
			FD_ZERO(&rd_set);

			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			cmd_fd_set(vpninfo, &rd_set, &maxfd);
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (is_cancel_pending(vpninfo, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL read cancelled\n"));
				return -EINTR;
			}
#ifdef GNUTLS_E_PREMATURE_TERMINATION
		} else if (done == GNUTLS_E_PREMATURE_TERMINATION) {
			/* We've seen this with HTTP 1.0 responses followed by abrupt
			   socket closure and no clean SSL shutdown.
			   https://bugs.launchpad.net/bugs/1225276 */
			vpn_progress(vpninfo, PRG_DEBUG, _("SSL socket closed uncleanly\n"));
			return 0;
#endif
		} else {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to read from SSL socket: %s\n"),
				     gnutls_strerror(done));
			return -EIO;
		}

	}
	return done;
}

static int openconnect_gnutls_gets(struct openconnect_info *vpninfo, char *buf, size_t len)
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
		} else if (ret == GNUTLS_E_AGAIN) {
			/* Wait for something to happen on the socket, or on cmd_fd */
			fd_set rd_set, wr_set;
			int maxfd = vpninfo->ssl_fd;

			FD_ZERO(&rd_set);
			FD_ZERO(&wr_set);

			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			cmd_fd_set(vpninfo, &rd_set, &maxfd);
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (is_cancel_pending(vpninfo, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL read cancelled\n"));
				ret = -EINTR;
				break;
			}
		} else {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to read from SSL socket: %s\n"),
				     gnutls_strerror(ret));
			ret = -EIO;
			break;
		}
	}
	buf[i] = 0;
	return i ?: ret;
}

int ssl_nonblock_read(struct openconnect_info *vpninfo, void *buf, int maxlen)
{
	int ret;

	ret = gnutls_record_recv(vpninfo->https_sess, buf, maxlen);
	if (ret > 0)
		return ret;

	if (ret != GNUTLS_E_AGAIN) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("SSL read error: %s; reconnecting.\n"),
			     gnutls_strerror(ret));
		return -EIO;
	}
	return 0;
}

int ssl_nonblock_write(struct openconnect_info *vpninfo, void *buf, int buflen)
{
	int ret;

	ret = gnutls_record_send(vpninfo->https_sess, buf, buflen);
	if (ret > 0)
		return ret;

	if (ret == GNUTLS_E_AGAIN) {
		if (gnutls_record_get_direction(vpninfo->https_sess)) {
			/* Waiting for the socket to become writable -- it's
			   probably stalled, and/or the buffers are full */
			monitor_write_fd(vpninfo, ssl);
		}
		return 0;
	}
	vpn_progress(vpninfo, PRG_ERR, _("SSL send failed: %s\n"),
		     gnutls_strerror(ret));
	return -1;
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
		char buf[80];
#ifdef _WIN32
		/*
		 * Windows doesn't have gmtime_r but apparently its gmtime()
		 * *is* thread-safe because it uses a per-thread static buffer.
		 * cf. http://sourceforge.net/p/mingw/bugs/1625/
		 *
		 * We also explicitly say 'GMT' because %Z would give us the
		 * Microsoft stupidity "GMT Standard Time". Which is not only
		 * silly, but also ambiguous because Windows actually says that
		 * even when it means British Summer Time (GMT+1). And having
		 * used gmtime() we really *are* giving the time in GMT.
		 */
		struct tm *tm = gmtime(&expires);
		strftime(buf, 80, "%a, %d %b %Y %H:%M:%S GMT", tm);
#else
		struct tm tm;

		gmtime_r(&expires, &tm);
		strftime(buf, 80, "%a, %d %b %Y %T %Z", &tm);
#endif
		vpn_progress(vpninfo, PRG_ERR, "%s: %s\n", reason, buf);
	}
	return 0;
}

static int load_datum(struct openconnect_info *vpninfo,
		      gnutls_datum_t *datum, const char *fname)
{
	struct stat st;
	int fd, err;

#ifdef ANDROID_KEYSTORE
	if (!strncmp(fname, "keystore:", 9)) {
		int len;
		const char *p = fname + 9;

		/* Skip first two slashes if the user has given it as
		   keystore://foo ... */
		if (*p == '/')
			p++;
		if (*p == '/')
			p++;
		len = keystore_fetch(p, &datum->data);
		if (len <= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to load item '%s' from keystore: %s\n"),
				     p, keystore_strerror(len));
			return -EINVAL;
		}
		datum->size = len;
		return 0;
	}
#endif /* ANDROID_KEYSTORE */

	fd = openconnect_open_utf8(vpninfo, fname, O_RDONLY|O_CLOEXEC|O_BINARY);
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
		return NOT_PKCS12;
	}

	pass = vpninfo->cert_password;
	while ((err = gnutls_pkcs12_verify_mac(p12, pass)) == GNUTLS_E_MAC_VERIFY_FAILED) {
		if (!pass) {
			/* OpenSSL's PKCS12_parse() code will try both NULL and "" automatically,
			 * but GnuTLS requires two separate attempts. */
			err = gnutls_pkcs12_verify_mac(p12, "");
			if (!err) {
				pass = strdup("");
				break;
			}
		} else
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to decrypt PKCS#12 certificate file\n"));
		free(pass);
		vpninfo->cert_password = NULL;
		err = request_passphrase(vpninfo, "openconnect_pkcs12", &pass,
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
		if (pass == vpninfo->cert_password) {
			/* Make it non-fatal... */
			level = PRG_DEBUG;
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
   do it for them. Is there a bug reference for this? Or just the git commit
   reference (c1ef7efb in master, 5196786c in gnutls_3_0_x-2)? */
static int check_issuer_sanity(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer)
{
#if GNUTLS_VERSION_NUMBER > 0x030014
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

#if defined(HAVE_P11KIT) || defined(HAVE_TROUSERS) || defined (HAVE_GNUTLS_SYSTEM_KEYS)
#ifndef HAVE_GNUTLS_CERTIFICATE_SET_KEY
/* For GnuTLS 2.12 even if we *have* a privkey (as we do for PKCS#11), we
   can't register it. So we have to use the cert_callback function. This
   just hands out the certificate chain we prepared in load_certificate().
   If we have a pkey then return that too; otherwise leave the key NULL —
   we'll also have registered a sign_callback for the session, which will
   handle that. */
static int gtls_cert_cb(gnutls_session_t sess, const gnutls_datum_t *req_ca_dn,
			int nreqs, const gnutls_pk_algorithm_t *pk_algos,
			int pk_algos_length, gnutls_retr2_st *st) {

	struct openconnect_info *vpninfo = gnutls_session_get_ptr(sess);
	int algo = GNUTLS_PK_RSA; /* TPM */
	int i;

#ifdef HAVE_P11KIT
	if (vpninfo->my_p11key) {
		st->key_type = GNUTLS_PRIVKEY_PKCS11;
		st->key.pkcs11 = vpninfo->my_p11key;
		algo = gnutls_pkcs11_privkey_get_pk_algorithm(vpninfo->my_p11key, NULL);
	};
#endif
	for (i = 0; i < pk_algos_length; i++) {
		if (algo == pk_algos[i])
			break;
	}
	if (i == pk_algos_length)
		return GNUTLS_E_UNKNOWN_PK_ALGORITHM;

	st->cert_type = GNUTLS_CRT_X509;
	st->cert.x509 = vpninfo->my_certs;
	st->ncerts = vpninfo->nr_my_certs;
	st->deinit_all = 0;

	return 0;
}

/* For GnuTLS 2.12, this has to set the cert_callback to the function
   above, which will return the pkey and certs on demand. Or in the
   case of TPM we can't make a suitable pkey, so we have to set a
   sign_callback too (which is done in openconnect_open_https() since
   it has to be done on the *session*). */
static int assign_privkey(struct openconnect_info *vpninfo,
			  gnutls_privkey_t pkey,
			  gnutls_x509_crt_t *certs,
			  unsigned int nr_certs,
			  uint8_t *free_certs)
{
	vpninfo->my_certs = gnutls_calloc(nr_certs, sizeof(*certs));
	if (!vpninfo->my_certs)
		return GNUTLS_E_MEMORY_ERROR;

	vpninfo->free_my_certs = gnutls_malloc(nr_certs);
	if (!vpninfo->free_my_certs) {
		gnutls_free(vpninfo->my_certs);
		vpninfo->my_certs = NULL;
		return GNUTLS_E_MEMORY_ERROR;
	}

	memcpy(vpninfo->free_my_certs, free_certs, nr_certs);
	memcpy(vpninfo->my_certs, certs, nr_certs * sizeof(*certs));
	vpninfo->nr_my_certs = nr_certs;

	/* We are *keeping* the certs, unlike in GnuTLS 3 where our caller
	   can free them after gnutls_certificate_set_key() has been called.
	   So wipe the 'free_certs' array. */
	memset(free_certs, 0, nr_certs);

	gnutls_certificate_set_retrieve_function(vpninfo->https_cred,
						 gtls_cert_cb);
	vpninfo->my_pkey = pkey;

	return 0;
}
#else /* !SET_KEY */

/* For GnuTLS 3+ this is saner than the GnuTLS 2.12 version. But still we
   have to convert the array of X509 certificates to gnutls_pcert_st for
   ourselves. There's no function that takes a gnutls_privkey_t as the key
   and gnutls_x509_crt_t certificates. */
static int assign_privkey(struct openconnect_info *vpninfo,
			  gnutls_privkey_t pkey,
			  gnutls_x509_crt_t *certs,
			  unsigned int nr_certs,
			  uint8_t *free_certs)
{
	gnutls_pcert_st *pcerts = calloc(nr_certs, sizeof(*pcerts));
	int i, err;

	if (!pcerts)
		return GNUTLS_E_MEMORY_ERROR;

	for (i = 0 ; i < nr_certs; i++) {
		err = gnutls_pcert_import_x509(pcerts + i, certs[i], 0);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Importing X509 certificate failed: %s\n"),
				     gnutls_strerror(err));
			goto free_pcerts;
		}
	}

	err = gnutls_certificate_set_key(vpninfo->https_cred, NULL, 0,
					 pcerts, nr_certs, pkey);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Setting PKCS#11 certificate failed: %s\n"),
			     gnutls_strerror(err));
	free_pcerts:
		for (i = 0 ; i < nr_certs; i++)
			gnutls_pcert_deinit(pcerts + i);
		free(pcerts);
	}
	return err;
}
#endif /* !SET_KEY */

static int verify_signed_data(gnutls_pubkey_t pubkey, gnutls_privkey_t privkey,
			      const gnutls_datum_t *data, const gnutls_datum_t *sig)
{
#ifdef HAVE_GNUTLS_PK_TO_SIGN
	gnutls_sign_algorithm_t algo = GNUTLS_SIGN_RSA_SHA1; /* TPM keys */

	if (privkey != OPENCONNECT_TPM_PKEY)
		algo = gnutls_pk_to_sign(gnutls_privkey_get_pk_algorithm(privkey, NULL),
					 GNUTLS_DIG_SHA1);

	return gnutls_pubkey_verify_data2(pubkey, algo, 0, data, sig);
#else
	return gnutls_pubkey_verify_data(pubkey, 0, data, sig);
#endif
}
#endif /* (P11KIT || TROUSERS || SYSTEM_KEYS) */

static int openssl_hash_password(struct openconnect_info *vpninfo, char *pass,
				 gnutls_datum_t *key, gnutls_datum_t *salt)
{
	unsigned char md5[16];
	gnutls_hash_hd_t hash;
	int count = 0;
	int err;

	while (count < key->size) {
		err = gnutls_hash_init(&hash, GNUTLS_DIG_MD5);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Could not initialise MD5 hash: %s\n"),
				     gnutls_strerror(err));
			return -EIO;
		}
		if (count) {
			err = gnutls_hash(hash, md5, sizeof(md5));
			if (err) {
			hash_err:
				gnutls_hash_deinit(hash, NULL);
				vpn_progress(vpninfo, PRG_ERR,
					     _("MD5 hash error: %s\n"),
					     gnutls_strerror(err));
				return -EIO;
			}
		}
		if (pass) {
			err = gnutls_hash(hash, pass, strlen(pass));
			if (err)
				goto hash_err;
		}
		/* We only use the first 8 bytes of the salt for this */
		err = gnutls_hash(hash, salt->data, 8);
		if (err)
			goto hash_err;

		gnutls_hash_deinit(hash, md5);

		if (key->size - count <= sizeof(md5)) {
			memcpy(&key->data[count], md5, key->size - count);
			break;
		}

		memcpy(&key->data[count], md5, sizeof(md5));
		count += sizeof(md5);
	}

	return 0;
}

static int import_openssl_pem(struct openconnect_info *vpninfo,
			      gnutls_x509_privkey_t key,
			      char type, char *pem_header, size_t pem_size)
{
	gnutls_cipher_hd_t handle;
	gnutls_cipher_algorithm_t cipher;
	gnutls_datum_t constructed_pem;
	gnutls_datum_t b64_data;
	gnutls_datum_t salt, enc_key;
	unsigned char *key_data;
	const char *begin;
	char *pass, *p;
	char *pem_start = pem_header;
	int ret, err, i;

	if (type == 'E')
		begin = "EC PRIVATE KEY";
	else if (type == 'R')
		begin = "RSA PRIVATE KEY";
	else if (type == 'D')
		begin = "DSA PRIVATE KEY";
	else
		return -EINVAL;

	while (*pem_header == '\r' || *pem_header == '\n')
		pem_header++;

	if (strncmp(pem_header, "DEK-Info: ", 10)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Missing DEK-Info: header from OpenSSL encrypted key\n"));
		return -EIO;
	}
	pem_header += 10;
	p = strchr(pem_header, ',');
	if (!p) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Cannot determine PEM encryption type\n"));
		return -EINVAL;
	}

	*p = 0;
	cipher = gnutls_cipher_get_id(pem_header);
	/* GnuTLS calls this '3DES-CBC' but all other names match */
	if (cipher == GNUTLS_CIPHER_UNKNOWN &&
	    !strcmp(pem_header, "DES-EDE3-CBC"))
		cipher = GNUTLS_CIPHER_3DES_CBC;

	if (cipher == GNUTLS_CIPHER_UNKNOWN) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unsupported PEM encryption type: %s\n"),
			     pem_header);
		return -EINVAL;
	}
	pem_header = p + 1;

	/* No supported algorithms have an IV larger than this, and dynamically
	   allocating it would be painful. */
	salt.size = 64;
	salt.data = malloc(salt.size);
	if (!salt.data)
		return -ENOMEM;
	for (i = 0; i < salt.size * 2; i++) {
		unsigned char x;
		char *c = &pem_header[i];

		if (*c >= '0' && *c <= '9')
			x = (*c) - '0';
		else if (*c >= 'A' && *c <= 'F')
			x = (*c) - 'A' + 10;
		else if ((*c == '\r' || *c == '\n') && i >= 16 && !(i % 16)) {
			salt.size = i / 2;
			break;
		} else {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid salt in encrypted PEM file\n"));
			ret = -EINVAL;
			goto out_salt;
		}
		if (i & 1)
			salt.data[i/2] |= x;
		else
			salt.data[i/2] = x << 4;
	}

	pem_header += salt.size * 2;
	if (*pem_header != '\r' && *pem_header != '\n') {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid salt in encrypted PEM file\n"));
		ret = -EINVAL;
		goto out_salt;
	}
	while (*pem_header == '\n' || *pem_header == '\r')
		pem_header++;

	/* pem_header should now point to the start of the base64 content.
	   Put a -----BEGIN banner in place before it, so that we can use
	   gnutls_pem_base64_decode_alloc(). The banner has to match the
	   -----END banner, so make sure we get it right... */
	pem_header -= 6;
	memcpy(pem_header, "-----\n", 6);
	pem_header -= strlen(begin);
	memcpy(pem_header, begin, strlen(begin));
	pem_header -= 11;
	memcpy(pem_header, "-----BEGIN ", 11);

	constructed_pem.data = (void *)pem_header;
	constructed_pem.size = pem_size - (pem_header - pem_start);

	err = gnutls_pem_base64_decode_alloc(begin, &constructed_pem, &b64_data);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error base64-decoding encrypted PEM file: %s\n"),
			     gnutls_strerror(err));
		ret = -EINVAL;
		goto out_salt;
	}
	if (b64_data.size < 16) {
		/* Just to be sure our parsing is OK */
		vpn_progress(vpninfo, PRG_ERR,
			     _("Encrypted PEM file too short\n"));
		ret = -EINVAL;
		goto out_b64;
	}

	ret = -ENOMEM;
	enc_key.size = gnutls_cipher_get_key_size(cipher);
	enc_key.data = malloc(enc_key.size);
	if (!enc_key.data)
		goto out_b64;

	key_data = malloc(b64_data.size);
	if (!key_data)
		goto out_enc_key;

	pass = vpninfo->cert_password;
	vpninfo->cert_password = NULL;

	while (1) {
		memcpy(key_data, b64_data.data, b64_data.size);

		ret = openssl_hash_password(vpninfo, pass, &enc_key, &salt);
		if (ret)
			goto out;

		err = gnutls_cipher_init(&handle, cipher, &enc_key, &salt);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to initialise cipher for decrypting PEM file: %s\n"),
				     gnutls_strerror(err));
			gnutls_cipher_deinit(handle);
			ret = -EIO;
			goto out;
		}

		err = gnutls_cipher_decrypt(handle, key_data, b64_data.size);
		gnutls_cipher_deinit(handle);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to decrypt PEM key: %s\n"),
				     gnutls_strerror(err));
			ret = -EIO;
			goto out;
		}

		/* We have to strip any padding for GnuTLS to accept it.
		   So a bit more ASN.1 parsing for us.
		   FIXME: Consolidate with similar code in gnutls_tpm.c */
		if (key_data[0] == 0x30) {
			gnutls_datum_t key_datum;
			int blocksize = gnutls_cipher_get_block_size(cipher);
			int keylen = key_data[1];
			int ofs = 2;

			if (keylen & 0x80) {
				int lenlen = keylen & 0x7f;
				keylen = 0;

				if (lenlen > 3)
					goto fail;

				while (lenlen) {
					keylen <<= 8;
					keylen |= key_data[ofs++];
					lenlen--;
				}
			}
			keylen += ofs;

			/* If there appears to be more padding than required, fail */
			if (b64_data.size - keylen >= blocksize)
				goto fail;

			/* If the padding bytes aren't all equal to the amount of padding, fail */
			ofs = keylen;
			while (ofs < b64_data.size) {
				if (key_data[ofs] != b64_data.size - keylen)
					goto fail;
				ofs++;
			}

			key_datum.data = key_data;
			key_datum.size = keylen;
			err = gnutls_x509_privkey_import(key, &key_datum, GNUTLS_X509_FMT_DER);
			if (!err) {
				ret = 0;
				goto out;
			}
		}
 fail:
		if (pass) {
			vpn_progress(vpninfo, PRG_ERR,  _("Decrypting PEM key failed\n"));
			free(pass);
			pass = NULL;
		}
		err = request_passphrase(vpninfo, "openconnect_pem",
					 &pass, _("Enter PEM pass phrase:"));
		if (err) {
			ret = -EINVAL;
			goto out;
		}
	}
 out:
	free(key_data);
	free(pass);
 out_enc_key:
	free(enc_key.data);
 out_b64:
	free(b64_data.data);
 out_salt:
	free(salt.data);
	return ret;
}

static int load_certificate(struct openconnect_info *vpninfo)
{
	gnutls_datum_t fdata;
	gnutls_x509_privkey_t key = NULL;
#if defined(HAVE_P11KIT) || defined(HAVE_TROUSERS) || defined(HAVE_GNUTLS_SYSTEM_KEYS)
	gnutls_privkey_t pkey = NULL;
	gnutls_datum_t pkey_sig = {NULL, 0};
	void *dummy_hash_data = &load_certificate;
#endif
#if defined(HAVE_P11KIT) || defined(HAVE_GNUTLS_SYSTEM_KEYS)
	char *cert_url = (char *)vpninfo->cert;
#endif
#ifdef HAVE_P11KIT
	char *key_url = (char *)vpninfo->sslkey;
	gnutls_pkcs11_privkey_t p11key = NULL;
#endif
	char *pem_header;
	gnutls_x509_crl_t crl = NULL;
	gnutls_x509_crt_t last_cert, cert = NULL;
	gnutls_x509_crt_t *extra_certs = NULL, *supporting_certs = NULL;
	unsigned int nr_supporting_certs = 0, nr_extra_certs = 0;
	uint8_t *free_supporting_certs = NULL;
	int err; /* GnuTLS error */
	int ret;
	int i;
	int cert_is_p11 = 0, key_is_p11 = 0;
	int cert_is_sys = 0, key_is_sys = 0;
	unsigned char key_id[20];
	size_t key_id_size = sizeof(key_id);
	char name[80];

	fdata.data = NULL;

	key_is_p11 = !strncmp(vpninfo->sslkey, "pkcs11:", 7);
	cert_is_p11 = !strncmp(vpninfo->cert, "pkcs11:", 7);
	key_is_sys = !strncmp(vpninfo->sslkey, "system:", 7);
	cert_is_sys = !strncmp(vpninfo->cert, "system:", 7);

#ifndef HAVE_GNUTLS_SYSTEM_KEYS
	if (key_is_sys || cert_is_sys) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("This binary built without system key support\n"));
		return -EINVAL;
	}
#endif
#ifndef HAVE_P11KIT
	if (key_is_p11 || cert_is_p11) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("This binary built without PKCS#11 support\n"));
		return -EINVAL;
	}
#else
	/* Install PIN handler if either certificate or key are coming from PKCS#11 */
	if (key_is_p11 || cert_is_p11) {
		CK_OBJECT_CLASS class;
		CK_ATTRIBUTE attr;
		P11KitUri *uri;
#ifndef HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION
		char pin_source[40];

		sprintf(pin_source, "openconnect:%p", vpninfo);
		p11_kit_pin_register_callback(pin_source, p11kit_pin_callback, vpninfo, NULL);
#endif
		uri = p11_kit_uri_new();

		attr.type = CKA_CLASS;
		attr.pValue = &class;
		attr.ulValueLen = sizeof(class);

		/* Add appropriate pin-source and object-type attributes to
		   both certificate and key URLs, unless they already exist. */
		if (cert_is_p11 &&
		    !p11_kit_uri_parse(cert_url, P11_KIT_URI_FOR_ANY, uri)) {
#ifndef HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION
			if (!p11_kit_uri_get_pin_source(uri))
				p11_kit_uri_set_pin_source(uri, pin_source);
#endif
			if (!p11_kit_uri_get_attribute(uri, CKA_CLASS)) {
				class = CKO_CERTIFICATE;
				p11_kit_uri_set_attribute(uri, &attr);
			}
			p11_kit_uri_format(uri, P11_KIT_URI_FOR_ANY, &cert_url);
		}

		if (key_is_p11 &&
		    !p11_kit_uri_parse(key_url, P11_KIT_URI_FOR_ANY, uri)) {
#ifndef HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION
			if (!p11_kit_uri_get_pin_source(uri))
				p11_kit_uri_set_pin_source(uri, pin_source);
#endif
			if (vpninfo->sslkey == vpninfo->cert ||
			    !p11_kit_uri_get_attribute(uri, CKA_CLASS)) {
				class = CKO_PRIVATE_KEY;
				p11_kit_uri_set_attribute(uri, &attr);
			}
			p11_kit_uri_format(uri, P11_KIT_URI_FOR_ANY, &key_url);
		}

		p11_kit_uri_free(uri);
	}
#endif /* HAVE_PKCS11 */

#if defined (HAVE_P11KIT) || defined(HAVE_GNUTLS_SYSTEM_KEYS)
	/* Load certificate(s) first... */
	if (cert_is_p11 || cert_is_sys) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     cert_is_p11 ? _("Using PKCS#11 certificate %s\n") :
			     _("Using system certificate %s\n"), cert_url);

		err = gnutls_x509_crt_init(&cert);
		if (err) {
			ret = -ENOMEM;
			goto out;
		}
#ifdef HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION
		gnutls_x509_crt_set_pin_function(cert, gnutls_pin_callback, vpninfo);
#endif
		/* Yes, even for *system* URLs the only API GnuTLS offers us is
		   ...import_pkcs11_url(). */
		err = gnutls_x509_crt_import_pkcs11_url(cert, cert_url, 0);
		if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			err = gnutls_x509_crt_import_pkcs11_url(cert, cert_url,
								GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     cert_is_p11 ? _("Error loading certificate from PKCS#11: %s\n") :
				     _("Error loading system certificate: %s\n"),
				     gnutls_strerror(err));
			ret = -EIO;
			goto out;
		}
		goto got_certs;
	}
#endif /* HAVE_P11KIT || HAVE_GNUTLS_SYSTEM_KEYS */

	/* OK, not a PKCS#11 certificate so it must be coming from a file... */
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Using certificate file %s\n"), vpninfo->cert);

	/* Load file contents */
	ret = load_datum(vpninfo, &fdata, vpninfo->cert);
	if (ret)
		return ret;

	/* Is it PKCS#12? */
	if (!key_is_p11) {
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
				free_supporting_certs = gnutls_malloc(nr_supporting_certs);
				if (!free_supporting_certs) {
					ret = -ENOMEM;
					goto out;
				}
				memset(free_supporting_certs, 1, nr_supporting_certs);
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
	/* Now we have either a single certificate in 'cert', or an array of
	   them in extra_certs[]. Next we look for the private key ... */
#ifdef HAVE_GNUTLS_SYSTEM_KEYS
	if (key_is_sys) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Using system key %s\n"), vpninfo->sslkey);

		err = gnutls_privkey_init(&pkey);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error initialising private key structure: %s\n"),
				     gnutls_strerror(err));
			ret = -EIO;
			goto out;
		}
#ifdef HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION
		gnutls_privkey_set_pin_function(pkey, gnutls_pin_callback, vpninfo);
#endif
		err = gnutls_privkey_import_url(pkey, vpninfo->sslkey, 0);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error importing system key %s: %s\n"),
				     vpninfo->sslkey, gnutls_strerror(err));
			ret = -EIO;
			goto out;
		}
		goto match_cert;
	}
#endif /* HAVE_GNUTLS_SYSTEM_KEYS */
#if defined(HAVE_P11KIT)
	if (key_is_p11) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Trying PKCS#11 key URL %s\n"), key_url);

		err = gnutls_pkcs11_privkey_init(&p11key);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error initialising PKCS#11 key structure: %s\n"),
				     gnutls_strerror(err));
			ret = -EIO;
			goto out;
		}
#ifdef HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION
		gnutls_pkcs11_privkey_set_pin_function(p11key, gnutls_pin_callback, vpninfo);
#endif
		err = gnutls_pkcs11_privkey_import_url(p11key, key_url, 0);

		/* Annoyingly, some tokens don't even admit the *existence* of
		   the key until they're logged in. And thus a search doesn't
		   work unless it specifies the *token* too. But if the URI for
		   key and cert are the same, and the cert was found, then we
		   can work out what token the *cert* was found in and try that
		   before we give up... */
		if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE &&
		    vpninfo->cert == vpninfo->sslkey) {
			gnutls_pkcs11_obj_t crt;
			P11KitUri *uri;
			CK_TOKEN_INFO *token;
			char buf[65];
			size_t s;

			if (gnutls_pkcs11_obj_init(&crt))
				goto key_err;
			if (gnutls_pkcs11_obj_import_url(crt, cert_url, 0))
				goto key_err_obj;
			uri = p11_kit_uri_new();
			if (!uri)
				goto key_err_obj;
			if (p11_kit_uri_parse(key_url, P11_KIT_URI_FOR_ANY, uri))
				goto key_err_uri;
			token = p11_kit_uri_get_token_info(uri);
			if (!token)
				goto key_err_uri;

			if (!token->label[0]) {
				s = sizeof(token->label) + 1;
				if (!gnutls_pkcs11_obj_get_info(crt, GNUTLS_PKCS11_OBJ_TOKEN_LABEL,
								buf, &s)) {
					s--;
					memcpy(token->label, buf, s);
					memset(token->label + s, ' ',
					       sizeof(token->label) - s);
				}
			}
			if (!token->manufacturerID[0]) {
				s = sizeof(token->manufacturerID) + 1;
				if (!gnutls_pkcs11_obj_get_info(crt, GNUTLS_PKCS11_OBJ_TOKEN_MANUFACTURER,
								buf, &s)) {
					s--;
					memcpy(token->manufacturerID, buf, s);
					memset(token->manufacturerID + s, ' ',
					       sizeof(token->manufacturerID) - s);
				}
			}
			if (!token->model[0]) {
				s = sizeof(token->model) + 1;
				if (!gnutls_pkcs11_obj_get_info(crt, GNUTLS_PKCS11_OBJ_TOKEN_MODEL,
								buf, &s)) {
					s--;
					memcpy(token->model, buf, s);
					memset(token->model + s, ' ',
					       sizeof(token->model) - s);
				}
			}
			if (!token->serialNumber[0]) {
				s = sizeof(token->serialNumber) + 1;
				if (!gnutls_pkcs11_obj_get_info(crt, GNUTLS_PKCS11_OBJ_TOKEN_SERIAL,
								buf, &s)) {
					s--;
					memcpy(token->serialNumber, buf, s);
					memset(token->serialNumber + s, ' ',
					       sizeof(token->serialNumber) - s);
				}

			}

			free(key_url);
			key_url = NULL;
			if (p11_kit_uri_format(uri, P11_KIT_URI_FOR_ANY, &key_url))
				goto key_err_uri;

			vpn_progress(vpninfo, PRG_TRACE,
				     _("Trying PKCS#11 key URL %s\n"), key_url);
			err = gnutls_pkcs11_privkey_import_url(p11key, key_url, 0);

			/* If it still doesn't work then try dropping CKA_LABEL and adding the
			   CKA_ID of the cert. */
			if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE &&
			    (p11_kit_uri_get_attribute(uri, CKA_LABEL) ||
			     !p11_kit_uri_get_attribute(uri, CKA_ID))) {
				CK_ATTRIBUTE attr;

				s = sizeof(buf);
				if (gnutls_pkcs11_obj_get_info(crt, GNUTLS_PKCS11_OBJ_ID,
							       buf, &s))
					goto key_err_uri;

				attr.type = CKA_ID;
				attr.pValue = buf;
				attr.ulValueLen = s;

				p11_kit_uri_set_attribute(uri, &attr);
				p11_kit_uri_clear_attribute(uri, CKA_LABEL);

				free(key_url);
				key_url = NULL;
				if (p11_kit_uri_format(uri, P11_KIT_URI_FOR_ANY, &key_url))
					goto key_err_uri;

				vpn_progress(vpninfo, PRG_TRACE,
					     _("Trying PKCS#11 key URL %s\n"), key_url);
				err = gnutls_pkcs11_privkey_import_url(p11key, key_url, 0);
			}
		key_err_uri:
			p11_kit_uri_free(uri);
		key_err_obj:
			gnutls_pkcs11_obj_deinit(crt);
		key_err:
			;
		}
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error importing PKCS#11 URL %s: %s\n"),
				     key_url, gnutls_strerror(err));
			gnutls_pkcs11_privkey_deinit(p11key);
			ret = -EIO;
			goto out;
		}
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Using PKCS#11 key %s\n"), key_url);

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
#ifndef HAVE_GNUTLS_CERTIFICATE_SET_KEY
		/* This can be set now and doesn't need to be separately freed.
		   It goes with the pkey. This is a PITA; it would be better
		   if there was a way to get the p11key *back* from a privkey
		   that we *know* is based on one. In fact, since this is only
		   for GnuTLS 2.12 and we *know* the gnutls_privkey_st won't
		   ever change there, so we *could* do something evil... but
		   we won't :) */
		vpninfo->my_p11key = p11key;
#endif /* !SET_KEY */
		goto match_cert;
	}
#endif /* HAVE_P11KIT */

	/* OK, not a PKCS#11 key so it must be coming from a file... load the
	   file into memory, unless it's the same as the cert file and we
	   already loaded that. */
	if (!fdata.data || vpninfo->sslkey != vpninfo->cert) {
		gnutls_free(fdata.data);
		fdata.data = NULL;

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Using private key file %s\n"), vpninfo->sslkey);

		ret = load_datum(vpninfo, &fdata, vpninfo->sslkey);
		if (ret)
			goto out;
	}

	/* Is it a PEM file with a TPM key blob? */
	if (strstr((char *)fdata.data, "-----BEGIN TSS KEY BLOB-----")) {
#ifndef HAVE_TROUSERS
		vpn_progress(vpninfo, PRG_ERR,
			     _("This version of OpenConnect was built without TPM support\n"));
		return -EINVAL;
#else
		ret = load_tpm_key(vpninfo, &fdata, &pkey, &pkey_sig);
		if (ret)
			goto out;

		goto match_cert;
#endif
	}

	/* OK, try other PEM files... */
	gnutls_x509_privkey_init(&key);
	if ((pem_header = strstr((char *)fdata.data, "-----BEGIN RSA PRIVATE KEY-----")) ||
	    (pem_header = strstr((char *)fdata.data, "-----BEGIN DSA PRIVATE KEY-----")) ||
	    (pem_header = strstr((char *)fdata.data, "-----BEGIN EC PRIVATE KEY-----"))) {
		/* PKCS#1 files, including OpenSSL's odd encrypted version */
		char type = pem_header[11];
		char *p = strchr(pem_header, '\n');
		if (!p) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to interpret PEM file\n"));
			ret = -EINVAL;
			goto out;
		}
		while (*p == '\n' || *p == '\r')
			p++;

		if (!strncmp(p, "Proc-Type: 4,ENCRYPTED", 22)) {
			p += 22;
			while (*p == '\n' || *p == '\r')
				p++;
			ret = import_openssl_pem(vpninfo, key, type, p,
						 fdata.size - (p - (char *)fdata.data));
			if (ret)
				goto out;
		} else {
			err = gnutls_x509_privkey_import(key, &fdata, GNUTLS_X509_FMT_PEM);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to load PKCS#1 private key: %s\n"),
					     gnutls_strerror(err));
				ret = -EINVAL;
				goto out;
			}
		}
	} else if (strstr((char *)fdata.data, "-----BEGIN PRIVATE KEY-----")) {
		/* Unencrypted PKCS#8 */
		err = gnutls_x509_privkey_import_pkcs8(key, &fdata,
						       GNUTLS_X509_FMT_PEM,
						       NULL, GNUTLS_PKCS_PLAIN);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to load private key as PKCS#8: %s\n"),
					     gnutls_strerror(err));
			ret = -EINVAL;
			goto out;
		}
	} else if (strstr((char *)fdata.data, "-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		/* Encrypted PKCS#8 */
		char *pass = vpninfo->cert_password;

		while ((err = gnutls_x509_privkey_import_pkcs8(key, &fdata,
							       GNUTLS_X509_FMT_PEM,
							       pass?:"", 0))) {
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
			err = request_passphrase(vpninfo, "openconnect_pem",
						 &pass, _("Enter PEM pass phrase:"));
			if (err) {
				ret = -EINVAL;
				goto out;
			}
		}
		free(pass);
		vpninfo->cert_password = NULL;
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to determine type of private key %s\n"),
			     vpninfo->sslkey);
		ret = -EINVAL;
		goto out;
	}

	/* Now attempt to make sure we use the *correct* certificate, to match
	   the key. Since we have a software key, we can easily query it and
	   compare its key_id with each certificate till we find a match. */
	err = gnutls_x509_privkey_get_key_id(key, 0, key_id, &key_id_size);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to get key ID: %s\n"),
			     gnutls_strerror(err));
		ret = -EINVAL;
		goto out;
	}
	/* If extra_certs[] is NULL, we have one candidate in 'cert' to check. */
	for (i = 0; i < (extra_certs ? nr_extra_certs : 1); i++) {
		unsigned char cert_id[20];
		size_t cert_id_size = sizeof(cert_id);

		err = gnutls_x509_crt_get_key_id(extra_certs ? extra_certs[i] : cert, 0, cert_id, &cert_id_size);
		if (err)
			continue;

		if (cert_id_size == key_id_size && !memcmp(cert_id, key_id, key_id_size)) {
			if (extra_certs) {
				cert = extra_certs[i];
				extra_certs[i] = NULL;
			}
			goto got_key;
		}
	}
	/* There's no pkey (there's an x509 key), so even if p11-kit or trousers is
	   enabled we'll fall straight through the bit at match_cert: below, and go
	   directly to the bit where it prints the 'no match found' error and exits. */

#if defined(HAVE_P11KIT) || defined(HAVE_TROUSERS) || defined(HAVE_GNUTLS_SYSTEM_KEYS)
 match_cert:
	/* If we have a privkey from PKCS#11 or TPM, we can't do the simple comparison
	   of key ID that we do for software keys to find which certificate is a
	   match. So sign some dummy data and then check the signature against each
	   of the available certificates until we find the right one. */
	if (pkey) {
		/* The TPM code may have already signed it, to test authorisation. We
		   only sign here for PKCS#11 keys, in which case fdata might be
		   empty too so point it at dummy data. */
		if (!pkey_sig.data) {
			if (!fdata.data) {
				fdata.data = dummy_hash_data;
				fdata.size = 20;
			}

			err = sign_dummy_data(vpninfo, pkey, &fdata, &pkey_sig);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error signing test data with private key: %s\n"),
					     gnutls_strerror(err));
				ret = -EINVAL;
				goto out;
			}
		}

		/* If extra_certs[] is NULL, we have one candidate in 'cert' to check. */
		for (i = 0; i < (extra_certs ? nr_extra_certs : 1); i++) {
			gnutls_pubkey_t pubkey;

			gnutls_pubkey_init(&pubkey);
			err = gnutls_pubkey_import_x509(pubkey, extra_certs ? extra_certs[i] : cert, 0);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error validating signature against certificate: %s\n"),
					     gnutls_strerror(err));
				/* We'll probably fail shortly if we don't find it. */
				gnutls_pubkey_deinit(pubkey);
				continue;
			}
			err = verify_signed_data(pubkey, pkey, &fdata, &pkey_sig);
			gnutls_pubkey_deinit(pubkey);

			if (err >= 0) {
				if (extra_certs) {
					cert = extra_certs[i];
					extra_certs[i] = NULL;
				}
				gnutls_free(pkey_sig.data);
				goto got_key;
			}
		}
		gnutls_free(pkey_sig.data);
	}
#endif /* P11KIT || TROUSERS || SYSTEM_KEYS */

	/* We shouldn't reach this. It means that we didn't find *any* matching cert */
	vpn_progress(vpninfo, PRG_ERR,
		     _("No SSL certificate found to match private key\n"));
	ret = -EINVAL;
	goto out;

	/********************************************************************/
 got_key:
	/* Now we have a key in either 'key' or 'pkey', a matching cert in 'cert',
	   and potentially a list of other certs in 'extra_certs[]'. If we loaded
	   a PKCS#12 file we may have a trust chain in 'supporting_certs[]' too. */
	check_certificate_expiry(vpninfo, cert);
	get_cert_name(cert, name, sizeof(name));
	get_cert_md5_fingerprint(vpninfo, cert, vpninfo->local_cert_md5);
	vpn_progress(vpninfo, PRG_INFO, _("Using client certificate '%s'\n"),
		     name);

	if (crl) {
		err = gnutls_certificate_set_x509_crl(vpninfo->https_cred, &crl, 1);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Setting certificate recovation list failed: %s\n"),
				     gnutls_strerror(err));
			ret = -EINVAL;
			goto out;
		}
	}

	/* OpenSSL has problems with certificate chains — if there are
	   multiple certs with the same name, it doesn't necessarily
	   choose the _right_ one. (RT#1942)
	   Pick the right ones for ourselves and add them manually. */

	/* We may have already got a bunch of certs from PKCS#12
	   file. Remember how many need to be freed when we're done,
	   since we'll expand the supporting_certs array with more
	   from the cafile and extra_certs[] array if we can, and
	   those extra certs must not be freed (twice). */
	if (!nr_supporting_certs) {
		supporting_certs = gnutls_malloc(sizeof(*supporting_certs));
		if (!supporting_certs) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to allocate memory for certificate\n"));
			ret = -ENOMEM;
			goto out;
		}
		supporting_certs[0] = cert;
		nr_supporting_certs = 1;

		free_supporting_certs = gnutls_malloc(1);
		if (!free_supporting_certs) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to allocate memory for certificate\n"));
			ret = -ENOMEM;
			goto out;
		}
		free_supporting_certs[0] = 1;
	}
	last_cert = supporting_certs[nr_supporting_certs-1];

	while (1) {
		uint8_t free_issuer;
		gnutls_x509_crt_t issuer;
		void *tmp;

		for (i = 0; i < nr_extra_certs; i++) {
			if (extra_certs[i] &&
			    gnutls_x509_crt_check_issuer(last_cert, extra_certs[i]) &&
			    !check_issuer_sanity(last_cert, extra_certs[i]))
				break;
		}

		if (i < nr_extra_certs) {
			/* We found the next cert in the chain in extra_certs[] */
			issuer = extra_certs[i];
			extra_certs[i] = NULL;
			free_issuer = 1;
		} else {
			/* Look for it in the system trust cafile too. */
			err = gnutls_certificate_get_issuer(vpninfo->https_cred,
							    last_cert, &issuer, 0);
			/* The check_issuer_sanity() function works fine as a workaround where
			   it was used above, but when gnutls_certificate_get_issuer() returns
			   a bogus cert, there's nothing we can do to fix it up. We don't get
			   to iterate over all the available certs like we can over our own
			   list. */
			if (!err && check_issuer_sanity(last_cert, issuer)) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("WARNING: GnuTLS returned incorrect issuer certs; authentication may fail!\n"));
				break;
			}
			free_issuer = 0;

#if defined(HAVE_P11KIT) && defined(HAVE_GNUTLS_PKCS11_GET_RAW_ISSUER)
			if (err && cert_is_p11) {
				gnutls_datum_t t;

				err = gnutls_pkcs11_get_raw_issuer(cert_url, last_cert, &t, GNUTLS_X509_FMT_DER, 0);
				if (!err) {
					err = gnutls_x509_crt_init(&issuer);
					if (!err) {
						err = gnutls_x509_crt_import(issuer, &t, GNUTLS_X509_FMT_DER);
						if (err)
							gnutls_x509_crt_deinit(issuer);
						else
							free_issuer = 1;
					}
					gnutls_free(t.data);
				}
				if (err) {
					vpn_progress(vpninfo, PRG_ERR,
						     "Got no issuer from PKCS#11\n");
				} else {
					get_cert_name(issuer, name, sizeof(name));

					vpn_progress(vpninfo, PRG_ERR,
						     _("Got next CA '%s' from PKCS11\n"), name);
				}
			}
#endif
			if (err)
				break;

		}

		if (gnutls_x509_crt_check_issuer(issuer, issuer)) {
			/* Don't actually include the root CA. If they don't already trust it,
			   then handing it to them isn't going to help. But don't omit the
			   original certificate if it's self-signed. */
			if (free_issuer)
				gnutls_x509_crt_deinit(issuer);
			break;
		}

		/* OK, we found a new cert to add to our chain. */
		tmp = supporting_certs;
		supporting_certs = gnutls_realloc(supporting_certs,
						  sizeof(cert) * (nr_supporting_certs+1));
		if (!supporting_certs) {
			supporting_certs = tmp;
		realloc_failed:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to allocate memory for supporting certificates\n"));
			if (free_issuer)
				gnutls_x509_crt_deinit(issuer);
			break;
		}

		tmp = free_supporting_certs;
		free_supporting_certs = gnutls_realloc(free_supporting_certs, nr_supporting_certs+1);
		if (!free_supporting_certs) {
			free_supporting_certs = tmp;
			goto realloc_failed;
		}

		/* Append the new one */
		supporting_certs[nr_supporting_certs] = issuer;
		free_supporting_certs[nr_supporting_certs] = free_issuer;
		nr_supporting_certs++;
		last_cert = issuer;
	}
	for (i = 1; i < nr_supporting_certs; i++) {
		get_cert_name(supporting_certs[i], name, sizeof(name));

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Adding supporting CA '%s'\n"), name);
	}

	/* OK, now we've checked the cert expiry and warned the user if it's
	   going to expire soon, and we've built up as much of a trust chain
	   in supporting_certs[] as we can find, to help the server work around
	   OpenSSL RT#1942. Set up the GnuTLS credentials with the appropriate
	   key and certs. GnuTLS makes us do this differently for X509 privkeys
	   vs. TPM/PKCS#11 "generic" privkeys, and the latter is particularly
	   'fun' for GnuTLS 2.12... */
#if defined(HAVE_P11KIT) || defined(HAVE_TROUSERS) || defined(HAVE_GNUTLS_SYSTEM_KEYS)
	if (pkey) {
		err = assign_privkey(vpninfo, pkey,
				     supporting_certs,
				     nr_supporting_certs,
				     free_supporting_certs);
		if (!err) {
			pkey = NULL; /* we gave it away, and potentially also some
					of extra_certs[] may have been zeroed. */
		}
	} else
#endif /* P11KIT || TROUSERS */
		err = gnutls_certificate_set_x509_key(vpninfo->https_cred,
						      supporting_certs,
						      nr_supporting_certs, key);

	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Setting certificate failed: %s\n"),
			     gnutls_strerror(err));
		ret = -EIO;
	} else
		ret = 0;
 out:
	if (crl)
		gnutls_x509_crl_deinit(crl);
	if (key)
		gnutls_x509_privkey_deinit(key);
	if (supporting_certs) {
		for (i = 0; i < nr_supporting_certs; i++) {
			/* We get here in an error case with !free_supporting_certs
			   and should free them all in that case */
			if (!free_supporting_certs || free_supporting_certs[i])
				gnutls_x509_crt_deinit(supporting_certs[i]);
		}
		gnutls_free(supporting_certs);
		gnutls_free(free_supporting_certs);
	} else if (cert) {
		/* Not if supporting_certs. It's supporting_certs[0] then and
		   was already freed. */
		gnutls_x509_crt_deinit(cert);
	}
	for (i = 0; i < nr_extra_certs; i++) {
		if (extra_certs[i])
			gnutls_x509_crt_deinit(extra_certs[i]);
	}
	gnutls_free(extra_certs);

#if defined(HAVE_P11KIT) || defined(HAVE_TROUSERS) || defined(HAVE_GNUTLS_SYSTEM_KEYS)
	if (pkey && pkey != OPENCONNECT_TPM_PKEY)
		gnutls_privkey_deinit(pkey);
	/* If we support arbitrary privkeys, we might have abused fdata.data
	   just to point to something to hash. Don't free it in that case! */
	if (fdata.data != dummy_hash_data)
#endif
		gnutls_free(fdata.data);

#ifdef HAVE_P11KIT
	/* This exists in the HAVE_GNUTLS_SYSTEM_KEYS case but will never
	   change so it's OK not to add to the #ifdef mess here. */
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

	for (i = 0; i < md_size; i++)
		sprintf(&buf[i*2], "%02X", md[i]);

	return 0;
}

int get_cert_md5_fingerprint(struct openconnect_info *vpninfo,
			     void *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, GNUTLS_DIG_MD5, buf);
}

static int set_peer_cert_hash(struct openconnect_info *vpninfo)
{
	unsigned char sha1[SHA1_SIZE];
	size_t shalen;
	gnutls_pubkey_t pkey;
	gnutls_datum_t d;
	int i, err;

	err = gnutls_pubkey_init(&pkey);
	if (err)
		return err;

	err = gnutls_pubkey_import_x509(pkey, vpninfo->peer_cert, 0);
	if (err) {
		gnutls_pubkey_deinit(pkey);
		return err;
	}
#ifdef HAVE_GNUTLS_PUBKEY_EXPORT2
	err = gnutls_pubkey_export2(pkey, GNUTLS_X509_FMT_DER, &d);
	if (err) {
		gnutls_pubkey_deinit(pkey);
		return err;
	}
#else
	shalen = 0;
	err = gnutls_pubkey_export(pkey, GNUTLS_X509_FMT_DER, NULL, &shalen);
	if (err != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		gnutls_pubkey_deinit(pkey);
		return err;
	}
	d.size = shalen;
	d.data = gnutls_malloc(d.size);
	if (!d.data) {
		gnutls_pubkey_deinit(pkey);
		return -ENOMEM;
	}
	err = gnutls_pubkey_export(pkey, GNUTLS_X509_FMT_DER, d.data, &shalen);
	if (err) {
		gnutls_free(d.data);
		gnutls_pubkey_deinit(pkey);
		return err;
	}
#endif
	gnutls_pubkey_deinit(pkey);
	shalen = SHA1_SIZE;

	err = gnutls_fingerprint(GNUTLS_DIG_SHA1, &d, sha1, &shalen);
	if (err) {
		gnutls_free(d.data);
		return err;
	}

	gnutls_free(d.data);

	vpninfo->peer_cert_hash = malloc(SHA1_SIZE * 2 + 6);
	if (vpninfo->peer_cert_hash) {
		snprintf(vpninfo->peer_cert_hash, 6, "sha1:");
		for (i = 0; i < shalen; i++)
			sprintf(&vpninfo->peer_cert_hash[i*2 + 5], "%02x", sha1[i]);
	}

	return 0;
}

char *openconnect_get_peer_cert_details(struct openconnect_info *vpninfo)
{
	gnutls_datum_t buf;

	if (gnutls_x509_crt_print(vpninfo->peer_cert, GNUTLS_CRT_PRINT_FULL, &buf))
		return NULL;

	return (char *)buf.data;
}

int openconnect_get_peer_cert_DER(struct openconnect_info *vpninfo,
				  unsigned char **buf)
{
	size_t l = 0;
	unsigned char *ret = NULL;

	if (gnutls_x509_crt_export(vpninfo->peer_cert, GNUTLS_X509_FMT_DER,
				   ret, &l) != GNUTLS_E_SHORT_MEMORY_BUFFER)
		return -EIO;

	ret = gnutls_malloc(l);
	if (!ret)
		return -ENOMEM;

	if (gnutls_x509_crt_export(vpninfo->peer_cert, GNUTLS_X509_FMT_DER,
				   ret, &l)) {
		gnutls_free(ret);
		return -EIO;
	}
	*buf = ret;
	return l;
}

void openconnect_free_cert_info(struct openconnect_info *vpninfo,
				void *buf)
{
	gnutls_free(buf);
}

static int verify_peer(gnutls_session_t session)
{
	struct openconnect_info *vpninfo = gnutls_session_get_ptr(session);
	const gnutls_datum_t *cert_list;
	gnutls_x509_crt_t cert;
	unsigned int status, cert_list_size;
	const char *reason = NULL;
	int err = 0;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (!cert_list) {
		vpn_progress(vpninfo, PRG_ERR, _("Server presented no certificate\n"));
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

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

	vpninfo->peer_cert = cert;
	err = set_peer_cert_hash(vpninfo);
	if (err < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Could not calculate hash of server's certificate\n"));
	}

	err = gnutls_certificate_verify_peers2(session, &status);
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

	if (reason)
		goto done;

	if (!gnutls_x509_crt_check_hostname(cert, vpninfo->hostname)) {
		int i, ret;
		unsigned char addrbuf[sizeof(struct in6_addr)];
		unsigned char certaddr[sizeof(struct in6_addr)];
		size_t addrlen = 0, certaddrlen;

		/* gnutls_x509_crt_check_hostname() doesn't cope with IPv6 literals
		   in URI form with surrounding [] so we must check for ourselves. */
		if (vpninfo->hostname[0] == '[' &&
		    vpninfo->hostname[strlen(vpninfo->hostname)-1] == ']') {
			char *p = &vpninfo->hostname[strlen(vpninfo->hostname)-1];
			*p = 0;
			if (inet_pton(AF_INET6, vpninfo->hostname + 1, addrbuf) > 0)
				addrlen = 16;
			*p = ']';
		}
#if GNUTLS_VERSION_NUMBER < 0x030306
		/* And before 3.3.6 it didn't check IP addresses at all. */
		else if (inet_pton(AF_INET, vpninfo->hostname, addrbuf) > 0)
			addrlen = 4;
		else if (inet_pton(AF_INET6, vpninfo->hostname, addrbuf) > 0)
			addrlen = 16;
#endif
		if (!addrlen) {
			/* vpninfo->hostname was not a bare IP address. Nothing to do */
			goto badhost;
		}

		for (i = 0; ; i++) {
			certaddrlen = sizeof(certaddr);
			ret = gnutls_x509_crt_get_subject_alt_name(cert, i, certaddr,
								   &certaddrlen, NULL);
			/* If this happens, it wasn't an IP address. */
			if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
				continue;
			if (ret < 0)
				break;
			if (ret != GNUTLS_SAN_IPADDRESS)
				continue;
			if (certaddrlen == addrlen && !memcmp(addrbuf, certaddr, addrlen))
				goto done;
		}
	badhost:
		reason = _("certificate does not match hostname");
	}
 done:
	if (reason) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("Server certificate verify failed: %s\n"),
			     reason);
		if (vpninfo->validate_peer_cert)
			err = vpninfo->validate_peer_cert(vpninfo->cbdata,
							  reason) ? GNUTLS_E_CERTIFICATE_ERROR : 0;
		else
			err = GNUTLS_E_CERTIFICATE_ERROR;
	}

	return err;
}


/* The F5 firewall is confused when the TLS client hello is between
 * 256 and 512 bytes. By disabling several TLS options we force the
 * client hello to be < 256 bytes. We don't do that in gnutls versions
 * >= 3.2.9 as there the %COMPAT keyword ensures that the client hello
 * will be outside that range.
 */
#if GNUTLS_VERSION_NUMBER >= 0x030209
# define DEFAULT_PRIO "NORMAL:-VERS-SSL3.0:%COMPAT"
#else
# define _DEFAULT_PRIO "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0:" \
	"%COMPAT:%DISABLE_SAFE_RENEGOTIATION:%LATEST_RECORD_VERSION"
# if GNUTLS_VERSION_MAJOR >= 3
#  define DEFAULT_PRIO _DEFAULT_PRIO":-CURVE-ALL:-ECDHE-RSA:-ECDHE-ECDSA"
#else
#  define DEFAULT_PRIO _DEFAULT_PRIO
# endif
#endif

int openconnect_open_https(struct openconnect_info *vpninfo)
{
	int ssl_sock = -1;
	int err;
	const char * prio;

	if (vpninfo->https_sess)
		return 0;

	if (vpninfo->peer_cert) {
		gnutls_x509_crt_deinit(vpninfo->peer_cert);
		vpninfo->peer_cert = NULL;
	}
	free(vpninfo->peer_cert_hash);
	vpninfo->peer_cert_hash = 0;
	gnutls_free(vpninfo->cstp_cipher);
	vpninfo->cstp_cipher = NULL;

	ssl_sock = connect_https_socket(vpninfo);
	if (ssl_sock < 0)
		return ssl_sock;

	if (!vpninfo->https_cred) {
		gnutls_certificate_allocate_credentials(&vpninfo->https_cred);
		if (!vpninfo->no_system_trust) {
#ifdef HAVE_GNUTLS_CERTIFICATE_SET_X509_SYSTEM_TRUST
			gnutls_certificate_set_x509_system_trust(vpninfo->https_cred);
#else
			gnutls_certificate_set_x509_trust_file(vpninfo->https_cred,
							       DEFAULT_SYSTEM_CAFILE,
							       GNUTLS_X509_FMT_PEM);
#endif
		}
		gnutls_certificate_set_verify_function(vpninfo->https_cred,
						       verify_peer);

#ifdef ANDROID_KEYSTORE
		if (vpninfo->cafile && !strncmp(vpninfo->cafile, "keystore:", 9)) {
			gnutls_datum_t datum;
			unsigned int nr_certs;

			err = load_datum(vpninfo, &datum, vpninfo->cafile);
			if (err < 0) {
				gnutls_certificate_free_credentials(vpninfo->https_cred);
				vpninfo->https_cred = NULL;
				return err;
			}

			/* For GnuTLS 3.x We should use gnutls_x509_crt_list_import2() */
			nr_certs = count_x509_certificates(&datum);
			if (nr_certs) {
				gnutls_x509_crt_t *certs;
				int i;

				certs = calloc(nr_certs, sizeof(*certs));
				if (!certs) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Failed to allocate memory for cafile certs\n"));
					gnutls_free(datum.data);
					gnutls_certificate_free_credentials(vpninfo->https_cred);
					vpninfo->https_cred = NULL;
					closesocket(ssl_sock);
					return -ENOMEM;
				}
				err = gnutls_x509_crt_list_import(certs, &nr_certs, &datum,
								  GNUTLS_X509_FMT_PEM, 0);
				gnutls_free(datum.data);
				if (err >= 0) {
					nr_certs = err;
					err = gnutls_certificate_set_x509_trust(vpninfo->https_cred,
										certs, nr_certs);
				}
				for (i = 0; i < nr_certs; i++)
					gnutls_x509_crt_deinit(certs[i]);
				free(certs);
				if (err < 0) {
					/* From crt_list_import or set_x509_trust */
					vpn_progress(vpninfo, PRG_ERR,
						     _("Failed to read certs from cafile: %s\n"),
						     gnutls_strerror(err));
					gnutls_certificate_free_credentials(vpninfo->https_cred);
					vpninfo->https_cred = NULL;
					closesocket(ssl_sock);
					return -EINVAL;
				}
			}
		} else
#endif
		if (vpninfo->cafile) {
			err = gnutls_certificate_set_x509_trust_file(vpninfo->https_cred,
								     vpninfo->cafile,
								     GNUTLS_X509_FMT_PEM);
			if (err < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to open CA file '%s': %s\n"),
					     vpninfo->cafile, gnutls_strerror(err));
				gnutls_certificate_free_credentials(vpninfo->https_cred);
				vpninfo->https_cred = NULL;
				closesocket(ssl_sock);
				return -EINVAL;
			}
		}

		if (vpninfo->cert) {
			err = load_certificate(vpninfo);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Loading certificate failed. Aborting.\n"));
				gnutls_certificate_free_credentials(vpninfo->https_cred);
				vpninfo->https_cred = NULL;
				closesocket(ssl_sock);
				return err;
			}
		}
	}
	gnutls_init(&vpninfo->https_sess, GNUTLS_CLIENT);
	gnutls_session_set_ptr(vpninfo->https_sess, (void *) vpninfo);
#if defined(HAVE_TROUSERS) && !defined(HAVE_GNUTLS_CERTIFICATE_SET_KEY)
	if (vpninfo->my_pkey == OPENCONNECT_TPM_PKEY)
		gnutls_sign_callback_set(vpninfo->https_sess, gtls2_tpm_sign_cb, vpninfo);
#endif
	/* We depend on 3.2.9 because that has the workaround for the
	   obnoxious F5 firewall that drops packets of certain sizes */
	if (gnutls_check_version("3.2.9") &&
	    string_is_hostname(vpninfo->hostname))
		gnutls_server_name_set(vpninfo->https_sess, GNUTLS_NAME_DNS,
				       vpninfo->hostname,
				       strlen(vpninfo->hostname));

	if (vpninfo->pfs) {
		prio = DEFAULT_PRIO":-RSA";
	} else {
		prio = DEFAULT_PRIO;
	}

	err = gnutls_priority_set_direct(vpninfo->https_sess,
					prio, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set TLS priority string: %s\n"),
			     gnutls_strerror(err));
		gnutls_deinit(vpninfo->https_sess);
		vpninfo->https_sess = NULL;
		closesocket(ssl_sock);
		return -EIO;
	}

	gnutls_record_disable_padding(vpninfo->https_sess);
	gnutls_credentials_set(vpninfo->https_sess, GNUTLS_CRD_CERTIFICATE, vpninfo->https_cred);
	gnutls_transport_set_ptr(vpninfo->https_sess,(gnutls_transport_ptr_t)(intptr_t)ssl_sock);

	vpn_progress(vpninfo, PRG_INFO, _("SSL negotiation with %s\n"),
		     vpninfo->hostname);

#ifdef GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT
	gnutls_handshake_set_timeout(vpninfo->https_sess,
				     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
#endif

	err = cstp_handshake(vpninfo, 1);
	if (err)
		return err;

	gnutls_free(vpninfo->cstp_cipher);
	vpninfo->cstp_cipher = get_gnutls_cipher(vpninfo->https_sess);

	vpninfo->ssl_fd = ssl_sock;

	vpninfo->ssl_read = openconnect_gnutls_read;
	vpninfo->ssl_write = openconnect_gnutls_write;
	vpninfo->ssl_gets = openconnect_gnutls_gets;

	return 0;
}

int cstp_handshake(struct openconnect_info *vpninfo, unsigned init)
{
	int err;
	int ssl_sock = -1;

	ssl_sock = (intptr_t)gnutls_transport_get_ptr(vpninfo->https_sess);

	while ((err = gnutls_handshake(vpninfo->https_sess))) {
		if (err == GNUTLS_E_AGAIN) {
			fd_set rd_set, wr_set;
			int maxfd = ssl_sock;

			FD_ZERO(&rd_set);
			FD_ZERO(&wr_set);

			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(ssl_sock, &wr_set);
			else
				FD_SET(ssl_sock, &rd_set);

			cmd_fd_set(vpninfo, &rd_set, &maxfd);
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (is_cancel_pending(vpninfo, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL connection cancelled\n"));
				gnutls_deinit(vpninfo->https_sess);
				vpninfo->https_sess = NULL;
				closesocket(ssl_sock);
				return -EINTR;
			}
		} else if (err == GNUTLS_E_INTERRUPTED || gnutls_error_is_fatal(err)) {
			vpn_progress(vpninfo, PRG_ERR, _("SSL connection failure: %s\n"),
							 gnutls_strerror(err));
			gnutls_deinit(vpninfo->https_sess);
			vpninfo->https_sess = NULL;
			closesocket(ssl_sock);
			return -EIO;
		} else {
			/* non-fatal error or warning. Ignore it and continue */
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("GnuTLS non-fatal return during handshake: %s\n"),
				     gnutls_strerror(err));
		}
	}

	if (init) {
		vpn_progress(vpninfo, PRG_INFO, _("Connected to HTTPS on %s\n"),
			     vpninfo->hostname);
	} else {
		vpn_progress(vpninfo, PRG_INFO, _("Renegotiated SSL on %s\n"),
			     vpninfo->hostname);
	}

	return 0;
}

void openconnect_close_https(struct openconnect_info *vpninfo, int final)
{
	if (vpninfo->https_sess) {
		gnutls_deinit(vpninfo->https_sess);
		vpninfo->https_sess = NULL;
	}
	if (vpninfo->ssl_fd != -1) {
		closesocket(vpninfo->ssl_fd);
		unmonitor_read_fd(vpninfo, ssl);
		unmonitor_write_fd(vpninfo, ssl);
		unmonitor_except_fd(vpninfo, ssl);
		vpninfo->ssl_fd = -1;
	}
	if (final && vpninfo->https_cred) {
		gnutls_certificate_free_credentials(vpninfo->https_cred);
		vpninfo->https_cred = NULL;
#if defined(HAVE_P11KIT) && !defined(HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION)
		if ((vpninfo->cert && !strncmp(vpninfo->cert, "pkcs11:", 7)) ||
		    (vpninfo->sslkey && !strncmp(vpninfo->sslkey, "pkcs11:", 7))) {
			char pin_source[40];
			sprintf(pin_source, "openconnect:%p", vpninfo);
			p11_kit_pin_unregister_callback(pin_source, p11kit_pin_callback, vpninfo);
		}
#endif
#ifdef HAVE_TROUSERS
		if (vpninfo->tpm_key_policy) {
			Tspi_Context_CloseObject(vpninfo->tpm_context, vpninfo->tpm_key_policy);
			vpninfo->tpm_key = 0;
		}
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
#ifndef HAVE_GNUTLS_CERTIFICATE_SET_KEY
		if (vpninfo->my_pkey && vpninfo->my_pkey != OPENCONNECT_TPM_PKEY) {
			gnutls_privkey_deinit(vpninfo->my_pkey);
			vpninfo->my_pkey = NULL;
			/* my_p11key went with it */
		}
		if (vpninfo->my_certs) {
			int i;
			for (i = 0; i < vpninfo->nr_my_certs; i++)
				if (vpninfo->free_my_certs[i])
					gnutls_x509_crt_deinit(vpninfo->my_certs[i]);
			gnutls_free(vpninfo->my_certs);
			gnutls_free(vpninfo->free_my_certs);
			vpninfo->my_certs = NULL;
			vpninfo->free_my_certs = NULL;
		}
#endif
	}
}

int openconnect_init_ssl(void)
{
#ifdef _WIN32
	int ret = openconnect__win32_sock_init();
	if (ret)
		return ret;
#endif
	if (gnutls_global_init())
		return -EIO;

	return 0;
}

char *get_gnutls_cipher(gnutls_session_t session)
{
	char *str;
#if GNUTLS_VERSION_NUMBER > 0x03010a
	str = gnutls_session_get_desc(session);
#else
	str = gnutls_strdup(gnutls_cipher_suite_get_name(
		gnutls_kx_get(session), gnutls_cipher_get(session),
		gnutls_mac_get(session)));
#endif
	return str;
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

int openconnect_md5(unsigned char *result, void *data, int datalen)
{
	gnutls_datum_t d;
	size_t md5len = MD5_SIZE;

	d.data = data;
	d.size = datalen;
	if (gnutls_fingerprint(GNUTLS_DIG_MD5, &d, result, &md5len))
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
	memcpy(buf, vpninfo->local_cert_md5, sizeof(vpninfo->local_cert_md5));

	return 0;
}

#if defined(HAVE_P11KIT) || defined(HAVE_GNUTLS_SYSTEM_KEYS)
static int gnutls_pin_callback(void *priv, int attempt, const char *uri,
			       const char *token_label, unsigned int flags,
			       char *pin, size_t pin_max)
{
	struct openconnect_info *vpninfo = priv;
	struct pin_cache **cache = &vpninfo->pin_cache;
	struct oc_auth_form f;
	struct oc_form_opt o;
	char message[1024];
	int ret;

	if (!vpninfo || !vpninfo->process_auth_form)
		return -1;

	while (*cache) {
		if (!strcmp(uri, (*cache)->token)) {
			if ((*cache)->pin) {
				if (attempt == 0) {
					snprintf(pin, pin_max, "%s", (*cache)->pin);
					return 0;
				}
				memset((*cache)->pin, 0x5a, strlen((*cache)->pin));
				free((*cache)->pin);
				(*cache)->pin = NULL;
			}
			break;
		}
		cache = &(*cache)->next;
	}
	if (!*cache) {
		*cache = calloc(1, sizeof(struct pin_cache));
		if (!*cache)
			return -1;

		(*cache)->token = strdup(uri);
	}

	memset(&f, 0, sizeof(f));
	f.auth_id = (char *)"pkcs11_pin";
	f.opts = &o;

	message[sizeof(message)-1] = 0;
	snprintf(message, sizeof(message) - 1, _("PIN required for %s"), token_label);
	f.message = message;

	if (flags & GNUTLS_PIN_WRONG)
		f.error = (char *)_("Wrong PIN");

	if (flags & GNUTLS_PIN_FINAL_TRY)
		f.banner = (char *)_("This is the final try before locking!");
	else if (flags & GNUTLS_PIN_COUNT_LOW)
		f.banner = (char *)_("Only a few tries left before locking!");

	o.next = NULL;
	o.type = OC_FORM_OPT_PASSWORD;
	o.name = (char *)"pkcs11_pin";
	o.label = (char *)_("Enter PIN:");
	o._value = NULL;

	ret = process_auth_form(vpninfo, &f);
	if (ret || !o._value)
		return -1;

	snprintf(pin, pin_max, "%s", o._value);
	(*cache)->pin = o._value;

	return 0;
}

#ifndef HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION
static P11KitPin *p11kit_pin_callback(const char *pin_source, P11KitUri *pin_uri,
				      const char *pin_description,
				      P11KitPinFlags flags,
				      void *_vpninfo)
{
	struct openconnect_info *vpninfo = _vpninfo;
	char *uri;
	P11KitPin *pin = NULL;
	char pin_str[1024];
	unsigned gnutls_flags = 0;
	int attempt = 0;

	if (!vpninfo || !vpninfo->process_auth_form)
		return NULL;

	if (p11_kit_uri_format(pin_uri, P11_KIT_URI_FOR_TOKEN, &uri))
		return NULL;

	/*
	 * In p11-kit <= 0.12, these flags are *odd*.
	 * RETRY is 0xa, FINAL_TRY is 0x14 and MANY_TRIES is 0x28.
	 * So don't treat it like a sane bitmask. Fixed in
	 * http://cgit.freedesktop.org/p11-glue/p11-kit/commit/?id=59774b11
	 */
	if ((flags & P11_KIT_PIN_FLAGS_RETRY) == P11_KIT_PIN_FLAGS_RETRY) {
		attempt = 1;
		gnutls_flags |= GNUTLS_PIN_WRONG;
	}
	if ((flags & P11_KIT_PIN_FLAGS_FINAL_TRY) == P11_KIT_PIN_FLAGS_FINAL_TRY)
		gnutls_flags |= GNUTLS_PIN_FINAL_TRY;
	if ((flags & P11_KIT_PIN_FLAGS_MANY_TRIES) == P11_KIT_PIN_FLAGS_MANY_TRIES)
		gnutls_flags |= GNUTLS_PIN_COUNT_LOW;

	if (!gnutls_pin_callback(vpninfo, attempt, uri, pin_description,
				gnutls_flags, pin_str, sizeof(pin_str)))
		pin = p11_kit_pin_new_for_string(pin_str);

	memset(pin_str, 0x5a, sizeof(pin_str));
	free(uri);

	return pin;
}
#endif /* !HAVE_GNUTLS_X509_CRT_SET_PIN_FUNCTION */
#endif /* HAVE_P11KIT || HAVE_GNUTLS_SYSTEM_KEYS */

#ifdef HAVE_LIBPCSCLITE
int openconnect_hash_yubikey_password(struct openconnect_info *vpninfo,
				      const char *password, const void *ident, int id_len)
{
	unsigned char U[SHA1_SIZE];
	gnutls_hmac_hd_t dgst;
	int ret = -EIO;
	int i, j;

	if (gnutls_hmac_init(&dgst, GNUTLS_MAC_SHA1, password, strlen(password)))
		return -EIO;

	if (gnutls_hmac(dgst, ident, id_len))
		goto out;
	/* This is a subset of full PBKDF2, where we know the outer loop is only
	 * run once because our output length (16) is less than the hash output
	 * size (20). So just hard-code the value. */
	if (gnutls_hmac(dgst, "\x0\x0\x0\x1", 4))
		goto out;
	gnutls_hmac_output(dgst, U);

	memcpy(vpninfo->yubikey_pwhash, U, 16);

	for (i = 1; i < 1000; i++) {
		if (gnutls_hmac(dgst, U, SHA1_SIZE))
			goto out;

		gnutls_hmac_output(dgst, U);

		for (j = 0; j < 16; j++)
			vpninfo->yubikey_pwhash[j] ^= U[j];
	}

	ret = 0;
 out:
	gnutls_hmac_deinit(dgst, NULL);
	return ret;
}

int openconnect_yubikey_chalresp(struct openconnect_info *vpninfo,
				 const void *challenge, int chall_len, void *result)
{
	if (gnutls_hmac_fast(GNUTLS_MAC_SHA1, vpninfo->yubikey_pwhash, 16, challenge, chall_len, result))
		return -EIO;

	return 0;
}
#endif
