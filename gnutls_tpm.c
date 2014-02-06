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
 */

/*
 * TPM code based on client-tpm.c from
 * Carolin Latze <latze@angry-red-pla.net> and Tobias Soder
 */

#include <errno.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include "openconnect-internal.h"

#include "gnutls.h"

#ifdef HAVE_TROUSERS

/* Signing function for TPM privkeys, set with gnutls_privkey_import_ext() */
static int tpm_sign_fn(gnutls_privkey_t key, void *_vpninfo,
		       const gnutls_datum_t *data, gnutls_datum_t *sig);


#ifndef HAVE_GNUTLS_CERTIFICATE_SET_KEY
/* We *want* to use gnutls_privkey_import_ext() to create a privkey with our
   own signing function tpm_sign_fn(). But GnuTLS 2.12 doesn't support that,
   so instead we have to register this sign_callback function with the
   *session* */
int gtls2_tpm_sign_cb(gnutls_session_t sess, void *_vpninfo,
		      gnutls_certificate_type_t cert_type,
		      const gnutls_datum_t *cert, const gnutls_datum_t *data,
		      gnutls_datum_t *sig)
{
	struct openconnect_info *vpninfo = _vpninfo;

	if (cert_type != GNUTLS_CRT_X509)
		return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;

	return tpm_sign_fn(NULL, vpninfo, data, sig);
}

/* In GnuTLS 2.12 since we don't have a normal privkey and hence can't just
   use gnutls_privkey_sign_data() with it, we have to jump through hoops to
   prepare the hash in exactly the right way and call our internal TPM
   signing function. */
int gtls2_tpm_sign_dummy_data(struct openconnect_info *vpninfo,
			      const gnutls_datum_t *data,
			      gnutls_datum_t *sig)
{
	static const unsigned char ber_encode[15] = {
		0x30, 0x21, /* SEQUENCE, length 31 */
		0x30, 0x09,   /* SEQUENCE, length 9 */
		0x06, 0x05,      /* OBJECT_ID, length 5 */
		0x2b, 0x0e, 0x03, 0x02, 0x1a,  /* SHA1 OID: 1.3.14.3.2.26 */
		0x05, 0x00,      /* NULL (parameters) */
		0x04, 0x14,   /* OCTET_STRING, length 20 */
		/* followed by the 20-byte sha1 */
	};
	gnutls_datum_t hash;
	unsigned char digest[sizeof(ber_encode) + SHA1_SIZE];
	size_t shalen = SHA1_SIZE;
	int err;

	err = gnutls_fingerprint(GNUTLS_DIG_SHA1, data,
				 &digest[sizeof(ber_encode)], &shalen);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to SHA1 input data for signing: %s\n"),
			     gnutls_strerror(err));
		return err;
	}

	memcpy(digest, ber_encode, sizeof(ber_encode));

	hash.data = digest;
	hash.size = sizeof(digest);

	return tpm_sign_fn(NULL, vpninfo, &hash, sig);
}
#endif /* !HAVE_GNUTLS_CERTIFICATE_SET_KEY */

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
			     _("Failed to create TPM hash object: %s\n"),
			     Trspi_Error_String(err));
		return GNUTLS_E_PK_SIGN_FAILED;
	}
	err = Tspi_Hash_SetHashValue(hash, data->size, data->data);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set value in TPM hash object: %s\n"),
			     Trspi_Error_String(err));
		Tspi_Context_CloseObject(vpninfo->tpm_context, hash);
		return GNUTLS_E_PK_SIGN_FAILED;
	}
	err = Tspi_Hash_Sign(hash, vpninfo->tpm_key, &sig->size, &sig->data);
	Tspi_Context_CloseObject(vpninfo->tpm_context, hash);
	if (err) {
		if (vpninfo->tpm_key_policy || err != TPM_E_AUTHFAIL)
			vpn_progress(vpninfo, PRG_ERR,
				     _("TPM hash signature failed: %s\n"),
				     Trspi_Error_String(err));
		if (err == TPM_E_AUTHFAIL)
			return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
		else
			return GNUTLS_E_PK_SIGN_FAILED;
	}
	return 0;
}

int load_tpm_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		 gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig)
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
		static const char nullpass[20];

		/* We don't seem to get the error here... */
		if (pass)
			err = Tspi_Policy_SetSecret(vpninfo->srk_policy,
						    TSS_SECRET_MODE_PLAIN,
						    strlen(pass), (BYTE *)pass);
		else /* Well-known NULL key */
			err = Tspi_Policy_SetSecret(vpninfo->srk_policy,
						    TSS_SECRET_MODE_SHA1,
						    sizeof(nullpass), (BYTE *)nullpass);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to set TPM PIN: %s\n"),
				     Trspi_Error_String(err));
			goto out_srkpol;
		}

		free(pass);

		/* ... we get it here instead. */
		err = Tspi_Context_LoadKeyByBlob(vpninfo->tpm_context, vpninfo->srk,
						 tss_len, asn1.data + ofs,
						 &vpninfo->tpm_key);
		if (!err)
			break;

		if (pass)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to load TPM key blob: %s\n"),
				     Trspi_Error_String(err));

		if (err != TPM_E_AUTHFAIL)
			goto out_srkpol;

		err = request_passphrase(vpninfo, "openconnect_tpm_srk",
					 &pass, _("Enter TPM SRK PIN:"));
		if (err)
			goto out_srkpol;
	}

#ifdef HAVE_GNUTLS_CERTIFICATE_SET_KEY
	gnutls_privkey_init(pkey);
	/* This would be nicer if there was a destructor callback. I could
	   allocate a data structure with the TPM handles and the vpninfo
	   pointer, and destroy that properly when the key is destroyed. */
	gnutls_privkey_import_ext(*pkey, GNUTLS_PK_RSA, vpninfo, tpm_sign_fn, NULL, 0);
#else
	*pkey = OPENCONNECT_TPM_PKEY;
#endif

 retry_sign:
	err = sign_dummy_data(vpninfo, *pkey, fdata, pkey_sig);
	if (err == GNUTLS_E_INSUFFICIENT_CREDENTIALS) {
		if (!vpninfo->tpm_key_policy) {
			err = Tspi_Context_CreateObject(vpninfo->tpm_context,
							TSS_OBJECT_TYPE_POLICY,
							TSS_POLICY_USAGE,
							&vpninfo->tpm_key_policy);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to create key policy object: %s\n"),
					     Trspi_Error_String(err));
				goto out_key;
			}
			err = Tspi_Policy_AssignToObject(vpninfo->tpm_key_policy,
							 vpninfo->tpm_key);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to assign policy to key: %s\n"),
					     Trspi_Error_String(err));
				goto out_key_policy;
			}
		}
		err = request_passphrase(vpninfo, "openconnect_tpm_key",
					 &pass, _("Enter TPM key PIN:"));
		if (err)
			goto out_key_policy;

		err = Tspi_Policy_SetSecret(vpninfo->tpm_key_policy,
					    TSS_SECRET_MODE_PLAIN,
					    strlen(pass), (void *)pass);
		free(pass);

		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to set key PIN: %s\n"),
				     Trspi_Error_String(err));
			goto out_key_policy;
		}
		goto retry_sign;
	}

	free(asn1.data);
	return 0;
 out_key_policy:
	Tspi_Context_CloseObject(vpninfo->tpm_context, vpninfo->tpm_key_policy);
	vpninfo->tpm_key_policy = 0;
 out_key:
	Tspi_Context_CloseObject(vpninfo->tpm_context, vpninfo->tpm_key);
	vpninfo->tpm_key = 0;
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
	free(asn1.data);
	return -EIO;
}

#endif /* HAVE_TROUSERS */
