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

#ifndef __OPENCONNECT_GNUTLS_H__
#define __OPENCONNECT_GNUTLS_H__

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>
#include <gnutls/abstract.h>

#include "openconnect-internal.h"

#ifndef HAVE_GNUTLS_PKCS12_SIMPLE_PARSE
/* If we're using a version of GnuTLS from before this was 
   exported, pull in our local copy. */
int gnutls_pkcs12_simple_parse (gnutls_pkcs12_t p12, const char *password,
				gnutls_x509_privkey_t * key,
				gnutls_x509_crt_t ** chain,
				unsigned int * chain_len,
				gnutls_x509_crt_t ** extra_certs,
				unsigned int * extra_certs_len,
				gnutls_x509_crl_t * crl,
				unsigned int flags);

#endif /* !HAVE_GNUTLS_PKCS12_SIMPLE_PARSE */


#ifndef HAVE_GNUTLS_CERTIFICATE_SET_KEY
int gtls2_tpm_sign_cb(gnutls_session_t sess, void *_vpninfo,
		      gnutls_certificate_type_t cert_type,
		      const gnutls_datum_t *cert, const gnutls_datum_t *data,
		      gnutls_datum_t *sig);
int gtls2_tpm_sign_dummy_data(struct openconnect_info *vpninfo,
			      const gnutls_datum_t *data,
			      gnutls_datum_t *sig);
#endif /* !HAVE_GNUTLS_CERTIFICATE_SET_KEY */

/* In GnuTLS 2.12 this can't be a real private key; we have to use the sign_callback
   instead. But we want to set the 'pkey' variable to *something* non-NULL in order
   to indicate that we aren't just using an x509 key. */
#define OPENCONNECT_TPM_PKEY ((void *)1UL)

static inline int sign_dummy_data(struct openconnect_info *vpninfo,
				  gnutls_privkey_t pkey,
				  const gnutls_datum_t *data,
				  gnutls_datum_t *sig)
{
#if defined (HAVE_TROUSERS) && !defined(HAVE_GNUTLS_CERTIFICATE_SET_KEY)
	if (pkey == OPENCONNECT_TPM_PKEY)
		return gtls2_tpm_sign_dummy_data(vpninfo, data, sig);
#endif
	return gnutls_privkey_sign_data(pkey, GNUTLS_DIG_SHA1, 0, data, sig);
}

int load_tpm_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		 gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig);

#endif /* __OPENCONNECT_GNUTLS_H__ */
