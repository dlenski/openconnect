/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2018 David Woodhouse.
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

#include <gnutls/gnutls.h>
#include "openconnect-internal.h"

#include "gnutls.h"

#ifdef HAVE_TSS2
#define TSSINCLUDE(x) < HAVE_TSS2/x >
#include TSSINCLUDE(tss.h)

struct oc_tpm2_ctx {
};

int load_tpm2_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		  gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig)
{
	gnutls_datum_t asn1;
	int err;

	err = gnutls_pem_base64_decode_alloc("TSS2 KEY BLOB", fdata, &asn1);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error decoding TSS2 key blob: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}
	free(asn1.data);
	vpn_progress(vpninfo, PRG_ERR,
		     _("TPM2 not really implemented yet\n"));
	return -EINVAL;
}

void release_tpm2_ctx(struct openconnect_info *vpninfo)
{
	if (vpninfo->tpm2)
		free(vpninfo->tpm2);
	vpninfo->tpm2 = NULL;
}
#endif /* HAVE_TSS2 */
