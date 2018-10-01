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

#ifndef __OPENCONNECT_GNUTLS_H__
#define __OPENCONNECT_GNUTLS_H__

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>
#include <gnutls/abstract.h>

#include "openconnect-internal.h"

int load_tpm1_key(struct openconnect_info *vpninfo, gnutls_datum_t *fdata,
		  gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig);
void release_tpm1_ctx(struct openconnect_info *info);

char *get_gnutls_cipher(gnutls_session_t session);

#endif /* __OPENCONNECT_GNUTLS_H__ */
