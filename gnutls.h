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

#endif /* __OPENCONNECT_GNUTLS_H__ */
