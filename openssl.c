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

#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "openconnect-internal.h"

int openconnect_sha1(unsigned char *result, void *data, int len)
{
        EVP_MD_CTX c;

        EVP_MD_CTX_init(&c);
        EVP_Digest(data, len, result, NULL, EVP_sha1(), NULL);
        EVP_MD_CTX_cleanup(&c);

        return 0;
}

int openconnect_get_cert_DER(struct openconnect_info *vpninfo,
			     struct x509_st *cert, unsigned char **buf)
{
	BIO *bp = BIO_new(BIO_s_mem());
	BUF_MEM *certinfo;
	size_t l;

	if (!i2d_X509_bio(bp, cert)) {
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
