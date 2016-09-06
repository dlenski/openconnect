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
#include <openssl/rand.h>

#ifdef HAVE_LIBP11 /* And p11-kit */

#include <libp11.h>
#include <p11-kit/pkcs11.h>

static PKCS11_CTX *pkcs11_ctx(struct openconnect_info *vpninfo)
{
	PKCS11_CTX *ctx;

	if (!vpninfo->pkcs11_ctx) {
		ERR_load_PKCS11_strings();

		ctx = PKCS11_CTX_new();
		if (!ctx) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to establish libp11 PKCS#11 context:\n"));
			openconnect_report_ssl_errors(vpninfo);
			return NULL;
		}
		if (PKCS11_CTX_load(ctx, DEFAULT_PKCS11_MODULE) < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to load PKCS#11 provider module (%s):\n"),
				     DEFAULT_PKCS11_MODULE);
			openconnect_report_ssl_errors(vpninfo);
			PKCS11_CTX_free(ctx);
			return NULL;
		}
		vpninfo->pkcs11_ctx = ctx;
	}

	return vpninfo->pkcs11_ctx;
}

static int parse_uri_attr(const char *attr, int attrlen, unsigned char **field,
			  size_t *field_len)
{
	size_t outlen = 0;
	unsigned char *out;
	int ret = 0;

	out = malloc(attrlen + 1);
	if (!out)
		return -ENOMEM;

	while (!ret && attrlen) {
		if (*attr == '%') {
			if (attrlen < 3) {
				ret = -EINVAL;
			} else {
				out[outlen++] = unhex(attr+1);

				attrlen -= 3;
				attr += 3;
			}

		} else {
			out[outlen++] = *(attr++);
			attrlen--;
		}
	}

	if (ret)
		free(out);
	else {
		if (field_len)
			*field_len = outlen;
		out[outlen] = 0;
		*field = out;
	}

	return ret;
}



static int parse_pkcs11_uri(const char *uri, PKCS11_TOKEN **p_tok,
			    unsigned char **id, size_t *id_len,
			    char **label, char **pin)
{
	PKCS11_TOKEN *tok;
	char *newlabel = NULL;
	const char *end, *p;
	int ret = 0;

	tok = calloc(1, sizeof(*tok));
	if (!tok) {
		fprintf(stderr, "Could not allocate memory for token info\n");
		return -ENOMEM;
	}

	/* We are only ever invoked if the string starts with 'pkcs11:' */
	end = uri + 6;
	while (!ret && end[0] && end[1]) {
		p = end + 1;
		end = strchr(p, ';');
		if (!end)
			end = p + strlen(p);

		if (!strncmp(p, "model=", 6)) {
			p += 6;
			ret = parse_uri_attr(p, end - p, (void *)&tok->model, NULL);
		} else if (!strncmp(p, "manufacturer=", 13)) {
			p += 13;
			ret = parse_uri_attr(p, end - p, (void *)&tok->manufacturer, NULL);
		} else if (!strncmp(p, "token=", 6)) {
			p += 6;
			ret = parse_uri_attr(p, end - p, (void *)&tok->label, NULL);
		} else if (!strncmp(p, "serial=", 7)) {
			p += 7;
			ret = parse_uri_attr(p, end - p, (void *)&tok->serialnr, NULL);
		} else if (!strncmp(p, "object=", 7)) {
			p += 7;
			ret = parse_uri_attr(p, end - p, (void *)&newlabel, NULL);
		} else if (!strncmp(p, "id=", 3)) {
			p += 3;
			ret = parse_uri_attr(p, end - p, (void *)id, id_len);
		} else if (!strncmp(p, "type=", 5) || !strncmp(p, "object-type=", 12)) {
			p = strchr(p, '=') + 1;

			if ((end - p == 4 && !strncmp(p, "cert", 4)) ||
			    (end - p == 7 && !strncmp(p, "private", 7))) {
				/* Actually, just ignore it */
			} else
				ret = -EINVAL;
			/* Ignore object type for now. */
		} else if (!strncmp(p, "pin-value=", 10)) {
			/* XXX We could do better than this but it'll cover all sane
			   use cases. */
			char *pinvalue = NULL;
			p += 10;
			ret = parse_uri_attr(p, end - p, (void *)&pinvalue, NULL);
			if (pinvalue) {
				free(*pin);
				*pin = pinvalue;
			}
		} else {
			ret = -EINVAL;
		}
	}

	if (!ret) {
		*label = newlabel;
		*p_tok = tok;
	} else {
		free(tok);
		tok = NULL;
		free(newlabel);
	}

	return ret;
}

static int request_pin(struct openconnect_info *vpninfo, struct pin_cache *cache, int retrying)
{
	struct oc_auth_form f;
	struct oc_form_opt o;
	char message[1024];
	int ret;

	if (!vpninfo || !vpninfo->process_auth_form)
		return -EINVAL;

	if (vpninfo->cert_password) {
		cache->pin = vpninfo->cert_password;
		vpninfo->cert_password = NULL;
		return 0;
	}
	memset(&f, 0, sizeof(f));
	f.auth_id = (char *)"pkcs11_pin";
	f.opts = &o;
	message[sizeof(message)-1] = 0;
	snprintf(message, sizeof(message) - 1, _("PIN required for %s"), cache->token);
	f.message = message;
	if (retrying)
		f.error = (char *)_("Wrong PIN");
	o.next = NULL;
	o.type  = OC_FORM_OPT_PASSWORD;
	o.name = (char *)"pkcs11_pin";
	o.label = (char *)_("Enter PIN:");
	o._value = NULL;

	ret = process_auth_form(vpninfo, &f);
	if (ret || !o._value)
		return -EIO;

	cache->pin = o._value;
	return 0;
}

static int slot_login(struct openconnect_info *vpninfo, PKCS11_CTX *ctx, PKCS11_SLOT *slot)
{
	PKCS11_TOKEN *token = slot->token;
	struct pin_cache *cache = vpninfo->pin_cache;
	int ret, retrying = 0;

 retry:
	ERR_clear_error();
	if (!token->secureLogin) {
		if (!cache) {
			for (cache = vpninfo->pin_cache; cache; cache = cache->next)
				if (!strcmp(slot->description, cache->token))
					break;
		}
		if (!cache) {
			cache = malloc(sizeof(*cache));
			if (!cache)
				return -ENOMEM;
			cache->pin = NULL;
			cache->next = vpninfo->pin_cache;
			cache->token = strdup(slot->description);
			if (!cache->token) {
				free(cache);
				return -ENOMEM;
			}
			vpninfo->pin_cache = cache;
		}
		if (!cache->pin) {
			ret = request_pin(vpninfo, cache, retrying);
			if (ret)
				return ret;
		}
	}
	ret = PKCS11_login(slot, 0, cache ? cache->pin : NULL);
	if (ret) {
		unsigned long err = ERR_peek_error();
		if (ERR_GET_LIB(err) == ERR_LIB_PKCS11 &&
		    ERR_GET_FUNC(err) == PKCS11_F_PKCS11_LOGIN)
			err = ERR_GET_REASON(err);
		else
			err = CKR_OK; /* Anything we don't explicitly match */

		switch (ERR_GET_REASON(err)) {
		case CKR_PIN_INCORRECT:
			/* They'll be told about it in the next UI prompt */
			if (cache) {
				free(cache->pin);
				cache->pin = NULL;
			}
			retrying = 1;
			goto retry;
		case CKR_PIN_LOCKED:
			vpn_progress(vpninfo, PRG_ERR, _("PIN locked\n"));
			break;
		case CKR_PIN_EXPIRED:
			vpn_progress(vpninfo, PRG_ERR, _("PIN expired\n"));
			break;
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
			vpn_progress(vpninfo, PRG_ERR, _("Another user already logged in\n"));
			break;
		default:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown error logging in to PKCS#11 token\n"));
			openconnect_report_ssl_errors(vpninfo);
		}
		ERR_clear_error();
		return -EPERM;
	}
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Logged in to PKCS#11 slot '%s'\n"),
		     slot->description);
	return 0;
}

static PKCS11_CERT *slot_find_cert(struct openconnect_info *vpninfo, PKCS11_CTX *ctx,
				 PKCS11_SLOT *slot, const char *cert_label,
				 unsigned char *cert_id, size_t cert_id_len)
{
	PKCS11_CERT *cert_list = NULL, *cert = NULL;
	unsigned int cert_count;

	if (PKCS11_enumerate_certs(slot->token, &cert_list, &cert_count) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to enumerate certs in PKCS#11 slot '%s'\n"),
			     slot->description);
		return NULL;
	}

	vpn_progress(vpninfo, PRG_TRACE,
		     _("Found %d certs in slot '%s'\n"),
		     cert_count, slot->description);

	for (cert = cert_list; cert < &cert_list[cert_count]; cert++) {

		if (cert_label && strcmp(cert_label, cert->label))
			continue;

		if (cert_id && (cert_id_len != cert->id_len ||
				memcmp(cert_id, cert->id, cert_id_len)))
			continue;

		return cert;
	}
	return NULL;
}

int load_pkcs11_certificate(struct openconnect_info *vpninfo)
{
	PKCS11_CTX *ctx;
	PKCS11_TOKEN *match_tok = NULL;
	PKCS11_CERT *cert = NULL;
	char *cert_label = NULL;
	unsigned char *cert_id = NULL;
	size_t cert_id_len = 0;
	PKCS11_SLOT *slot_list = NULL, *slot, *login_slot = NULL;
	unsigned int slot_count, matching_slots = 0;
	int ret = 0;

	ctx = pkcs11_ctx(vpninfo);
	if (!ctx)
		return -EIO;

	if (parse_pkcs11_uri(vpninfo->cert, &match_tok, &cert_id,
			     &cert_id_len, &cert_label, &vpninfo->cert_password) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse PKCS#11 URI '%s'\n"),
			     vpninfo->cert);
		return -EINVAL;
	}

	if (PKCS11_enumerate_slots(ctx, &slot_list, &slot_count) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to enumerate PKCS#11 slots\n"));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EIO;
		goto out;
	}
	for (slot = slot_list; slot < &slot_list[slot_count] && slot != login_slot; slot++) {
		if (!slot->token)
			continue;
		if (match_tok->label &&
		    strcmp(match_tok->label, slot->token->label))
			continue;
		if (match_tok->manufacturer &&
		    strcmp(match_tok->manufacturer, slot->token->manufacturer))
			continue;
		if (match_tok->model &&
		    strcmp(match_tok->model, slot->token->model))
			continue;
		if (match_tok->serialnr &&
		    strcmp(match_tok->serialnr, slot->token->serialnr))
			continue;


		cert = slot_find_cert(vpninfo, ctx, slot, cert_label, cert_id, cert_id_len);
		if (cert)
			goto got_cert;

		login_slot = slot;
		matching_slots++;
	}
	/* If there was precisely one matching slot, and we still didn't find the cert,
	   try logging in to it. */
	if (matching_slots == 1 && login_slot->token->loginRequired) {
		slot = login_slot;
		vpn_progress(vpninfo, PRG_INFO,
			     _("Logging in to PKCS#11 slot '%s'\n"),
			     slot->description);
		if (!slot_login(vpninfo, ctx, slot)) {
			cert = slot_find_cert(vpninfo, ctx, slot, cert_label, cert_id, cert_id_len);
			if (cert)
				goto got_cert;
		}
	}
	ret = -EINVAL;
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to find PKCS#11 cert '%s'\n"),
		     vpninfo->cert);
 got_cert:
	if (cert) {
		/* This happens if the cert is too large for the fixed buffer
		   in libp11 :( */
		if (!cert->x509) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Certificate X.509 content not fetched by libp11\n"));
			ret = -EIO;
			goto out;
		}

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Using PKCS#11 certificate %s\n"), vpninfo->cert);

		vpninfo->cert_x509 = X509_dup(cert->x509);
		if (!SSL_CTX_use_certificate(vpninfo->https_ctx, vpninfo->cert_x509)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to install certificate in OpenSSL context\n"));
			openconnect_report_ssl_errors(vpninfo);
			ret = -EIO;
			goto out;
		}
		/* If the key is in PKCS#11 too (which is likely), then keep the slot around.
		   We might want to know which slot the certificate was found in, so we can
		   log into it to find the key. */
		if (!strncmp(vpninfo->sslkey, "pkcs11:", 7)) {
			vpninfo->pkcs11_slot_list = slot_list;
			vpninfo->pkcs11_slot_count = slot_count;
			vpninfo->pkcs11_cert_slot = slot;
			slot_list = NULL;
		}
		/* Also remember the ID of the cert, in case it helps us find the matching key */
		vpninfo->pkcs11_cert_id = malloc(cert->id_len);
		if (vpninfo->pkcs11_cert_id) {
			vpninfo->pkcs11_cert_id_len = cert->id_len;
			memcpy(vpninfo->pkcs11_cert_id, cert->id, cert->id_len);
		}
	}
 out:
	if (match_tok) {
		free(match_tok->model);
		free(match_tok->manufacturer);
		free(match_tok->serialnr);
		free(match_tok->label);
		free(match_tok);
	}
	free(cert_id);
	free(cert_label);
	if (slot_list)
		PKCS11_release_all_slots(ctx, slot_list, slot_count);

	return ret;
}

static PKCS11_KEY *slot_find_key(struct openconnect_info *vpninfo, PKCS11_CTX *ctx,
				 PKCS11_SLOT *slot, const char *key_label,
				 unsigned char *key_id, size_t key_id_len)
{
	PKCS11_KEY *key_list = NULL, *key = NULL;
	unsigned int key_count;

	if (PKCS11_enumerate_keys(slot->token, &key_list, &key_count) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to enumerate keys in PKCS#11 slot '%s'\n"),
			     slot->description);
		return NULL;
	}

	vpn_progress(vpninfo, PRG_TRACE,
		     _("Found %d keys in slot '%s'\n"),
		     key_count, slot->description);

	for (key = key_list; key < &key_list[key_count]; key++) {

		if (key_label && strcmp(key_label, key->label))
			continue;

		if (key_id && (key_id_len != key->id_len ||
			       memcmp(key_id, key->id, key_id_len)))
			continue;

		return key;
	}
	return NULL;
}

#ifndef OPENSSL_NO_EC
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define EVP_PKEY_id(k) ((k)->type)
#endif
static int validate_ecdsa_key(struct openconnect_info *vpninfo, EC_KEY *priv_ec)
{
	EVP_PKEY *pub_pkey;
	EC_KEY *pub_ec;
	unsigned char rdata[SHA1_SIZE];
	unsigned int siglen = ECDSA_size(priv_ec);
	unsigned char *sig;
	int ret = -EINVAL;

	pub_pkey = X509_get_pubkey(vpninfo->cert_x509);
	if (!pub_pkey) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Certificate has no public key\n"));
		goto out;
	}
	pub_ec = EVP_PKEY_get1_EC_KEY(pub_pkey);
	if (!pub_ec) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Certificate does not match private key\n"));
		goto out_pkey;
	}
	vpn_progress(vpninfo, PRG_TRACE, _("Checking EC key matches cert\n"));
	sig = malloc(siglen);
	if (!sig) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate signature buffer\n"));
		ret = -ENOMEM;
		goto out_pubec;
	}
	if (!RAND_bytes(rdata, sizeof(rdata))) {
		/* Actually, who cares? */
	}
	if (!ECDSA_sign(NID_sha1, rdata, sizeof(rdata),
			sig, &siglen, priv_ec)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to sign dummy data to validate EC key\n"));
		openconnect_report_ssl_errors(vpninfo);
		goto out_sig;
	}
	if (!ECDSA_verify(NID_sha1, rdata, sizeof(rdata), sig, siglen, pub_ec)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Certificate does not match private key\n"));
		goto out_sig;
	}

	/* Finally, copy the public EC_POINT data now that we know it really did match */
	EC_KEY_set_public_key(priv_ec, EC_KEY_get0_public_key(pub_ec));
	ret = 0;

 out_sig:
	free(sig);
 out_pubec:
	EC_KEY_free(pub_ec);
 out_pkey:
	EVP_PKEY_free(pub_pkey);
 out:
	return ret;
}
#endif

int load_pkcs11_key(struct openconnect_info *vpninfo)
{
	PKCS11_CTX *ctx;
	PKCS11_TOKEN *match_tok = NULL;
	PKCS11_KEY *key = NULL;
	EVP_PKEY *pkey = NULL;
	char *key_label = NULL;
	unsigned char *key_id = NULL;
	size_t key_id_len = 0;
	PKCS11_SLOT *slot_list = NULL, *slot, *login_slot = NULL;
	unsigned int slot_count, matching_slots = 0;
	int ret = 0;

	ctx = pkcs11_ctx(vpninfo);
	if (!ctx)
		return -EIO;

	if (parse_pkcs11_uri(vpninfo->sslkey, &match_tok, &key_id,
			     &key_id_len, &key_label, &vpninfo->cert_password) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse PKCS#11 URI '%s'\n"),
			     vpninfo->sslkey);
		return -EINVAL;
	}

	if (vpninfo->pkcs11_slot_list) {
		slot_list = vpninfo->pkcs11_slot_list;
		slot_count = vpninfo->pkcs11_slot_count;
	} else if (PKCS11_enumerate_slots(ctx, &slot_list, &slot_count) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to enumerate PKCS#11 slots\n"));
		openconnect_report_ssl_errors(vpninfo);
		ret = -EIO;
		goto out;
	}

	for (slot = slot_list; slot < &slot_list[slot_count] && slot != login_slot; slot++) {
		if (!slot->token)
			continue;
		if (match_tok->label &&
		    strcmp(match_tok->label, slot->token->label))
			continue;
		if (match_tok->manufacturer &&
		    strcmp(match_tok->manufacturer, slot->token->manufacturer))
			continue;
		if (match_tok->model &&
		    strcmp(match_tok->model, slot->token->model))
			continue;
		if (match_tok->serialnr &&
		    strcmp(match_tok->serialnr, slot->token->serialnr))
			continue;

		key = slot_find_key(vpninfo, ctx, slot, key_label, key_id, key_id_len);
		if (key)
			goto got_key;

		login_slot = slot;
		matching_slots++;
	}
	/* If there was precisely one matching slot, or if we know which slot
	   the cert was found in and the key wasn't separately specified, then
	   try that slot. */
	if (matching_slots != 1 && vpninfo->pkcs11_cert_slot &&
	    vpninfo->sslkey == vpninfo->cert) {
		/* Use the slot the cert was found in, if one specifier was given for both */
		matching_slots = 1;
		login_slot = vpninfo->pkcs11_cert_slot;
		vpninfo->pkcs11_cert_slot = NULL;
	}
	if (matching_slots == 1 && login_slot->token->loginRequired) {
		slot = login_slot;
		vpn_progress(vpninfo, PRG_INFO,
			     _("Logging in to PKCS#11 slot '%s'\n"),
			     slot->description);
		if (!slot_login(vpninfo, ctx, slot)) {
			key = slot_find_key(vpninfo, ctx, slot, key_label, key_id, key_id_len);
			if (key)
				goto got_key;

			/* We still haven't found it. If we weren't explicitly given a URI for
			   the key and we're inferring the location of the key from the cert,
			   then drop the label and try matching the CKA_ID of the cert. */
			if (vpninfo->cert == vpninfo->sslkey && vpninfo->pkcs11_cert_id &&
			    (key_label || !key_id)) {
				key = slot_find_key(vpninfo, ctx, slot, NULL, vpninfo->pkcs11_cert_id,
						    vpninfo->pkcs11_cert_id_len);
				if (key)
					goto got_key;
			}
		}
	}
	ret = -EINVAL;
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to find PKCS#11 key '%s'\n"),
		     vpninfo->sslkey);

 got_key:
	if (key) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Using PKCS#11 key %s\n"), vpninfo->sslkey);

		pkey = PKCS11_get_private_key(key);
		if (!pkey) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to instantiated private key from PKCS#11\n"));
			openconnect_report_ssl_errors(vpninfo);
			ret = -EIO;
			goto out;
		}

#ifndef OPENSSL_NO_EC
		/*
		 * If an EC EVP_PKEY has no public key, OpenSSL will crash
		 * when trying to check it matches the certificate:
		 * https://github.com/openssl/openssl/issues/1532
		 *
		 * Work around this by detecting this condition, manually
		 * checking that the certificate *does* match by performing
		 * a signature and validating it against the cert, then
		 * copying the EC_POINT public key information from the cert.
		 */
		if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
			EC_KEY *priv_ec = EVP_PKEY_get1_EC_KEY(pkey);

			ret = 0;
			if (!EC_KEY_get0_public_key(priv_ec))
				ret = validate_ecdsa_key(vpninfo, priv_ec);
			EC_KEY_free(priv_ec);
			if (ret)
				goto out;
		}
#endif
		if (!SSL_CTX_use_PrivateKey(vpninfo->https_ctx, pkey)) {
			vpn_progress(vpninfo, PRG_ERR, _("Add key from PKCS#11 failed\n"));
			openconnect_report_ssl_errors(vpninfo);
			ret = -EINVAL;
			goto out;
		}

		/* We have to keep the entire slot list around, because the EVP_PKEY
		   depends on the one we're using, and we have no way to free the
		   others. */
		vpninfo->pkcs11_slot_list = slot_list;
		vpninfo->pkcs11_slot_count = slot_count;
		slot_list = NULL;
	}
 out:
	if (match_tok) {
		free(match_tok->model);
		free(match_tok->manufacturer);
		free(match_tok->serialnr);
		free(match_tok->label);
		free(match_tok);
	}
	free(key_id);
	free(key_label);
	if (slot_list)
		PKCS11_release_all_slots(ctx, slot_list, slot_count);

	return ret;
}
#else
int load_pkcs11_key(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without PKCS#11 support\n"));
	return -EINVAL;
}
int load_pkcs11_certificate(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without PKCS#11 support\n"));
	return -EINVAL;
}
#endif
