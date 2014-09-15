/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
 * Copyright © 2013 John Morrissey <jwm@horde.net>

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

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <liboath/oath.h>

#include "openconnect-internal.h"

static char *parse_hex(const char *tok, int len)
{
	unsigned char *data, *p;

	data = malloc((len + 1) / 2);
	if (!data)
		return NULL;

	p = data;

	if (len & 1) {
		char b[2] = { '0', tok[0] };
		if (!isxdigit((int)(unsigned char)tok[0])) {
			free(data);
			return NULL;
		}
		*(p++) = unhex(b);
		tok++;
		len--;
	}

	while (len) {
		if (!isxdigit((int)(unsigned char)tok[0]) ||
		    !isxdigit((int)(unsigned char)tok[1])) {
			free(data);
			return NULL;
		}
		*(p++) = unhex(tok);
		tok += 2;
		len -= 2;
	}

	return (char *)data;
}

static int pskc_decode(struct openconnect_info *vpninfo, const char *token_str,
		       int toklen, int mode)
{
#ifdef HAVE_LIBPSKC
	pskc_t *container;
	pskc_key_t *key;
	const char *key_algo;
	const char *want_algo;
	size_t klen;

	if (pskc_global_init())
		return -EIO;

	if (pskc_init(&container))
		return -ENOMEM;

	if (pskc_parse_from_memory(container, toklen, token_str))
		return -EINVAL;

	key = pskc_get_keypackage(container, 0);
	if (!key) {
		pskc_done(container);
		return -EINVAL;
	}
	if (mode == OC_TOKEN_MODE_HOTP)
		want_algo = "urn:ietf:params:xml:ns:keyprov:pskc:hotp";
	else
		want_algo = "urn:ietf:params:xml:ns:keyprov:pskc:totp";
	key_algo = pskc_get_key_algorithm(key);

	if (!key_algo || strcmp(key_algo, want_algo)) {
		pskc_done(container);
		return -EINVAL;
	}

	vpninfo->oath_secret = (char *)pskc_get_key_data_secret(key, &klen);
	vpninfo->oath_secret_len = klen;
	if (!vpninfo->oath_secret) {
		pskc_done(container);
		return -EINVAL;
	}
	vpninfo->token_time = pskc_get_key_data_counter(key, NULL);

	vpninfo->pskc = container;
	vpninfo->pskc_key = key;

	return 0;
#else /* !HAVE_LIBPSKC */
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without PSKC support\n"));
	return -EINVAL;
#endif /* HAVE_LIBPSKC */
}

int set_totp_mode(struct openconnect_info *vpninfo, const char *token_str)
{
	int ret, toklen;

	ret = oath_init();
	if (ret != OATH_OK)
		return -EIO;

	if (!token_str)
		return -EINVAL;

	toklen = strlen(token_str);
	while (toklen && isspace((int)(unsigned char)token_str[toklen-1]))
		toklen--;

	if (strncmp(token_str, "<?xml", 5) == 0) {
		vpninfo->hotp_secret_format = HOTP_SECRET_PSKC;
		ret = pskc_decode(vpninfo, token_str, toklen, OC_TOKEN_MODE_TOTP);
		if (ret)
			return -EINVAL;
	} else if (strncasecmp(token_str, "base32:", strlen("base32:")) == 0) {
		ret = oath_base32_decode(token_str + strlen("base32:"),
					 toklen - strlen("base32:"),
					 &vpninfo->oath_secret,
					 &vpninfo->oath_secret_len);
		if (ret != OATH_OK)
			return -EINVAL;
	} else if (strncmp(token_str, "0x", 2) == 0) {
		vpninfo->oath_secret_len = (toklen - 2) / 2;
		vpninfo->oath_secret = parse_hex(token_str + 2, toklen - 2);
		if (!vpninfo->oath_secret)
			return -EINVAL;
	} else {
		vpninfo->oath_secret = strdup(token_str);
		vpninfo->oath_secret_len = toklen;
	}

	vpninfo->token_mode = OC_TOKEN_MODE_TOTP;
	return 0;
}

int set_hotp_mode(struct openconnect_info *vpninfo, const char *token_str)
{
	int ret, toklen;
	char *p;

	ret = oath_init();
	if (ret != OATH_OK)
		return -EIO;

	if (!token_str)
		return -EINVAL;

	toklen = strlen(token_str);

	if (strncmp(token_str, "<?xml", 5) == 0) {
		vpninfo->hotp_secret_format = HOTP_SECRET_PSKC;
		ret = pskc_decode(vpninfo, token_str, toklen, OC_TOKEN_MODE_HOTP);
		if (ret)
			return -EINVAL;
		vpninfo->token_mode = OC_TOKEN_MODE_HOTP;
		return 0;
	}
	p = strrchr(token_str, ',');
	if (p) {
		long counter;
		toklen = p - token_str;
		p++;
		counter = strtol(p, &p, 0);
		if (counter < 0)
			return -EINVAL;
		while (*p) {
			if (isspace((int)(unsigned char)*p))
				p++;
			else
				return -EINVAL;
		}
		vpninfo->token_time = counter;
	} else {
		while (toklen &&
		       isspace((int)(unsigned char)token_str[toklen-1]))
			toklen--;
	}

	if (strncasecmp(token_str, "base32:", strlen("base32:")) == 0) {
		vpninfo->hotp_secret_format = HOTP_SECRET_BASE32;
		ret = oath_base32_decode(token_str + strlen("base32:"),
					 toklen - strlen("base32:"),
					 &vpninfo->oath_secret,
					 &vpninfo->oath_secret_len);
		if (ret != OATH_OK)
			return -EINVAL;
	} else if (strncmp(token_str, "0x", 2) == 0) {
		vpninfo->hotp_secret_format = HOTP_SECRET_HEX;
		vpninfo->oath_secret_len = (toklen - 2) / 2;
		vpninfo->oath_secret = parse_hex(token_str + 2, toklen - 2);
		if (!vpninfo->oath_secret)
			return -EINVAL;
	} else {
		vpninfo->hotp_secret_format = HOTP_SECRET_RAW;
		vpninfo->oath_secret = strdup(token_str);
		vpninfo->oath_secret_len = toklen;
	}

	vpninfo->token_mode = OC_TOKEN_MODE_HOTP;
	return 0;
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
int can_gen_totp_code(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt)
{
	if ((strcmp(opt->name, "secondary_password") != 0) ||
	    vpninfo->token_bypassed)
		return -EINVAL;
	if (vpninfo->token_tries == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate INITIAL tokencode\n"));
		vpninfo->token_time = 0;
	} else if (vpninfo->token_tries == 1) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate NEXT tokencode\n"));
		vpninfo->token_time += OATH_TOTP_DEFAULT_TIME_STEP_SIZE;
	} else {
		/* limit the number of retries, to avoid account lockouts */
		vpn_progress(vpninfo, PRG_INFO,
			     _("Server is rejecting the soft token; switching to manual entry\n"));
		return -ENOENT;
	}
	return 0;
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
int can_gen_hotp_code(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt)
{
	if ((strcmp(opt->name, "secondary_password") != 0) ||
	    vpninfo->token_bypassed)
		return -EINVAL;
	if (vpninfo->token_tries == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate INITIAL tokencode\n"));
	} else if (vpninfo->token_tries == 1) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate NEXT tokencode\n"));
	} else {
		/* limit the number of retries, to avoid account lockouts */
		vpn_progress(vpninfo, PRG_INFO,
			     _("Server is rejecting the soft token; switching to manual entry\n"));
		return -ENOENT;
	}
	return 0;
}

int do_gen_totp_code(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form,
		     struct oc_form_opt *opt)
{
	int oath_err;
	char tokencode[7];

	if (!vpninfo->token_time)
		vpninfo->token_time = time(NULL);

	vpn_progress(vpninfo, PRG_INFO, _("Generating OATH TOTP token code\n"));

	oath_err = oath_totp_generate(vpninfo->oath_secret,
				      vpninfo->oath_secret_len,
				      vpninfo->token_time,
				      OATH_TOTP_DEFAULT_TIME_STEP_SIZE,
				      OATH_TOTP_DEFAULT_START_TIME,
				      6, tokencode);
	if (oath_err != OATH_OK) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unable to generate OATH TOTP token code: %s\n"),
			     oath_strerror(oath_err));
		return -EIO;
	}

	vpninfo->token_tries++;
	opt->_value = strdup(tokencode);
	return opt->_value ? 0 : -ENOMEM;
}

static void buf_append_base32(struct oc_text_buf *buf, void *data, int len)
{
	size_t b32_len;
	char *b32 = NULL;

	if (oath_base32_encode(data, len, &b32, &b32_len)) {
		buf->error = ENOMEM;
		return;
	}
	buf_append_bytes(buf, b32, b32_len);
	free(b32);
}

static char *regen_hotp_secret(struct openconnect_info *vpninfo)
{
	char *new_secret = NULL;
	struct oc_text_buf *buf;
	int i;

	switch (vpninfo->hotp_secret_format) {
	case HOTP_SECRET_BASE32:
		buf = buf_alloc();
		buf_append(buf, "base32:");
		buf_append_base32(buf, vpninfo->oath_secret,
				  vpninfo->oath_secret_len);
		break;

	case HOTP_SECRET_HEX:
		buf = buf_alloc();
		buf_append(buf, "0x");
		for (i=0; i < vpninfo->oath_secret_len; i++)
			buf_append(buf, "%02x",
				   (unsigned char)vpninfo->oath_secret[i]);
		break;

	case HOTP_SECRET_RAW:
		buf = buf_alloc();
		buf_append_bytes(buf, vpninfo->oath_secret,
				 vpninfo->oath_secret_len);
		break;

	case HOTP_SECRET_PSKC:
#ifdef HAVE_LIBPSKC
	{
		size_t len;
		if (!vpninfo->pskc_key || !vpninfo->pskc)
			return NULL;
		pskc_set_key_data_counter(vpninfo->pskc_key, vpninfo->token_time);
		pskc_build_xml(vpninfo->pskc, &new_secret, &len);
		/* FFS #1: libpskc craps all over itself on pskc_build_xml().
		   https://bugzilla.redhat.com/show_bug.cgi?id=1129491
		   Hopefully this will be fixed by 2.4.2 but make it
		   unconditional for now... */
		if (1 || !pskc_check_version("2.4.2")) {
			pskc_done(vpninfo->pskc);
			vpninfo->pskc = NULL;
			vpninfo->pskc_key = NULL;
			if (pskc_init(&vpninfo->pskc) ||
			    pskc_parse_from_memory(vpninfo->pskc, len, new_secret)) {
				pskc_done(vpninfo->pskc);
				vpninfo->pskc = NULL;
			} else {
				vpninfo->pskc_key = pskc_get_keypackage(vpninfo->pskc, 0);
				vpninfo->oath_secret = (char *)pskc_get_key_data_secret(vpninfo->pskc_key, NULL);
			}
		}
		/* FFS #2: No terminating NUL byte */
		realloc_inplace(new_secret, len + 1);
		if (new_secret)
			new_secret[len] = 0;
		return new_secret;
	}
#endif
	default:
		return NULL;
	}

	buf_append(buf,",%ld", (long)vpninfo->token_time);
	if (!buf_error(buf)) {
		new_secret = buf->data;
		buf->data = NULL;
	}
	buf_free(buf);
	return new_secret;
}

int do_gen_hotp_code(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form,
		     struct oc_form_opt *opt)
{
	int oath_err;
	char tokencode[7];
	int ret;

	vpn_progress(vpninfo, PRG_INFO, _("Generating OATH HOTP token code\n"));

	if (vpninfo->lock_token) {
		/* This may call openconnect_set_token_mode() again to update
		 * the token if it's changed. */
		ret = vpninfo->lock_token(vpninfo->tok_cbdata);
		if (ret)
			return ret;
	}

	oath_err = oath_hotp_generate(vpninfo->oath_secret,
				      vpninfo->oath_secret_len,
				      vpninfo->token_time,
				      6, false, OATH_HOTP_DYNAMIC_TRUNCATION,
				      tokencode);
	if (oath_err != OATH_OK) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unable to generate OATH HOTP token code: %s\n"),
			     oath_strerror(oath_err));
		if (vpninfo->unlock_token)
			vpninfo->unlock_token(vpninfo->tok_cbdata, NULL);
		return -EIO;
	}
	vpninfo->token_time++;
	vpninfo->token_tries++;
	opt->_value = strdup(tokencode);
	if (vpninfo->unlock_token) {
		char *new_tok = regen_hotp_secret(vpninfo);
		vpninfo->unlock_token(vpninfo->tok_cbdata, new_tok);
		free(new_tok);
	}
	return opt->_value ? 0 : -ENOMEM;
}
