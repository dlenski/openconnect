/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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

#include "openconnect-internal.h"

static int b32_char(char in)
{
	if (in >= 'A' && in <= 'Z')
		return in - 'A';
	if (in >= 'a' && in <= 'z')
		return in - 'a';
	if (in >= '2' && in <= '7')
		return in - '2' + 26;
	if (in == '=')
		return -2;
	return -1;
}

static int decode_b32_group(unsigned char *out, const char *in)
{
	uint32_t d = 0;
	int c, i, len;

	for (i = 0; i < 8; i++) {
		c = b32_char(in[i]);
		if (c == -1)
			return -EINVAL;
		if (c == -2)
			break;
		d <<= 5;
		d |= c;

		/* Write the top bits before they disappear off the top
		   of 'd' which is only a uint32_t */
		if (i == 1)
			out[0] = d >> 2;
	}
	len = i;
	if (i < 8) {
		d <<= 5 * (8 - i);
		while (++i < 8) {
			if (in[i] != '=')
				return -EINVAL;
		}
	}

	store_be32(out + 1, d);

	switch(len) {
	case 8:
		return 5;
	case 7:
		return 4;
	case 5:
		return 3;
	case 4:
		return 2;
	case 2:
		return 1;
	default:
		return -EINVAL;
	}
}

static int decode_base32(struct openconnect_info *vpninfo, const char *b32, int len)
{
	unsigned char *output = NULL;
	int inpos, outpos;
	int outlen;
	int ret;

	if (len % 8) {
	invalid:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid base32 token string\n"));
		free(output);
		return -EINVAL;
	}
	outlen = len / 8 * 5;
	output = malloc(outlen);
	if (!output) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate memory to decode OATH secret\n"));
		return -ENOMEM;
	}
	outpos = inpos = 0;
	while (inpos < len) {
		ret = decode_b32_group(output + outpos, b32 + inpos);
		if (ret < 0)
			goto invalid;

		inpos += 8;
		if (ret != 5 && inpos != len)
			goto invalid;
		outpos += ret;
	}
	vpninfo->oath_secret = (void *)output;
	vpninfo->oath_secret_len = outpos;
	return 0;
}

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
		vpninfo->token_mode = OC_TOKEN_MODE_TOTP;
		return 0;
	}
	if (!strncasecmp(token_str, "sha1:", 5)) {
		token_str += 5;
		toklen -= 5;
		vpninfo->oath_hmac_alg = OATH_ALG_HMAC_SHA1;
	} else if (!strncasecmp(token_str, "sha256:", 7)) {
		token_str += 7;
		toklen -= 7;
		vpninfo->oath_hmac_alg = OATH_ALG_HMAC_SHA256;
	} else if (!strncasecmp(token_str, "sha512:", 7)) {
		token_str += 7;
		toklen -= 7;
		vpninfo->oath_hmac_alg = OATH_ALG_HMAC_SHA512;
	} else
		vpninfo->oath_hmac_alg = OATH_ALG_HMAC_SHA1;

	if (strncasecmp(token_str, "base32:", strlen("base32:")) == 0) {
		ret = decode_base32(vpninfo, token_str + strlen("base32:"),
				    toklen - strlen("base32:"));
		if (ret)
			return ret;
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

	if (!strncasecmp(token_str, "sha1:", 5)) {
		token_str += 5;
		toklen -= 5;
		vpninfo->oath_hmac_alg = OATH_ALG_HMAC_SHA1;
	} else if (!strncasecmp(token_str, "sha256:", 7)) {
		token_str += 7;
		toklen -= 7;
		vpninfo->oath_hmac_alg = OATH_ALG_HMAC_SHA256;
	} else if (!strncasecmp(token_str, "sha512:", 7)) {
		toklen -= 7;
		token_str += 7;
		vpninfo->oath_hmac_alg = OATH_ALG_HMAC_SHA512;
	} else
		vpninfo->oath_hmac_alg = OATH_ALG_HMAC_SHA1;

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
		ret = decode_base32(vpninfo, token_str + strlen("base32:"),
				    toklen - strlen("base32:"));
		if (ret)
			return ret;
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
	if (vpninfo->token_tries == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate INITIAL tokencode\n"));
		vpninfo->token_time = 0;
	} else if (vpninfo->token_tries == 1) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate NEXT tokencode\n"));
		vpninfo->token_time += 30;
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

static int gen_hotp(struct openconnect_info *vpninfo, uint64_t data, char *output)
{
	uint32_t data_be[2];
	int digest;

	data_be[0] = htonl(data >> 32);
	data_be[1] = htonl(data);

	digest = hotp_hmac(vpninfo, data_be);
	if (digest < 0)
		return digest;

	digest %= 1000000;
	snprintf(output, 7, "%06d", digest);

	return 0;
}

int do_gen_totp_code(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form,
		     struct oc_form_opt *opt)
{
	char tokencode[7];
	uint64_t challenge;

	if (!vpninfo->token_time)
		vpninfo->token_time = time(NULL);

	vpn_progress(vpninfo, PRG_INFO, _("Generating OATH TOTP token code\n"));

	/* XXX: Support non-standard start time and step size */
	challenge = vpninfo->token_time / 30;

	if (gen_hotp(vpninfo, challenge, tokencode))
		return -EIO;

	vpninfo->token_tries++;
	opt->_value = strdup(tokencode);
	return opt->_value ? 0 : -ENOMEM;
}

static void buf_append_base32(struct oc_text_buf *buf, void *data, int len)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	unsigned char *bytes = data;
	int i, j, b32_len = ((len + 4) / 5) * 8;
	uint32_t d;
	char b32[8];

	if (buf_ensure_space(buf, b32_len + 1))
		return;

	for (i = 0; i < (len - 4); i += 5) {
		/* Load low 4 input bytes into 'd' */
		d = load_be32(&bytes[i + 1]);
		/* Loop backwardd over output group, emitting low
		 * 5 bits of 'd' each time and shifting. */
		for (j = 7; j >= 0; j--) {
			b32[j] = alphabet[d & 31];
			d >>= 5;
			/* Mask in the last input byte when we can fit it */
			if (j == 5)
				d |= bytes[i] << 17;
		}
		buf_append_bytes(buf, b32, 8);
	}
	if (i < len) {
		d = 0;
		/* This is basically load_be32(bytes + i) but substituting
		 * zeroes instead of reading off the end. */
		for (j = 0; j < 4; j++) {
			d <<= 8;
			if (i + j < len)
				d |= bytes[i + j];
		}
		/* Now, work out how much '=' padding we need */
		memset(b32, '=', 8);
		b32_len = (((len - i) * 8) + 4) / 5;
		memset(b32 + b32_len, '=', 8 - b32_len);
		/* If we need 7 characters of data then put the seventh
		 * in manually because the LSB of 'd' is actually bit 3
		 * of the output character. */
		if (b32_len == 7) {
			b32[6] = alphabet[(d & 3) << 3];
			b32_len--;
		}
		/* Now shift bits into the right place and do the simple
		 * loop emitting characters from the low 5 bits of 'd'. */
		d >>= ((8 - b32_len) * 5) - 8;
		for (j = b32_len - 1; j >= 0; j--) {
			b32[j] = alphabet[d & 31];
			d >>= 5;
		}
		buf_append_bytes(buf, b32, 8);
	}
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
	if (gen_hotp(vpninfo, vpninfo->token_time, tokencode))
		return -EIO;

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
