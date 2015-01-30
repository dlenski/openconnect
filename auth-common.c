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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>

#include "openconnect-internal.h"

int xmlnode_is_named(xmlNode *xml_node, const char *name)
{
	return !strcmp((char *)xml_node->name, name);
}

int xmlnode_get_prop(xmlNode *xml_node, const char *name, char **var)
{
	char *str = (char *)xmlGetProp(xml_node, (unsigned char *)name);

	if (!str)
		return -ENOENT;

	free(*var);
	*var = str;
	return 0;
}

int xmlnode_match_prop(xmlNode *xml_node, const char *name, const char *match)
{
	char *str = (char *)xmlGetProp(xml_node, (unsigned char *)name);
	int ret = 0;

	if (!str)
		return -ENOENT;

	if (strcmp(str, match))
	    ret = -EEXIST;

	free(str);
	return ret;
}

int append_opt(struct oc_text_buf *body, char *opt, char *name)
{
	if (buf_error(body))
		return buf_error(body);

	if (body->pos)
		buf_append(body, "&");

	buf_append_urlencoded(body, opt);
	buf_append(body, "=");
	buf_append_urlencoded(body, name);

	return 0;
}

int append_form_opts(struct openconnect_info *vpninfo,
			    struct oc_auth_form *form, struct oc_text_buf *body)
{
	struct oc_form_opt *opt;
	int ret;

	for (opt = form->opts; opt; opt = opt->next) {
		ret = append_opt(body, opt->name, opt->_value);
		if (ret)
			return ret;
	}
	return 0;
}

void free_opt(struct oc_form_opt *opt)
{
	/* for SELECT options, opt->value is a pointer to oc_choice->name */
	if (opt->type != OC_FORM_OPT_SELECT)
		free(opt->_value);
	else {
		struct oc_form_opt_select *sel = (void *)opt;
		int i;

		for (i = 0; i < sel->nr_choices; i++) {
			free(sel->choices[i]->name);
			free(sel->choices[i]->label);
			free(sel->choices[i]->auth_type);
			free(sel->choices[i]->override_name);
			free(sel->choices[i]->override_label);
			free(sel->choices[i]);
		}
		free(sel->choices);
	}

	free(opt->name);
	free(opt->label);
	free(opt);
}

void free_auth_form(struct oc_auth_form *form)
{
	if (!form)
		return;
	while (form->opts) {
		struct oc_form_opt *tmp = form->opts->next;
		free_opt(form->opts);
		form->opts = tmp;
	}
	free(form->error);
	free(form->message);
	free(form->banner);
	free(form->auth_id);
	free(form->method);
	free(form->action);
	free(form);
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
int do_gen_tokencode(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form)
{
	struct oc_form_opt *opt;

	for (opt = form->opts; ; opt = opt->next) {
		/* this form might not have anything for us to do */
		if (!opt)
			return 0;
		if (opt->type == OC_FORM_OPT_TOKEN)
			break;
	}

	switch (vpninfo->token_mode) {
#ifdef HAVE_LIBSTOKEN
	case OC_TOKEN_MODE_STOKEN:
		return do_gen_stoken_code(vpninfo, form, opt);
#endif
	case OC_TOKEN_MODE_TOTP:
		return do_gen_totp_code(vpninfo, form, opt);

	case OC_TOKEN_MODE_HOTP:
		return do_gen_hotp_code(vpninfo, form, opt);
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return do_gen_yubikey_code(vpninfo, form, opt);
#endif
	default:
		return -EINVAL;
	}
}

int can_gen_tokencode(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt)
{
	switch (vpninfo->token_mode) {
#ifdef HAVE_LIBSTOKEN
	case OC_TOKEN_MODE_STOKEN:
		return can_gen_stoken_code(vpninfo, form, opt);
#endif
	case OC_TOKEN_MODE_TOTP:
		return can_gen_totp_code(vpninfo, form, opt);

	case OC_TOKEN_MODE_HOTP:
		return can_gen_hotp_code(vpninfo, form, opt);
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return can_gen_yubikey_code(vpninfo, form, opt);
#endif
	default:
		return -EINVAL;
	}
}
