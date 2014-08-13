/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
 * Copyright © 2012-2014 Kevin Cernekee <cernekee@gmail.com>
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

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <stoken.h>

#include "openconnect-internal.h"

#ifndef STOKEN_CHECK_VER
#define STOKEN_CHECK_VER(x,y) 0
#endif

int set_libstoken_mode(struct openconnect_info *vpninfo, const char *token_str)
{
	int ret;

	if (!vpninfo->stoken_ctx) {
		vpninfo->stoken_ctx = stoken_new();
		if (!vpninfo->stoken_ctx)
			return -EIO;
	}

	ret = token_str ?
	      stoken_import_string(vpninfo->stoken_ctx, token_str) :
	      stoken_import_rcfile(vpninfo->stoken_ctx, NULL);
	if (ret)
		return ret;

	vpninfo->token_mode = OC_TOKEN_MODE_STOKEN;
	return 0;
}


/*
 * A SecurID token can be encrypted with a device ID, a password, both,
 * or neither.  Gather the required information, decrypt the token, and
 * check the hash to make sure it is sane.
 *
 * Return value:
 *  < 0, on error
 *  = 0, on success
 *  = 1, if the user cancelled the form submission
 *  = 2, if the user left the entire form blank and clicked OK
 */
static int decrypt_stoken(struct openconnect_info *vpninfo)
{
	struct oc_auth_form form;
	struct oc_form_opt opts[2], *opt = opts;
	char **devid = NULL, **pass = NULL;
	int ret = 0;

	memset(&form, 0, sizeof(form));
	memset(&opts, 0, sizeof(opts));

	form.opts = opts;
	form.message = _("Enter credentials to unlock software token.");

	if (stoken_devid_required(vpninfo->stoken_ctx)) {
		opt->type = OC_FORM_OPT_TEXT;
		opt->name = (char *)"devid";
		opt->label = _("Device ID:");
		devid = &opt->value;
		opt++;
	}
	if (stoken_pass_required(vpninfo->stoken_ctx)) {
		opt->type = OC_FORM_OPT_PASSWORD;
		opt->name = (char *)"password";
		opt->label = _("Password:");
		pass = &opt->value;
		opt++;
	}

	opts[0].next = opts[1].type ? &opts[1] : NULL;

	while (1) {
		nuke_opt_values(opts);

		if (!opts[0].type) {
			/* don't bug the user if there's nothing to enter */
			ret = 0;
		} else {
			int some_empty = 0, all_empty = 1;

			/* < 0 for error; 1 if cancelled */
			ret = process_auth_form(vpninfo, &form);
			if (ret)
				break;

			for (opt = opts; opt; opt = opt->next) {
				if (!opt->value || !strlen(opt->value))
					some_empty = 1;
				else
					all_empty = 0;
			}
			if (all_empty) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("User bypassed soft token.\n"));
				ret = 2;
				break;
			}
			if (some_empty) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("All fields are required; try again.\n"));
				continue;
			}
		}

		ret = stoken_decrypt_seed(vpninfo->stoken_ctx,
					  pass ? *pass : NULL,
					  devid ? *devid : NULL);
		if (ret == -EIO || (ret && !devid && !pass)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("General failure in libstoken.\n"));
			break;
		} else if (ret != 0) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Incorrect device ID or password; try again.\n"));
			continue;
		}

		vpn_progress(vpninfo, PRG_DEBUG, _("Soft token init was successful.\n"));
		ret = 0;
		break;
	}

	nuke_opt_values(opts);
	return ret;
}

static void get_stoken_details(struct openconnect_info *vpninfo)
{
#if STOKEN_CHECK_VER(1,3)
	struct stoken_info *info = stoken_get_info(vpninfo->stoken_ctx);

	if (info) {
		vpninfo->stoken_concat_pin = !info->uses_pin;
		vpninfo->stoken_interval = info->interval;
		return;
	}
#endif
	vpninfo->stoken_concat_pin = 0;
	vpninfo->stoken_interval = 60;
}

/*
 * Return value:
 *  < 0, on error
 *  = 0, on success
 *  = 1, if the user cancelled the form submission
 */
static int request_stoken_pin(struct openconnect_info *vpninfo)
{
	struct oc_auth_form form;
	struct oc_form_opt opts[1], *opt = opts;
	int ret = 0;

	if (!vpninfo->stoken_concat_pin && !stoken_pin_required(vpninfo->stoken_ctx))
		return 0;

	memset(&form, 0, sizeof(form));
	memset(&opts, 0, sizeof(opts));

	form.opts = opts;
	form.message = _("Enter software token PIN.");

	opt->type = OC_FORM_OPT_PASSWORD;
	opt->name = (char *)"password";
	opt->label = _("PIN:");
	opt->flags = OC_FORM_OPT_NUMERIC;

	while (1) {
		char *pin;

		nuke_opt_values(opts);

		/* < 0 for error; 1 if cancelled */
		ret = process_auth_form(vpninfo, &form);
		if (ret)
			break;

		pin = opt->value;
		if (!pin || !strlen(pin)) {
			/* in some cases there really is no PIN */
			if (vpninfo->stoken_concat_pin)
				return 0;

			vpn_progress(vpninfo, PRG_INFO,
				     _("All fields are required; try again.\n"));
			continue;
		}

		if (!vpninfo->stoken_concat_pin &&
		    stoken_check_pin(vpninfo->stoken_ctx, pin) != 0) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Invalid PIN format; try again.\n"));
			continue;
		}

		free(vpninfo->stoken_pin);
		vpninfo->stoken_pin = strdup(pin);
		if (!vpninfo->stoken_pin)
			ret = -ENOMEM;
		break;
	}

	nuke_opt_values(opts);
	return ret;
}

/*
 * If the user clicks OK on the devid/password prompt without entering
 * any data, we will continue connecting but bypass soft token generation
 * for the duration of this "obtain_cookie" session.  (They might not even
 * have the credentials that we're prompting for.)
 *
 * If the user clicks Cancel, we will abort the connection.
 *
 * Return value:
 *  < 0, on error
 *  = 0, on success (or if the user bypassed soft token init)
 *  = 1, if the user cancelled the form submission
 */
int prepare_stoken(struct openconnect_info *vpninfo)
{
	int ret;

	vpninfo->token_tries = 0;
	vpninfo->token_bypassed = 0;

	ret = decrypt_stoken(vpninfo);
	if (ret == 2) {
		vpninfo->token_bypassed = 1;
		return 0;
	} else if (ret != 0)
		return ret;

	get_stoken_details(vpninfo);
	return request_stoken_pin(vpninfo);
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
int can_gen_stoken_code(struct openconnect_info *vpninfo,
			struct oc_auth_form *form,
			struct oc_form_opt *opt)
{
	if ((strcmp(opt->name, "password") && strcmp(opt->name, "answer")) ||
	    vpninfo->token_bypassed)
		return -EINVAL;
	if (vpninfo->token_tries == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate INITIAL tokencode\n"));
		vpninfo->token_time = 0;
	} else if (vpninfo->token_tries == 1 && form->message &&
		   strcasestr(form->message, "next tokencode")) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("OK to generate NEXT tokencode\n"));
		vpninfo->token_time += vpninfo->stoken_interval;
	} else {
		/* limit the number of retries, to avoid account lockouts */
		vpn_progress(vpninfo, PRG_INFO,
			     _("Server is rejecting the soft token; switching to manual entry\n"));
		return -ENOENT;
	}
	return 0;
}

int do_gen_stoken_code(struct openconnect_info *vpninfo,
		       struct oc_auth_form *form,
		       struct oc_form_opt *opt)
{
	char tokencode[STOKEN_MAX_TOKENCODE + 1];

	if (!vpninfo->token_time)
		vpninfo->token_time = time(NULL);
	vpn_progress(vpninfo, PRG_INFO, _("Generating RSA token code\n"));

	/* This doesn't normally fail */
	if (stoken_compute_tokencode(vpninfo->stoken_ctx, vpninfo->token_time,
				     vpninfo->stoken_pin, tokencode) < 0) {
		vpn_progress(vpninfo, PRG_ERR, _("General failure in libstoken.\n"));
		return -EIO;
	}

	vpninfo->token_tries++;

	if (asprintf(&opt->value, "%s%s",
	    (vpninfo->stoken_concat_pin && vpninfo->stoken_pin) ? vpninfo->stoken_pin : "",
	    tokencode) < 0)
		return -ENOMEM;
	return 0;
}

