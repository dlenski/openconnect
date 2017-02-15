/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Author: Dan Lenski <dlenski@gmail.com>
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

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "openconnect-internal.h"

void gpst_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	http_common_headers(vpninfo, buf);
}

/* our "auth form" always has a username and password or challenge */
static struct oc_auth_form *auth_form(struct openconnect_info *vpninfo, char *prompt, char *user, char *inputStr)
{
	static struct oc_auth_form *form;
	static struct oc_form_opt *opt, *opt2;

	form = calloc(1, sizeof(*form));

	if (!form)
		return NULL;
	form->message = prompt ? : strdup(_("Please enter your username and password."));
	form->auth_id = inputStr;

	opt = form->opts = calloc(1, sizeof(*opt));
	if (!opt)
		return NULL;
	opt->name=strdup("username");
	opt->label=strdup(_("Username: "));
	opt->type = user ? OC_FORM_OPT_HIDDEN : OC_FORM_OPT_TEXT;
	opt->_value = user;

	opt2 = opt->next = calloc(1, sizeof(*opt));
	if (!opt2)
		return NULL;
	opt2->name = strdup("password");
	opt2->label = inputStr ? strdup(_("Challenge: ")) : strdup(_("Password: "));
	opt2->type = vpninfo->token_mode!=OC_TOKEN_MODE_NONE ? OC_FORM_OPT_TOKEN : OC_FORM_OPT_PASSWORD;

	form->opts = opt;
	return form;
}

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
struct gp_login_arg { const char *opt; int save:1; int show:1; int warn_missing:1; int err_missing:1; const char *check; };
static const struct gp_login_arg gp_login_args[] = {
    [1] = { .opt="authcookie", .save=1, .err_missing=1 },
    [3] = { .opt="portal", .save=1, .warn_missing=1 },
    [4] = { .opt="user", .save=1, .err_missing=1 },
    [5] = { .opt="authentication source", .show=1 },
    [7] = { .opt="domain", .save=1, .warn_missing=1 },
    [12] = { .opt="connection-type", .err_missing=1, .check="tunnel" },
    [14] = { .opt="clientVer", .err_missing=1, .check="4100" },
    [15] = { .opt="preferred-ip", .save=1 },
};
const int gp_login_nargs = (sizeof(gp_login_args)/sizeof(*gp_login_args));

static int parse_login_xml(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	struct oc_text_buf *cookie = buf_alloc();
	const char *value = NULL;
	const struct gp_login_arg *arg;

	if (!xmlnode_is_named(xml_node, "jnlp"))
		goto err_out;

	xml_node = xml_node->children;
	if (!xmlnode_is_named(xml_node, "application-desc"))
		goto err_out;

	xml_node = xml_node->children;
	for (arg=gp_login_args; xml_node && arg<gp_login_args+gp_login_nargs; xml_node=xml_node->next, arg++) {
		if (!xmlnode_is_named(xml_node, "argument"))
			goto err_out;

		if (!arg->opt)
			continue;

		value = (const char *)xmlNodeGetContent(xml_node);
		if (value && (!strlen(value) || !strcmp(value, "(null)"))) {
			free((void *)value);
			value = NULL;
		}

		if (arg->check && (value==NULL || strcmp(value, arg->check))) {
			vpn_progress(vpninfo, arg->err_missing ? PRG_ERR : PRG_DEBUG,
						 _("GlobalProtect login returned %s=%s (expected %s)\n"), arg->opt, value, arg->check);
			if (arg->err_missing) goto err_out;
		} else if ((arg->err_missing || arg->warn_missing) && value==NULL) {
			vpn_progress(vpninfo, arg->err_missing ? PRG_ERR : PRG_DEBUG,
						 _("GlobalProtect login returned empty %s\n"), arg->opt);
			if (arg->err_missing) goto err_out;
		} else if (value && arg->show) {
			vpn_progress(vpninfo, PRG_INFO,
						 _("GlobalProtect login returned %s=%s\n"), arg->opt, value);
		}

		if (value && arg->save)
			append_opt(cookie, arg->opt, value);
		free((void *)value);
	}

	vpninfo->cookie = strdup(cookie->data);
	buf_free(cookie);
	return 0;

err_out:
	free((void *)value);
	buf_free(cookie);
	return -EINVAL;
}

int gpst_obtain_cookie(struct openconnect_info *vpninfo)
{
	int result;

	struct oc_form_opt *opt;
	struct oc_auth_form *form;
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL, *orig_path, *orig_ua;
	char *prompt=NULL, *inputStr=NULL;

#ifdef HAVE_LIBSTOKEN
	/* Step 1: Unlock software token (if applicable) */
	if (vpninfo->token_mode == OC_TOKEN_MODE_STOKEN) {
		result = prepare_stoken(vpninfo);
		if (result)
			goto out;
	}
#endif

	/* Ask the user to fill in the auth form; repeat as necessary */
	do {

		form = auth_form(vpninfo, prompt, NULL, inputStr);
		if (!form)
			return -ENOMEM;

		/* process auth form (username, password or challenge, and hidden inputStr) */
		result = process_auth_form(vpninfo, form);
		if (result)
			goto out;

		/* generate token code if specified */
		result = do_gen_tokencode(vpninfo, form);
		if (result) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
			vpninfo->token_bypassed = 1;
			goto out;
		}

		/* submit login request */
		buf_truncate(request_body);
		buf_append(request_body, "jnlpReady=jnlpReady&ok=Login&direct=yes&clientVer=4100&prot=https:");
		append_opt(request_body, "server", vpninfo->hostname);
		append_opt(request_body, "computer", vpninfo->localname);
		append_opt(request_body, "inputStr", form->auth_id);
		for (opt=form->opts; opt; opt=opt->next) {
			if (!strcmp(opt->name, "username"))
				append_opt(request_body, "user", opt->_value);
			else if (!strcmp(opt->name, "password"))
				append_opt(request_body, "passwd", opt->_value);
		}
		free_auth_form(form);

		orig_path = vpninfo->urlpath;
		orig_ua = vpninfo->useragent;
		vpninfo->useragent = (char *)"PAN GlobalProtect";
		vpninfo->urlpath = strdup("ssl-vpn/login.esp");
		result = do_https_request(vpninfo, method, request_body_type, request_body,
					  &xml_buf, 0);
		free(vpninfo->urlpath);
		vpninfo->urlpath = orig_path;
		vpninfo->useragent = orig_ua;

		/* Result could be either a JavaScript challenge or XML */
		result = gpst_xml_or_error(vpninfo, result, xml_buf, parse_login_xml, &prompt, &inputStr);
	}
	/* repeat on invalid username or password, or challenge */
	while (result == -512 || result == 2);

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

int gpst_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path, *orig_ua;
	int result;
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL;

	/* submit logout request */
	append_opt(request_body, "computer", vpninfo->localname);
	buf_append(request_body, "&%s", vpninfo->cookie);

	/* We need to close and reopen the HTTPS connection (to kill
	 * the tunnel session) and submit a new HTTPS request to
	 * logout.
	 */
	orig_path = vpninfo->urlpath;
	orig_ua = vpninfo->useragent;
	vpninfo->useragent = (char *)"PAN GlobalProtect";
	vpninfo->urlpath = strdup("ssl-vpn/logout.esp");
	openconnect_close_https(vpninfo, 0);
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;
	vpninfo->useragent = orig_ua;

	/* logout.esp returns HTTP status 200 and <response status="success"> when
	 * successful, and all manner of malformed junk when unsuccessful.
	 */
	result = gpst_xml_or_error(vpninfo, result, xml_buf, NULL, NULL, NULL);
	if (result < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful\n"));

	buf_free(request_body);
	free(xml_buf);
	return result;
}
