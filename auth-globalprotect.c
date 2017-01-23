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

/* our "auth form" is just a static combination of username and password */
static struct oc_auth_form *gp_auth_form(struct openconnect_info *vpninfo)
{
	static struct oc_form_opt password = {.type=OC_FORM_OPT_PASSWORD, .name=(char *)"password", .label=(char *)"Password: "};
	static struct oc_form_opt username = {.next=&password, .type=OC_FORM_OPT_TEXT, .name=(char *)"username", .label=(char *)"Username: "};
	static struct oc_auth_form form = {.opts=&username, .message=(char *)"Please enter your username and password." };

	if (vpninfo->token_mode!=OC_TOKEN_MODE_NONE)
		password.type = OC_FORM_OPT_TOKEN;

	return &form;
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

static int parse_prelogin_response(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	int result = 0;
	const char *status = NULL, *msg = NULL;

	/* is it <prelogin-response><status>Error<status><msg>GlobalProtect [portal|gateway] does not exist</msg></response> ? */
	if (!xmlnode_is_named(xml_node, "prelogin-response")) {
		result = -EINVAL;
	} else {
		for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
			if (xmlnode_is_named(xml_node, "status"))
				status = (const char *)xmlNodeGetContent(xml_node);
			else if (xmlnode_is_named(xml_node, "msg"))
				msg = (const char *)xmlNodeGetContent(xml_node);
		}

		if (!status || strcasecmp(status, "Success")) {
			vpn_progress(vpninfo, PRG_DEBUG,
						 _("Prelogin response error: %s\n"), msg);
			if (msg && !strcmp(msg, "GlobalProtect portal does not exist"))
				result = -EEXIST;
			else if (msg && !strcmp(msg, "GlobalProtect gateway does not exist"))
				result = -EEXIST;
			else
				result = -EINVAL;
		} else {
			vpn_progress(vpninfo, PRG_INFO,
						 _("Prelogin response info: %s\n"), msg);
		}
	}

	free((void *)status);
	free((void *)msg);
	return result;
}

static int gpst_portal_login(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR, _("Support for GlobalProtect portal not yet implemented.\n"));
	return -EINVAL;
}

static int gpst_gateway_login(struct openconnect_info *vpninfo)
{
	int result;

	struct oc_form_opt *opt;
	struct oc_auth_form *form = gp_auth_form(vpninfo);
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL, *orig_path, *orig_ua;

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
		free(xml_buf);
		buf_truncate(request_body);

		/* process static auth form (username and password) */
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
		buf_append(request_body, "jnlpReady=jnlpReady&ok=Login&direct=yes&clientVer=4100&prot=https:");
		append_opt(request_body, "server", vpninfo->hostname);
		append_opt(request_body, "computer", vpninfo->localname);
		for (opt=form->opts; opt; opt=opt->next) {
			if (!strcmp(opt->name, "username"))
				append_opt(request_body, "user", opt->_value);
			else if (!strcmp(opt->name, "password"))
				append_opt(request_body, "passwd", opt->_value);
		}

		orig_path = vpninfo->urlpath;
		orig_ua = vpninfo->useragent;
		vpninfo->useragent = (char *)"PAN GlobalProtect";
		vpninfo->urlpath = strdup("ssl-vpn/login.esp");
		result = do_https_request(vpninfo, method, request_body_type, request_body,
					  &xml_buf, 0);
		free(vpninfo->urlpath);
		vpninfo->urlpath = orig_path;
		vpninfo->useragent = orig_ua;

		result = gpst_xml_or_error(vpninfo, result, xml_buf, parse_login_xml);

	}
	/* repeat on invalid username or password */
	while (result == -512);

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

int gpst_obtain_cookie(struct openconnect_info *vpninfo)
{
	char *xml_buf=NULL, *orig_path, *orig_ua;
	int result;

	if (vpninfo->urlpath && !strncmp(vpninfo->urlpath, "global-protect", 14)) {
		/* assume the server is a portal */
		return gpst_portal_login(vpninfo);
	} else if (vpninfo->urlpath && !strncmp(vpninfo->urlpath, "ssl-vpn", 7)) {
		/* assume the server is a gateway */
		return gpst_gateway_login(vpninfo);
	} else {
		/* first try handling it as a gateway, then a portal */
		for (int ii=0; ii<2; ii++) {
			orig_path = vpninfo->urlpath;
			orig_ua = vpninfo->useragent;
			vpninfo->useragent = (char *)"PAN GlobalProtect";
			vpninfo->urlpath = strdup(ii==0 ? "ssl-vpn/prelogin.esp" : "global-protect/prelogin.esp");
			result = do_https_request(vpninfo, "GET", NULL, NULL, &xml_buf, 0);
			free(vpninfo->urlpath);
			vpninfo->urlpath = orig_path;
			vpninfo->useragent = orig_ua;

			result = gpst_xml_or_error(vpninfo, result, xml_buf, parse_prelogin_response);
			if (result==0) {
				switch (ii) {
				case 0:
					vpn_progress(vpninfo, PRG_DEBUG, _("Logging in to GlobalProtect gateway\n"));
					return gpst_gateway_login(vpninfo);
				case 1:
					vpn_progress(vpninfo, PRG_DEBUG, _("Logging in to GlobalProtect portal\n"));
					return gpst_portal_login(vpninfo);
				}
			}
		}
		vpn_progress(vpninfo, PRG_ERR, _("Server is not a GlobalProtect portal or gateway.\n"));
		return -EINVAL;
	}
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
	result = gpst_xml_or_error(vpninfo, result, xml_buf, NULL);
	if (result < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful\n"));

	buf_free(request_body);
	free(xml_buf);
	return result;
}
