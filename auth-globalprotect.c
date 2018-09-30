/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2016-2018 Daniel Lenski
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

struct login_context {
	char *username;				/* Username that has already succeeded in some form */
	char *alt_secret;			/* Alternative secret (DO NOT FREE) */
	struct oc_auth_form *form;
};

void gpst_common_headers(struct openconnect_info *vpninfo,
			 struct oc_text_buf *buf)
{
	char *orig_ua = vpninfo->useragent;
	vpninfo->useragent = (char *)"PAN GlobalProtect";

	http_common_headers(vpninfo, buf);

	vpninfo->useragent = orig_ua;
}

/* Parse pre-login response ({POST,GET} /{global-protect,ssl-vpn}/pre-login.esp)
 *
 * Extracts the relevant arguments from the XML (username-label, password-label)
 * and uses them to build an auth form, which always has two visible fields:
 *
 *   1) username
 *   2) one secret value:
 *       - normal account password
 *       - "challenge" (2FA) password, along with form name in auth_id
 *       - cookie from external authentication flow ("alternative secret" INSTEAD OF password)
 *
 */
static int parse_prelogin_xml(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	struct login_context *ctx = cb_data;
	struct oc_auth_form *form = ctx->form;
	struct oc_form_opt *opt, *opt2;
	char *prompt = NULL, *username_label = NULL, *password_label = NULL;
	char *saml_method = NULL, *saml_path = NULL;
	int result = 0;

	if (!xmlnode_is_named(xml_node, "prelogin-response"))
		goto out;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		char *s = NULL;
		if (!xmlnode_get_val(xml_node, "saml-request", &s)) {
			int len;
			saml_path = openconnect_base64_decode(&len, s);
			if (len < 0) {
				vpn_progress(vpninfo, PRG_ERR, "Could not decode SAML request as base64: %s\n", s);
				free(s);
				result = -EINVAL;
				goto out;
			}
			free(s);
			saml_path = realloc(saml_path, len+1);
			saml_path[len] = '\0';
		} else {
			xmlnode_get_val(xml_node, "saml-auth-method", &saml_method);
			xmlnode_get_val(xml_node, "authentication-message", &prompt);
			xmlnode_get_val(xml_node, "username-label", &username_label);
			xmlnode_get_val(xml_node, "password-label", &password_label);
			/* XX: should we save the certificate username from <ccusername/> ? */
		}
	}

	/* XX: Alt-secret form field must be specified for SAML, because we can't autodetect it */
	if ((saml_method || saml_path) && !ctx->alt_secret) {
		vpn_progress(vpninfo, PRG_ERR, "SAML authentication via %s to %s is required.\n"
					 "Must specify destination form field by appending :field_name to login URL.\n",
					 saml_method, saml_path);
		result = -EINVAL;
	}

	/* Replace old form */
	free_auth_form(ctx->form);
	form = ctx->form = calloc(1, sizeof(*form));
	if (!form) {
	nomem:
		free_auth_form(form);
		result = -ENOMEM;
		goto out;
	}
	if (saml_path && asprintf(&form->banner, _("SAML login is required via %s to this URL:\n\t%s"), saml_method, saml_path) == 0)
		goto nomem;
	form->message = prompt ? : strdup(_("Please enter your username and password"));
	prompt = NULL;
	form->auth_id = strdup("_login");

	/* First field (username) */
	opt = form->opts = calloc(1, sizeof(*opt));
	if (!opt)
		goto nomem;
	opt->name = strdup("user");
	if (asprintf(&opt->label, "%s: ", username_label ? : _("Username")) == 0)
		goto nomem;
	if (!ctx->username)
		opt->type = OC_FORM_OPT_TEXT;
	else {
		opt->type = OC_FORM_OPT_HIDDEN;
		opt->_value = ctx->username;
		ctx->username = NULL;
	}

	/* Second field (secret) */
	opt2 = opt->next = calloc(1, sizeof(*opt));
	if (!opt2)
		goto nomem;
	opt2->name = strdup(ctx->alt_secret ? : "passwd");
	if (asprintf(&opt2->label, "%s: ", ctx->alt_secret ? : password_label ? : _("Password")) == 0)
		goto nomem;

	/* XX: Some VPNs use a password in the first form, followed by a
	 * a token in the second ("challenge") form. Others use only a
	 * token. How can we distinguish these? */
	if (!can_gen_tokencode(vpninfo, form, opt2))
		opt2->type = OC_FORM_OPT_TOKEN;
	else
		opt2->type = OC_FORM_OPT_PASSWORD;

	vpn_progress(vpninfo, PRG_TRACE, "%s%s: \"%s\" %s(%s)=%s, \"%s\" %s(%s)\n",
				 form->auth_id[0] == '_' ? "Login form" : "Challenge form ",
				 form->auth_id[0] != '_' ? form->auth_id : "",
				 opt->label, opt->name, opt->type == OC_FORM_OPT_TEXT ? "TEXT" : "HIDDEN", opt->_value,
				 opt2->label, opt2->name, opt2->type == OC_FORM_OPT_PASSWORD ? "PASSWORD" : "TOKEN");

out:
	free(prompt);
	free(username_label);
	free(password_label);
	free(saml_method);
	free(saml_path);
	return result;
}

/* Callback function to create a new form from a challenge
 *
 */
static int challenge_cb(struct openconnect_info *vpninfo, char *prompt, char *inputStr, void *cb_data)
{
	struct login_context *ctx = cb_data;
	struct oc_auth_form *form = ctx->form;
	struct oc_form_opt *opt = form->opts, *opt2 = form->opts->next;

	/* Replace prompt, inputStr, and password prompt;
	 * clear password field, and make user field hidden.
	 */
	free(form->message);
	free(form->auth_id);
	free(opt2->label);
	free(opt2->_value);
	opt2->_value = NULL;
	opt->type = OC_FORM_OPT_HIDDEN;

	if (    !(form->message = strdup(prompt))
		 || !(form->auth_id = strdup(inputStr))
		 || !(opt2->label = strdup(_("Challenge: "))) )
		return -ENOMEM;

	vpn_progress(vpninfo, PRG_TRACE, "%s%s: \"%s\" %s(%s)=%s, \"%s\" %s(%s)\n",
				 form->auth_id[0] == '_' ? "Login form" : "Challenge form ",
				 form->auth_id[0] != '_' ? form->auth_id : "",
				 opt->label, opt->name, opt->type == OC_FORM_OPT_TEXT ? "TEXT" : "HIDDEN", opt->_value,
				 opt2->label, opt2->name, opt2->type == OC_FORM_OPT_PASSWORD ? "PASSWORD" : "TOKEN");

	return -EAGAIN;
}

/* Parse gateway login response (POST /ssl-vpn/login.esp)
 *
 * Extracts the relevant arguments from the XML (<jnlp><application-desc><argument>...</argument></application-desc></jnlp>)
 * and uses them to build a query string fragment which is usable for subsequent requests.
 * This query string fragement is saved as vpninfo->cookie.
 *
 */
struct gp_login_arg {
	const char *opt;
	unsigned save:1;
	unsigned show:1;
	unsigned warn_missing:1;
	unsigned err_missing:1;
	const char *check;
};
static const struct gp_login_arg gp_login_args[] = {
	{ .opt="unknown-arg0", .show=1 },
	{ .opt="authcookie", .save=1, .err_missing=1 },
	{ .opt="persistent-cookie", .warn_missing=1 },  /* 40 hex digits; persists across sessions */
	{ .opt="portal", .save=1, .warn_missing=1 },
	{ .opt="user", .save=1, .err_missing=1 },
	{ .opt="authentication-source", .show=1 },      /* LDAP-auth, AUTH-RADIUS_RSA_OTP, etc. */
	{ .opt="configuration", .warn_missing=1 },      /* usually vsys1 (sometimes vsys2, etc.) */
	{ .opt="domain", .save=1, .warn_missing=1 },
	{ .opt="unknown-arg8", .show=1 },
	{ .opt="unknown-arg9", .show=1 },
	{ .opt="unknown-arg10", .show=1 },
	{ .opt="unknown-arg11", .show=1 },
	{ .opt="connection-type", .err_missing=1, .check="tunnel" },
	{ .opt="password-expiration-days", .show=1 },   /* days until password expires, if not -1 */
	{ .opt="clientVer", .err_missing=1, .check="4100" },
	{ .opt="preferred-ip", .save=1 },
	{ .opt=NULL },
};

static int parse_login_xml(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	struct oc_text_buf *cookie = buf_alloc();
	char *value = NULL;
	const struct gp_login_arg *arg;

	if (!xmlnode_is_named(xml_node, "jnlp"))
		goto err_out;

	xml_node = xml_node->children;
	while (xml_node && xml_node->type != XML_ELEMENT_NODE)
		xml_node = xml_node->next;

	if (!xmlnode_is_named(xml_node, "application-desc"))
		goto err_out;

	xml_node = xml_node->children;
	for (arg = gp_login_args; arg->opt; arg++) {
		while (xml_node && xml_node->type != XML_ELEMENT_NODE)
			xml_node = xml_node->next;

		if (xml_node && !xmlnode_get_val(xml_node, "argument", &value)) {
			if (value && (!value[0] || !strcmp(value, "(null)") || !strcmp(value, "-1"))) {
				free(value);
				value = NULL;
			}
			xml_node = xml_node->next;
		} else if (xml_node)
			goto err_out;

		if (arg->check && (!value || strcmp(value, arg->check))) {
			vpn_progress(vpninfo, arg->err_missing ? PRG_ERR : PRG_DEBUG,
				     _("GlobalProtect login returned %s=%s (expected %s)\n"),
				     arg->opt, value, arg->check);
			if (arg->err_missing)
				goto err_out;
		} else if ((arg->err_missing || arg->warn_missing) && !value) {
			vpn_progress(vpninfo, arg->err_missing ? PRG_ERR : PRG_DEBUG,
				     _("GlobalProtect login returned empty or missing %s\n"),
				     arg->opt);
			if (arg->err_missing)
				goto err_out;
		} else if (value && arg->show) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("GlobalProtect login returned %s=%s\n"),
				     arg->opt, value);
		}

		if (value && arg->save)
			append_opt(cookie, arg->opt, value);
		free(value);
		value = NULL;
	}
	append_opt(cookie, "computer", vpninfo->localname);

	if (!buf_error(cookie)) {
		vpninfo->cookie = cookie->data;
		cookie->data = NULL;
	}
	return buf_free(cookie);

err_out:
	free(value);
	buf_free(cookie);
	return -EINVAL;
}

/* Parse portal login/config response (POST /ssl-vpn/getconfig.esp)
 *
 * Extracts the list of gateways from the XML, writes them to the XML config,
 * presents the user with a form to choose the gateway, and redirects
 * to that gateway.
 *
 */
static int parse_portal_xml(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	struct oc_auth_form *form;
	xmlNode *x = NULL;
	struct oc_form_opt_select *opt;
	struct oc_text_buf *buf = NULL;
	int max_choices = 0, result;
	char *portal = NULL;

	form = calloc(1, sizeof(*form));
	if (!form)
		return -ENOMEM;

	form->message = strdup(_("Please select GlobalProtect gateway."));
	form->auth_id = strdup("_portal");

	opt = form->authgroup_opt = calloc(1, sizeof(*opt));
	if (!opt) {
		result = -ENOMEM;
		goto out;
	}
	opt->form.type = OC_FORM_OPT_SELECT;
	opt->form.name = strdup("gateway");
	opt->form.label = strdup(_("GATEWAY:"));
	form->opts = (void *)opt;

	/*
	 * The portal contains a ton of stuff, but basically none of it is
	 * useful to a VPN client that wishes to give control to the client
	 * user, as opposed to the VPN administrator.  The exception is the
	 * list of gateways in policy/gateways/external/list
	 */
	if (xmlnode_is_named(xml_node, "policy")) {
		for (x = xml_node->children, xml_node = NULL; x; x = x->next) {
			if (xmlnode_is_named(x, "gateways"))
				xml_node = x;
			else
				xmlnode_get_val(x, "portal-name", &portal);
		}
	}

	if (xml_node) {
		for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next)
			if (xmlnode_is_named(xml_node, "external"))
				for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next)
					if (xmlnode_is_named(xml_node, "list"))
						goto gateways;
	}
	result = -EINVAL;
	goto out;

gateways:
	if (vpninfo->write_new_config) {
		buf = buf_alloc();
		buf_append(buf, "<GPPortal>\n  <ServerList>\n");
		if (portal) {
			buf_append(buf, "      <HostEntry><HostName>");
			buf_append_xmlescaped(buf, portal);
			buf_append(buf, "</HostName><HostAddress>%s", vpninfo->hostname);
			if (vpninfo->port!=443)
				buf_append(buf, ":%d", vpninfo->port);
			buf_append(buf, "/global-protect</HostAddress></HostEntry>\n");
		}
	}

	/* first, count the number of gateways */
	for (x = xml_node->children; x; x = x->next)
		if (xmlnode_is_named(x, "entry"))
			max_choices++;

	opt->choices = calloc(max_choices, sizeof(opt->choices[0]));
	if (!opt->choices) {
		result = -ENOMEM;
		goto out;
	}

	/* each entry looks like <entry name="host[:443]"><description>Label</description></entry> */
	vpn_progress(vpninfo, PRG_INFO, _("%d gateway servers available:\n"), max_choices);
	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xmlnode_is_named(xml_node, "entry")) {
			struct oc_choice *choice = calloc(1, sizeof(*choice));
			if (!choice) {
				result = -ENOMEM;
				goto out;
			}

			xmlnode_get_prop(xml_node, "name", &choice->name);
			for (x = xml_node->children; x; x=x->next)
				if (!xmlnode_get_val(x, "description", &choice->label)) {
					if (vpninfo->write_new_config) {
						buf_append(buf, "      <HostEntry><HostName>");
						buf_append_xmlescaped(buf, choice->label);
						buf_append(buf, "</HostName><HostAddress>%s/ssl-vpn</HostAddress></HostEntry>\n",
								   choice->name);
					}
				}

			opt->choices[opt->nr_choices++] = choice;
			vpn_progress(vpninfo, PRG_INFO, _("  %s (%s)\n"),
				     choice->label, choice->name);
		}
	}

	if (vpninfo->write_new_config) {
		buf_append(buf, "  </ServerList>\n</GPPortal>\n");
		if ((result = buf_error(buf)))
			goto out;
		if ((result = vpninfo->write_new_config(vpninfo->cbdata, buf->data, buf->pos)))
			goto out;
	}

	/* process auth form to select gateway */
	result = process_auth_form(vpninfo, form);
	if (result != OC_FORM_RESULT_NEWGROUP)
		goto out;

	/* redirect to the gateway (no-op if it's the same host) */
	free(vpninfo->redirect_url);
	if (asprintf(&vpninfo->redirect_url, "https://%s", vpninfo->authgroup) == 0) {
		result = -ENOMEM;
		goto out;
	}
	result = handle_redirect(vpninfo);

out:
	buf_free(buf);
	free(portal);
	free_auth_form(form);
	return result;
}

/* Main login entry point
 *
 * portal: 0 for gateway login, 1 for portal login
 * alt_secret: "alternate secret" field (see new_auth_form)
 *
 */
static int gpst_login(struct openconnect_info *vpninfo, int portal, struct login_context *ctx)
{
	int result, blind_retry = 0;
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	char *xml_buf = NULL, *orig_path;

#ifdef HAVE_LIBSTOKEN
	/* Step 1: Unlock software token (if applicable) */
	if (vpninfo->token_mode == OC_TOKEN_MODE_STOKEN) {
		result = prepare_stoken(vpninfo);
		if (result)
			goto out;
	}
#endif

	/* Ask the user to fill in the auth form; repeat as necessary */
	for (;;) {
		const char *clientos;
		if (!strcmp(vpninfo->platname, "mac-intel") || !strcmp(vpninfo->platname, "apple-ios"))
			clientos = "Mac";
		else if (!strcmp(vpninfo->platname, "linux-64") || !strcmp(vpninfo->platname, "android"))
			clientos = "Linux";
		else
			clientos = "Windows";

		/* submit prelogin request to get form */
		orig_path = vpninfo->urlpath;
		asprintf(&vpninfo->urlpath, "%s/prelogin.esp?tmp=tmp&clientVer=4100&clientos=%s",
				 portal ? "global-protect" : "ssl-vpn", clientos);
		result = do_https_request(vpninfo, "POST", NULL, NULL, &xml_buf, 0);
		free(vpninfo->urlpath);
		vpninfo->urlpath = orig_path;

		if (result >= 0)
			result = gpst_xml_or_error(vpninfo, xml_buf, parse_prelogin_xml, NULL, ctx);
		if (result)
			goto out;

	got_form:
		/* process auth form */
		result = process_auth_form(vpninfo, ctx->form);
		if (result)
			goto out;

	replay_form:
		/* generate token code if specified */
		result = do_gen_tokencode(vpninfo, ctx->form);
		if (result) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
			vpninfo->token_bypassed = 1;
			goto out;
		}

		/* submit gateway login (ssl-vpn/login.esp) or portal config (global-protect/getconfig.esp) request */
		buf_truncate(request_body);
		buf_append(request_body, "jnlpReady=jnlpReady&ok=Login&direct=yes&clientVer=4100&prot=https:");
		if (!strcmp(vpninfo->platname, "mac-intel") || !strcmp(vpninfo->platname, "apple-ios"))
			append_opt(request_body, "clientos", "Mac");
		else if (!strcmp(vpninfo->platname, "linux-64") || !strcmp(vpninfo->platname, "android"))
			append_opt(request_body, "clientos", "Linux");
		else
			append_opt(request_body, "clientos", "Windows");
		append_opt(request_body, "os-version", vpninfo->platname);
		append_opt(request_body, "server", vpninfo->hostname);
		append_opt(request_body, "computer", vpninfo->localname);
		if (vpninfo->ip_info.addr)
			append_opt(request_body, "preferred-ip", vpninfo->ip_info.addr);
		if (ctx->form->auth_id && ctx->form->auth_id[0]!='_')
			append_opt(request_body, "inputStr", ctx->form->auth_id);
		append_form_opts(vpninfo, ctx->form, request_body);
		if ((result = buf_error(request_body)))
			goto out;

		orig_path = vpninfo->urlpath;
		vpninfo->urlpath = strdup(portal ? "global-protect/getconfig.esp" : "ssl-vpn/login.esp");
		result = do_https_request(vpninfo, "POST", request_body_type, request_body,
					  &xml_buf, 0);
		free(vpninfo->urlpath);
		vpninfo->urlpath = orig_path;

		/* Result could be either a JavaScript challenge or XML */
		if (result >= 0)
			result = gpst_xml_or_error(vpninfo, xml_buf, portal ? parse_portal_xml : parse_login_xml,
									   challenge_cb, ctx);
		if (result == -EACCES) {
			/* Invalid username/password; reuse same form, but blank,
			 * unless we just did a blind retry.
			 */
			nuke_opt_values(ctx->form->opts);
			if (!blind_retry)
				goto got_form;
			else
				blind_retry = 0;
		} else {
			/* Save successful username */
			if (!ctx->username)
				ctx->username = strdup(ctx->form->opts->_value);
			if (result == -EAGAIN) {
				/* New form is already populated from the challenge */
				goto got_form;
			} else if (portal && result == 0) {
				/* Portal login succeeded; blindly retry same credentials on gateway,
				 * unless it was a challenge auth form or alt-secret form.
				 */
				portal = 0;
				if (ctx->form->auth_id[0] == '_' && ctx->alt_secret) {
					blind_retry = 1;
					goto replay_form;
				}
			} else
			  break;
		}
	}

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

int gpst_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct login_context ctx = { .username=NULL, .alt_secret=NULL, .form=NULL };
	int result;

	/* An alternate password/secret field may be specified in the "URL path" (or --usergroup).
        * Known possibilities are:
	 *     /portal:portal-userauthcookie
	 *     /gateway:prelogin-cookie
	 */
	if (vpninfo->urlpath
	    && (ctx.alt_secret = strrchr(vpninfo->urlpath, ':')) != NULL) {
		*(ctx.alt_secret) = '\0';
		ctx.alt_secret = strdup(ctx.alt_secret+1);
	}

	if (vpninfo->urlpath && (!strcmp(vpninfo->urlpath, "portal") || !strncmp(vpninfo->urlpath, "global-protect", 14))) {
		/* assume the server is a portal */
		result = gpst_login(vpninfo, 1, &ctx);
	} else if (vpninfo->urlpath && (!strcmp(vpninfo->urlpath, "gateway") || !strncmp(vpninfo->urlpath, "ssl-vpn", 7))) {
		/* assume the server is a gateway */
		result = gpst_login(vpninfo, 0, &ctx);
	} else {
		/* first try handling it as a gateway, then a portal */
		result = gpst_login(vpninfo, 0, &ctx);
		if (result == -EEXIST) {
			result = gpst_login(vpninfo, 1, &ctx);
			if (result == -EEXIST)
				vpn_progress(vpninfo, PRG_ERR, _("Server is neither a GlobalProtect portal nor a gateway.\n"));
		}
	}
	free(ctx.username);
	free(ctx.alt_secret);
	free_auth_form(ctx.form);
	return result;
}

int gpst_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	int result;
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf = NULL;

	/* In order to logout successfully, the client must send not only
	 * the session's authcookie, but also the portal, user, computer,
	 * and domain matching the values sent with the getconfig request.
	 *
	 * You read that right: the client must send a bunch of irrelevant
	 * non-secret values in its logout request. If they're wrong or
	 * missing, the logout will fail and the authcookie will remain
	 * valid -- which is a security hole.
	 *
	 * Don't blame me. I didn't design this.
	 */
	buf_append(request_body, "%s", vpninfo->cookie);
	if ((result = buf_error(request_body)))
		goto out;

	/* We need to close and reopen the HTTPS connection (to kill
	 * the tunnel session) and submit a new HTTPS request to
	 * logout.
	 */
	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("ssl-vpn/logout.esp");
	openconnect_close_https(vpninfo, 0);
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	/* logout.esp returns HTTP status 200 and <response status="success"> when
	 * successful, and all manner of malformed junk when unsuccessful.
	 */
	if (result >= 0)
		result = gpst_xml_or_error(vpninfo, xml_buf, NULL, NULL, NULL);

	if (result < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful\n"));

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}
