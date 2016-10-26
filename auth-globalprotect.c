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
static struct oc_auth_form *gp_auth_form(void)
{
	static struct oc_form_opt password = {.type=OC_FORM_OPT_PASSWORD, .name=(char *)"password", .label=(char *)"Password: "};
	static struct oc_form_opt username = {.next=&password, .type=OC_FORM_OPT_TEXT, .name=(char *)"username", .label=(char *)"Username: "};
	static struct oc_auth_form form = {.opts=&username, .message=(char *)"Please enter your username and password." };
	return &form;
}

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int parse_login_xml(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	struct oc_text_buf *cookie = buf_alloc();
	int argn=0;

	if (!xmlnode_is_named(xml_node, "jnlp"))
		return -EINVAL;

	xml_node = xml_node->children;
	if (!xmlnode_is_named(xml_node, "application-desc"))
		return -EINVAL;

	xml_node = xml_node->children;
	for (argn=0; xml_node; xml_node=xml_node->next) {
		if (xmlnode_is_named(xml_node, "argument")) {
			if (argn == 1)
				append_opt(cookie, "authcookie", (char *)xmlNodeGetContent(xml_node));
			else if (argn == 3)
				append_opt(cookie, "portal", (char *)xmlNodeGetContent(xml_node));
			else if (argn == 4)
				append_opt(cookie, "user", (char *)xmlNodeGetContent(xml_node));
			else if (argn == 7)
				append_opt(cookie, "domain", (char *)xmlNodeGetContent(xml_node));
			argn++;
		}
	}

	if (argn<8) {
		buf_free(cookie);
		return -EINVAL;
	}

	vpninfo->cookie = strdup(cookie->data);
	buf_free(cookie);
	return 0;
}

int gpst_obtain_cookie(struct openconnect_info *vpninfo)
{
	int result;

	struct oc_form_opt *opt;
	struct oc_auth_form *form = gp_auth_form();
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL, *orig_path, *orig_ua;

	/* Ask the user to fill in the auth form; repeat as necessary */
	do {
		free(xml_buf);
		buf_truncate(request_body);

		/* process static auth form (username and password) */
		result = process_auth_form(vpninfo, form);
		if (result)
			goto out;

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
		vpninfo->urlpath = (char *)"ssl-vpn/login.esp";
		result = do_https_request(vpninfo, method, request_body_type, request_body,
					  &xml_buf, 0);
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
	vpninfo->urlpath = (char *)"ssl-vpn/logout.esp";
	openconnect_close_https(vpninfo, 0);
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
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
