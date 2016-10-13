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
	buf_append(buf, "Connection: Keep-Alive\r\n");
}

/* our "auth form" is just a static combination of username and password */
struct oc_auth_form *gp_auth_form(void)
{
	static struct oc_form_opt password = {.type=OC_FORM_OPT_PASSWORD, .name="password", .label="Password: "};
	static struct oc_form_opt username = {.next=&password, .type=OC_FORM_OPT_TEXT, .name="username", .label="Username: "};
	static struct oc_auth_form form = {.opts=&username };
	return &form;
}

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int parse_login_xml(struct openconnect_info *vpninfo, char *response)
{
	struct oc_text_buf *cookie = buf_alloc();
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	int ret, argn;

	if (!response) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc)
		goto bad_xml;

	xml_node = xmlDocGetRootElement(xml_doc);
	if (!xmlnode_is_named(xml_node, "jnlp"))
		goto bad_xml;
	xml_node = xml_node->children;
	if (!xmlnode_is_named(xml_node, "application-desc"))
		goto bad_xml;
	xml_node = xml_node->children;

	for (argn=0; xml_node; xml_node=xml_node->next) {
		if (xmlnode_is_named(xml_node, "argument")) {
			if (argn == 1)
				buf_append(cookie, "AUTH=%s;", xmlNodeGetContent(xml_node));
			else if (argn == 3)
				buf_append(cookie, "PORTAL=%s;", xmlNodeGetContent(xml_node));
			else if (argn == 4)
				buf_append(cookie, "USER=%s", xmlNodeGetContent(xml_node));
			argn++;
		}
	}
	if (argn<5) {
		buf_free(cookie);
		goto bad_xml;
	}

	vpninfo->cookie = strdup(cookie->data);
	buf_free(cookie);
	xmlFreeDoc(xml_doc);
	return 0;

bad_xml:
	if (xml_doc)
		xmlFreeDoc(xml_doc);
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to parse server response\n"));
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Response was:%s\n"), response);
	return -EINVAL;
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


	/* process static auth form (username and password) */
	result = process_auth_form(vpninfo, form);
	if (result)
		return result;

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
	vpninfo->useragent = "PAN GlobalProtect";
	vpninfo->urlpath = "ssl-vpn/login.esp";
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	vpninfo->urlpath = orig_path;
	vpninfo->useragent = orig_ua;

	buf_free(request_body);
	if (result < 0)
		return -EINVAL;

	/* parse login result */
	result = parse_login_xml(vpninfo, xml_buf);
	return result;
}
