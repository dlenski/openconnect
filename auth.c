/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
 * Copyright © 2013 John Morrissey <jwm@horde.net>
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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _WIN32
#include <pwd.h>
#endif

#ifdef HAVE_LIBOATH
#include <liboath/oath.h>
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "openconnect-internal.h"

static int xmlpost_append_form_opts(struct openconnect_info *vpninfo,
				    struct oc_auth_form *form, struct oc_text_buf *body);
static int can_gen_tokencode(struct openconnect_info *vpninfo,
			     struct oc_auth_form *form, struct oc_form_opt *opt);
static int do_gen_tokencode(struct openconnect_info *vpninfo, struct oc_auth_form *form);

int openconnect_set_option_value(struct oc_form_opt *opt, const char *value)
{
	if (opt->type == OC_FORM_OPT_SELECT) {
		struct oc_form_opt_select *sopt = (void *)opt;
		int i;

		for (i=0; i<sopt->nr_choices; i++) {
			if (!strcmp(value, sopt->choices[i]->name)) {
				opt->_value = sopt->choices[i]->name;
				return 0;
			}
		}
		return -EINVAL;
	}

	opt->_value = strdup(value);
	if (!opt->_value)
		return -ENOMEM;

	return 0;
}

static int append_opt(struct oc_text_buf *body, char *opt, char *name)
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

static int append_form_opts(struct openconnect_info *vpninfo,
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

static void free_opt(struct oc_form_opt *opt)
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

static int prop_equals(xmlNode *xml_node, const char *name, const char *value)
{
	char *tmp = (char *)xmlGetProp(xml_node, (unsigned char *)name);
	int ret = 0;

	if (tmp && !strcasecmp(tmp, value))
		ret = 1;
	free(tmp);
	return ret;
}

static int parse_auth_choice(struct openconnect_info *vpninfo, struct oc_auth_form *form,
			     xmlNode *xml_node)
{
	struct oc_form_opt_select *opt;
	xmlNode *opt_node;
	int max_choices = 0, selection = 0;

	opt = calloc(1, sizeof(*opt));
	if (!opt)
		return -ENOMEM;

	opt->form.type = OC_FORM_OPT_SELECT;
	opt->form.name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
	opt->form.label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");

	if (!opt->form.name) {
		vpn_progress(vpninfo, PRG_ERR, _("Form choice has no name\n"));
		free_opt((struct oc_form_opt *)opt);
		return -EINVAL;
	}

	for (opt_node = xml_node->children; opt_node; opt_node = opt_node->next)
		max_choices++;

	opt->choices = calloc(1, max_choices * sizeof(struct oc_choice *));
	if (!opt->choices) {
		free_opt((struct oc_form_opt *)opt);
		return -ENOMEM;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		char *form_id;
		struct oc_choice *choice;

		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp((char *)xml_node->name, "option"))
			continue;

		form_id = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		if (!form_id)
			form_id = (char *)xmlNodeGetContent(xml_node);
		if (!form_id)
			continue;

		choice = calloc(1, sizeof(*choice));
		if (!choice) {
			free_opt((struct oc_form_opt *)opt);
			return -ENOMEM;
		}

		choice->name = form_id;
		choice->label = (char *)xmlNodeGetContent(xml_node);
		choice->auth_type = (char *)xmlGetProp(xml_node, (unsigned char *)"auth-type");
		choice->override_name = (char *)xmlGetProp(xml_node, (unsigned char *)"override-name");
		choice->override_label = (char *)xmlGetProp(xml_node, (unsigned char *)"override-label");

		choice->second_auth = prop_equals(xml_node, "second-auth", "1");
		choice->secondary_username = (char *)xmlGetProp(xml_node,
			(unsigned char *)"secondary_username");
		choice->secondary_username_editable = prop_equals(xml_node,
			"secondary_username_editable", "true");
		choice->noaaa = prop_equals(xml_node, "noaaa", "1");

		if (prop_equals(xml_node, "selected", "true"))
			selection = opt->nr_choices;

		opt->choices[opt->nr_choices++] = choice;
	}

	if (!strcmp(opt->form.name, "group_list")) {
		form->authgroup_opt = opt;
		form->authgroup_selection = selection;
	}

	/* We link the choice _first_ so it's at the top of what we present
	   to the user */
	opt->form.next = form->opts;
	form->opts = &opt->form;
	return 0;
}

static int parse_form(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		      xmlNode *xml_node)
{
	char *input_type, *input_name, *input_label;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		struct oc_form_opt *opt, **p;

		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "select")) {
			if (parse_auth_choice(vpninfo, form, xml_node))
				return -EINVAL;
			continue;
		}
		if (strcmp((char *)xml_node->name, "input")) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("name %s not input\n"), xml_node->name);
			continue;
		}

		input_type = (char *)xmlGetProp(xml_node, (unsigned char *)"type");
		if (!input_type) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("No input type in form\n"));
			continue;
		}

		if (!strcmp(input_type, "submit") || !strcmp(input_type, "reset")) {
			free(input_type);
			continue;
		}

		input_name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
		if (!input_name) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("No input name in form\n"));
			free(input_type);
			continue;
		}
		input_label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");

		opt = calloc(1, sizeof(*opt));
		if (!opt) {
			free(input_type);
			free(input_name);
			free(input_label);
			return -ENOMEM;
		}

		opt->name = input_name;
		opt->label = input_label;
		opt->flags = prop_equals(xml_node, "second-auth", "1") ? OC_FORM_OPT_SECOND_AUTH : 0;

		if (!strcmp(input_type, "hidden")) {
			opt->type = OC_FORM_OPT_HIDDEN;
			opt->_value = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		} else if (!strcmp(input_type, "text")) {
			opt->type = OC_FORM_OPT_TEXT;
		} else if (!strcmp(input_type, "password")) {
			if (vpninfo->token_mode != OC_TOKEN_MODE_NONE &&
			    (can_gen_tokencode(vpninfo, form, opt) == 0)) {
				opt->type = OC_FORM_OPT_TOKEN;
			} else {
				opt->type = OC_FORM_OPT_PASSWORD;
			}
		} else {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Unknown input type %s in form\n"),
				     input_type);
			free(input_type);
			free(input_name);
			free(input_label);
			free(opt);
			continue;
		}

		free(input_type);

		p = &form->opts;
		while (*p)
			p = &(*p)->next;

		*p = opt;
	}

	return 0;
}

static char *xmlnode_msg(xmlNode *xml_node)
{
	char *fmt = (char *)xmlNodeGetContent(xml_node);
	char *result, *params[2], *pct;
	int len;
	int nr_params = 0;

	if (!fmt || !fmt[0]) {
		free(fmt);
		return NULL;
	}

	len = strlen(fmt) + 1;

	params[0] = (char *)xmlGetProp(xml_node, (unsigned char *)"param1");
	if (params[0])
		len += strlen(params[0]);
	params[1] = (char *)xmlGetProp(xml_node, (unsigned char *)"param2");
	if (params[1])
		len += strlen(params[1]);

	result = malloc(len);
	if (!result) {
		result = fmt;
		goto out;
	}

	strcpy(result, fmt);
	free(fmt);

	for (pct = strchr(result, '%'); pct;
	     (pct = strchr(pct, '%'))) {
		int paramlen;

		/* We only cope with '%s' */
		if (pct[1] != 's')
			goto out;

		if (params[nr_params]) {
			paramlen = strlen(params[nr_params]);
			/* Move rest of fmt string up... */
			memmove(pct + paramlen, pct + 2, strlen(pct + 2) + 1);
			/* ... and put the string parameter in where the '%s' was */
			memcpy(pct, params[nr_params], paramlen);
			pct += paramlen;
		} else
			pct++;

		if (++nr_params == 2)
			break;
	}
 out:
	free(params[0]);
	free(params[1]);
	return result;
}

static int xmlnode_is_named(xmlNode *xml_node, const char *name)
{
	return !strcmp((char *)xml_node->name, name);
}

static int xmlnode_get_prop(xmlNode *xml_node, const char *name, char **var)
{
	char *str = (char *)xmlGetProp(xml_node, (unsigned char *)name);

	if (!str)
		return -ENOENT;

	free(*var);
	*var = str;
	return 0;
}

static int xmlnode_match_prop(xmlNode *xml_node, const char *name, const char *match)
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

static int xmlnode_get_text(xmlNode *xml_node, const char *name, char **var)
{
	char *str;

	if (name && !xmlnode_is_named(xml_node, name))
		return -EINVAL;

	str = xmlnode_msg(xml_node);
	if (!str)
		return -ENOENT;

	free(*var);
	*var = str;
	return 0;
}

/*
 * Legacy server response looks like:
 *
 * <auth id="<!-- "main" for initial attempt, "success" means we have a cookie -->">
 *   <title><!-- title to display to user --></title>
 *   <csd
 *        token="<!-- save to vpninfo->csd_token -->"
 *        ticket="<!-- save to vpninfo->csd_ticket -->" />
 *   <csd
 *        stuburl="<!-- save to vpninfo->csd_stuburl if --os=win -->"
 *        starturl="<!-- save to vpninfo->csd_starturl if --os=win -->"
 *        waiturl="<!-- save to vpninfo->csd_starturl if --os=win -->"
 *   <csdMac
 *        stuburl="<!-- save to vpninfo->csd_stuburl if --os=mac-intel -->"
 *        starturl="<!-- save to vpninfo->csd_starturl if --os=mac-intel -->"
 *        waiturl="<!-- save to vpninfo->csd_waiturl if --os=mac-intel -->" />
 *   <csdLinux
 *        stuburl="<!-- same as above, for Linux -->"
 *        starturl="<!-- same as above, for Linux -->"
 *        waiturl="<!-- same as above, for Linux -->" />
 *   <banner><!-- display this to the user --></banner>
 *   <message>Please enter your username and password.</message>
 *   <form method="post" action="/+webvpn+/index.html">
 *     <input type="text" name="username" label="Username:" />
 *     <input type="password" name="password" label="Password:" />
 *     <input type="hidden" name="<!-- save these -->" value="<!-- ... -->" />
 *     <input type="submit" name="Login" value="Login" />
 *     <input type="reset" name="Clear" value="Clear" />
 *   </form>
 * </auth>
 *
 * New server response looks like:
 *
 * <config-auth>
 *   <version><!-- whatever --></version>
 *   <session-token><!-- if present, save to vpninfo->cookie --></session-token>
 *   <opaque>
 *     <!-- this could contain anything; copy to vpninfo->opaque_srvdata -->
 *     <tunnel-group>foobar</tunnel-group>
 *     <config-hash>1234567</config-hash>
 *   </opaque>
 *   <auth id="<!-- see above -->
 *     <!-- all of our old familiar fields -->
 *   </auth>
 *   <host-scan>
 *     <host-scan-ticket><!-- save to vpninfo->csd_ticket --></host-scan-ticket>
 *     <host-scan-token><!-- save to vpninfo->csd_token --></host-scan-token>
 *     <host-scan-base-uri><!-- save to vpninfo->csd_starturl --></host-scan-base-uri>
 *     <host-scan-wait-uri><!-- save to vpninfo->csd_waiturl --></host-scan-wait-uri>
 *   </host-scan>
 * </config-auth>
 *
 * Notes:
 *
 * 1) The new host-scan-*-uri nodes do not map directly to the old CSD fields.
 *
 * 2) The new <form> tag tends to omit the method/action properties.
 */

static int parse_auth_node(struct openconnect_info *vpninfo, xmlNode *xml_node,
			   struct oc_auth_form *form)
{
	int ret = 0;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		xmlnode_get_text(xml_node, "banner", &form->banner);
		xmlnode_get_text(xml_node, "message", &form->message);
		xmlnode_get_text(xml_node, "error", &form->error);

		if (xmlnode_is_named(xml_node, "form")) {

			/* defaults for new XML POST */
			form->method = strdup("POST");
			form->action = strdup("/");

			xmlnode_get_prop(xml_node, "method", &form->method);
			xmlnode_get_prop(xml_node, "action", &form->action);

			if (!form->method || !form->action ||
			    strcasecmp(form->method, "POST") || !form->action[0]) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Cannot handle form method='%s', action='%s'\n"),
					     form->method, form->action);
				ret = -EINVAL;
				goto out;
			}

			ret = parse_form(vpninfo, form, xml_node);
			if (ret < 0)
				goto out;
		} else if (!vpninfo->csd_scriptname && xmlnode_is_named(xml_node, "csd")) {
			xmlnode_get_prop(xml_node, "token", &vpninfo->csd_token);
			xmlnode_get_prop(xml_node, "ticket", &vpninfo->csd_ticket);
		}
		/* For Windows, vpninfo->csd_xmltag will be "csd" and there are *two* <csd>
		   nodes; one with token/ticket and one with the URLs. Process them both
		   the same and rely on the fact that xmlnode_get_prop() will not *clear*
		   the variable if no such property is found. */
		if (!vpninfo->csd_scriptname && xmlnode_is_named(xml_node, vpninfo->csd_xmltag)) {
			/* ignore the CSD trojan binary on mobile platforms */
			if (!vpninfo->csd_nostub)
				xmlnode_get_prop(xml_node, "stuburl", &vpninfo->csd_stuburl);
			xmlnode_get_prop(xml_node, "starturl", &vpninfo->csd_starturl);
			xmlnode_get_prop(xml_node, "waiturl", &vpninfo->csd_waiturl);
			vpninfo->csd_preurl = strdup(vpninfo->urlpath);
		}
	}

out:
	return ret;
}

static int parse_host_scan_node(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	/* ignore this whole section if the CSD trojan has already run */
	if (vpninfo->csd_scriptname)
		return 0;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		xmlnode_get_text(xml_node, "host-scan-ticket", &vpninfo->csd_ticket);
		xmlnode_get_text(xml_node, "host-scan-token", &vpninfo->csd_token);
		xmlnode_get_text(xml_node, "host-scan-base-uri", &vpninfo->csd_starturl);
		xmlnode_get_text(xml_node, "host-scan-wait-uri", &vpninfo->csd_waiturl);
	}
	return 0;
}

static void parse_profile_node(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	/* ignore this whole section if we already have a URL */
	if (vpninfo->profile_url && vpninfo->profile_sha1)
		return;

	/* Find <vpn rev="1.0"> child... */
	xml_node = xml_node->children;
	while (1) {
		if (!xml_node)
			return;

		if (xml_node->type == XML_ELEMENT_NODE &&
		    xmlnode_is_named(xml_node, "vpn") &&
		    !xmlnode_match_prop(xml_node, "rev", "1.0"))
			break;

		xml_node = xml_node->next;
	}

	/* Find <file type="profile" service-type="user"> */
	xml_node = xml_node->children;
	while (1) {
		if (!xml_node)
			return;

		if (xml_node->type == XML_ELEMENT_NODE &&
		    xmlnode_is_named(xml_node, "file") &&
		    !xmlnode_match_prop(xml_node, "type", "profile") &&
		    !xmlnode_match_prop(xml_node, "service-type", "user"))
			break;

		xml_node = xml_node->next;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		xmlnode_get_text(xml_node, "uri", &vpninfo->profile_url);
		/* FIXME: Check for <hash type="sha1"> */
		xmlnode_get_text(xml_node, "hash", &vpninfo->profile_sha1);
	}
}

static void parse_config_node(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (xmlnode_is_named(xml_node, "vpn-profile-manifest"))
			parse_profile_node(vpninfo, xml_node);
	}
}

static void free_auth_form(struct oc_auth_form *form)
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
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int parse_xml_response(struct openconnect_info *vpninfo, char *response,
			      struct oc_auth_form **formp, int *cert_rq)
{
	struct oc_auth_form *form;
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	int ret;

	if (*formp) {
		free_auth_form(*formp);
		*formp = NULL;
	}
	if (cert_rq)
		*cert_rq = 0;

	if (!response) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	form = calloc(1, sizeof(*form));
	if (!form)
		return -ENOMEM;
	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse server response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), response);
		free(form);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	while (xml_node) {
		ret = 0;

		if (xml_node->type != XML_ELEMENT_NODE) {
			xml_node = xml_node->next;
			continue;
		}
		if (xmlnode_is_named(xml_node, "config-auth")) {
			/* if we do have a config-auth node, it is the root element */
			xml_node = xml_node->children;
			continue;
		} else if (xmlnode_is_named(xml_node, "client-cert-request")) {
			if (cert_rq)
				*cert_rq = 1;
			else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Received <client-cert-request> when not expected.\n"));
				ret = -EINVAL;
			}
		} else if (xmlnode_is_named(xml_node, "auth")) {
			xmlnode_get_prop(xml_node, "id", &form->auth_id);
			ret = parse_auth_node(vpninfo, xml_node, form);
		} else if (xmlnode_is_named(xml_node, "opaque")) {
			if (vpninfo->opaque_srvdata)
				xmlFreeNode(vpninfo->opaque_srvdata);
			vpninfo->opaque_srvdata = xmlCopyNode(xml_node, 1);
			if (!vpninfo->opaque_srvdata)
				ret = -ENOMEM;
		} else if (xmlnode_is_named(xml_node, "host-scan")) {
			ret = parse_host_scan_node(vpninfo, xml_node);
		} else if (xmlnode_is_named(xml_node, "config")) {
			parse_config_node(vpninfo, xml_node);
		} else {
			xmlnode_get_text(xml_node, "session-token", &vpninfo->cookie);
			xmlnode_get_text(xml_node, "error", &form->error);
		}

		if (ret)
			goto out;
		xml_node = xml_node->next;
	}

	if (!form->auth_id && (!cert_rq || !*cert_rq)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("XML response has no \"auth\" node\n"));
		ret = -EINVAL;
		goto out;
	}

	*formp = form;
	xmlFreeDoc(xml_doc);
	return 0;

 out:
	xmlFreeDoc(xml_doc);
	free_auth_form(form);
	return ret;
}

/* Return value:
 *  < 0, on error
 *  = OC_FORM_RESULT_OK (0), when form parsed and POST required
 *  = OC_FORM_RESULT_CANCELLED, when response was cancelled by user
 *  = OC_FORM_RESULT_LOGGEDIN, when form indicates that login was already successful
 */
static int handle_auth_form(struct openconnect_info *vpninfo, struct oc_auth_form *form,
			    struct oc_text_buf *request_body, const char **method,
			    const char **request_body_type)
{
	int ret;
	struct oc_vpn_option *opt, *next;

	if (!strcmp(form->auth_id, "success"))
		return OC_FORM_RESULT_LOGGEDIN;

	if (vpninfo->nopasswd) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Asked for password but '--no-passwd' set\n"));
		return -EPERM;
	}

	if (vpninfo->csd_token && vpninfo->csd_ticket && vpninfo->csd_starturl && vpninfo->csd_waiturl) {
		/* AB: remove all cookies */
		for (opt = vpninfo->cookies; opt; opt = next) {
			next = opt->next;

			free(opt->option);
			free(opt->value);
			free(opt);
		}
		vpninfo->cookies = NULL;
		return OC_FORM_RESULT_OK;
	}
	if (!form->opts) {
		if (form->message)
			vpn_progress(vpninfo, PRG_INFO, "%s\n", form->message);
		if (form->error)
			vpn_progress(vpninfo, PRG_ERR, "%s\n", form->error);
		return -EPERM;
	}

	ret = process_auth_form(vpninfo, form);
	if (ret)
		return ret;

	/* tokencode generation is deferred until after username prompts and CSD */
	ret = do_gen_tokencode(vpninfo, form);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
		vpninfo->token_bypassed = 1;
		return ret;
	}

	ret = vpninfo->xmlpost ?
	      xmlpost_append_form_opts(vpninfo, form, request_body) :
	      append_form_opts(vpninfo, form, request_body);
	if (!ret) {
		*method = "POST";
		*request_body_type = "application/x-www-form-urlencoded";
	}
	return ret;
}

/*
 * Old submission format is just an HTTP query string:
 *
 * password=12345678&username=joe
 *
 * New XML format is more complicated:
 *
 * <config-auth client="vpn" type="<!-- init or auth-reply -->">
 *   <version who="vpn"><!-- currently just the OpenConnect version --></version>
 *   <device-id><!-- linux, linux-64, win, ... --></device-id>
 *   <opaque is-for="<!-- some name -->">
 *     <!-- just copy this verbatim from whatever the gateway sent us -->
 *   </opaque>
 *
 * For init only, add:
 *   <group-access>https://<!-- insert hostname here --></group-access>
 *
 * For auth-reply only, add:
 *   <auth>
 *     <username><!-- same treatment as the old form options --></username>
 *     <password><!-- ditto -->
 *   </auth>
 *   <group-select><!-- name of selected authgroup --></group-select>
 *   <host-scan-token><!-- vpninfo->csd_ticket --></host-scan-token>
 */

#define XCAST(x) ((const xmlChar *)(x))

static xmlDocPtr xmlpost_new_query(struct openconnect_info *vpninfo, const char *type,
				   xmlNodePtr *rootp)
{
	xmlDocPtr doc;
	xmlNodePtr root, node;

	doc = xmlNewDoc(XCAST("1.0"));
	if (!doc)
		return NULL;

	*rootp = root = xmlNewNode(NULL, XCAST("config-auth"));
	if (!root)
		goto bad;
	if (!xmlNewProp(root, XCAST("client"), XCAST("vpn")))
		goto bad;
	if (!xmlNewProp(root, XCAST("type"), XCAST(type)))
		goto bad;
	xmlDocSetRootElement(doc, root);

	node = xmlNewTextChild(root, NULL, XCAST("version"), XCAST(openconnect_version_str));
	if (!node)
		goto bad;
	if (!xmlNewProp(node, XCAST("who"), XCAST("vpn")))
		goto bad;

	node = xmlNewTextChild(root, NULL, XCAST("device-id"), XCAST(vpninfo->platname));
	if (!node)
		goto bad;
	if (vpninfo->mobile_platform_version) {
		if (!xmlNewProp(node, XCAST("platform-version"), XCAST(vpninfo->mobile_platform_version)) ||
		    !xmlNewProp(node, XCAST("device-type"), XCAST(vpninfo->mobile_device_type)) ||
		    !xmlNewProp(node, XCAST("unique-id"), XCAST(vpninfo->mobile_device_uniqueid)))
			goto bad;
	}

	return doc;

bad:
	xmlFreeDoc(doc);
	return NULL;
}

static int xmlpost_complete(xmlDocPtr doc, struct oc_text_buf *body)
{
	xmlChar *mem = NULL;
	int len, ret = 0;

	if (!body) {
		xmlFree(doc);
		return 0;
	}

	xmlDocDumpMemoryEnc(doc, &mem, &len, "UTF-8");
	if (!mem) {
		xmlFreeDoc(doc);
		return -ENOMEM;
	}

	buf_append_bytes(body, mem, len);

	xmlFreeDoc(doc);
	xmlFree(mem);

	return ret;
}

static int xmlpost_initial_req(struct openconnect_info *vpninfo,
			       struct oc_text_buf *request_body, int cert_fail)
{
	xmlNodePtr root, node;
	xmlDocPtr doc = xmlpost_new_query(vpninfo, "init", &root);
	char *url;
	int result;

	if (!doc)
		return -ENOMEM;

	if (vpninfo->urlpath)
		result = asprintf(&url, "https://%s/%s", vpninfo->hostname, vpninfo->urlpath);
	else
		result = asprintf(&url, "https://%s", vpninfo->hostname);

	if (result == -1)
		goto bad;
	node = xmlNewTextChild(root, NULL, XCAST("group-access"), XCAST(url));
	free(url);
	if (!node)
		goto bad;
	if (cert_fail) {
		node = xmlNewTextChild(root, NULL, XCAST("client-cert-fail"), NULL);
		if (!node)
			goto bad;
	}
	if (vpninfo->authgroup) {
		node = xmlNewTextChild(root, NULL, XCAST("group-select"), XCAST(vpninfo->authgroup));
		if (!node)
			goto bad;
	}
	return xmlpost_complete(doc, request_body);

bad:
	xmlpost_complete(doc, NULL);
	return -ENOMEM;
}

static int xmlpost_append_form_opts(struct openconnect_info *vpninfo,
				    struct oc_auth_form *form, struct oc_text_buf *body)
{
	xmlNodePtr root, node;
	xmlDocPtr doc = xmlpost_new_query(vpninfo, "auth-reply", &root);
	struct oc_form_opt *opt;

	if (!doc)
		return -ENOMEM;

	if (vpninfo->opaque_srvdata) {
		node = xmlCopyNode(vpninfo->opaque_srvdata, 1);
		if (!node)
			goto bad;
		if (!xmlAddChild(root, node))
			goto bad;
	}

	node = xmlNewChild(root, NULL, XCAST("auth"), NULL);
	if (!node)
		goto bad;

	for (opt = form->opts; opt; opt = opt->next) {
		/* group_list: create a new <group-select> node under <config-auth> */
		if (!strcmp(opt->name, "group_list")) {
			if (!xmlNewTextChild(root, NULL, XCAST("group-select"), XCAST(opt->_value)))
				goto bad;
			continue;
		}

		/* answer,whichpin,new_password: rename to "password" */
		if (!strcmp(opt->name, "answer") ||
		    !strcmp(opt->name, "whichpin") ||
		    !strcmp(opt->name, "new_password")) {
			if (!xmlNewTextChild(node, NULL, XCAST("password"), XCAST(opt->_value)))
				goto bad;
			continue;
		}

		/* verify_pin,verify_password: ignore */
		if (!strcmp(opt->name, "verify_pin") ||
		    !strcmp(opt->name, "verify_password")) {
			continue;
		}

		/* everything else: create <foo>user_input</foo> under <auth> */
		if (!xmlNewTextChild(node, NULL, XCAST(opt->name), XCAST(opt->_value)))
			goto bad;
	}

	if (vpninfo->csd_token &&
	    !xmlNewTextChild(root, NULL, XCAST("host-scan-token"), XCAST(vpninfo->csd_token)))
		goto bad;

	return xmlpost_complete(doc, body);

bad:
	xmlpost_complete(doc, NULL);
	return -ENOMEM;
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
static int can_gen_tokencode(struct openconnect_info *vpninfo,
			     struct oc_auth_form *form,
			     struct oc_form_opt *opt)
{
	switch (vpninfo->token_mode) {
#ifdef HAVE_LIBSTOKEN
	case OC_TOKEN_MODE_STOKEN:
		return can_gen_stoken_code(vpninfo, form, opt);
#endif
#ifdef HAVE_LIBOATH
	case OC_TOKEN_MODE_TOTP:
		return can_gen_totp_code(vpninfo, form, opt);

	case OC_TOKEN_MODE_HOTP:
		return can_gen_hotp_code(vpninfo, form, opt);
#endif
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return can_gen_yubikey_code(vpninfo, form, opt);
#endif
	default:
		return -EINVAL;
	}
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
static int do_gen_tokencode(struct openconnect_info *vpninfo,
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
#ifdef HAVE_LIBOATH
	case OC_TOKEN_MODE_TOTP:
		return do_gen_totp_code(vpninfo, form, opt);

	case OC_TOKEN_MODE_HOTP:
		return do_gen_hotp_code(vpninfo, form, opt);
#endif
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return do_gen_yubikey_code(vpninfo, form, opt);
#endif
	default:
		return -EINVAL;
	}
}

static int fetch_config(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *buf;
	int result;
	unsigned char local_sha1_bin[SHA1_SIZE];
	char local_sha1_ascii[(SHA1_SIZE * 2)+1];
	int i;

	if (!vpninfo->profile_url || !vpninfo->profile_sha1 || !vpninfo->write_new_config)
		return -ENOENT;

	if (!strncasecmp(vpninfo->xmlsha1, vpninfo->profile_sha1, SHA1_SIZE * 2)) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Not downloading XML profile because SHA1 already matches\n"));
		return 0;
	}

	if ((result = openconnect_open_https(vpninfo))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open HTTPS connection to %s\n"),
			     vpninfo->hostname);
		return result;
	}

	buf = buf_alloc();
	buf_append(buf, "GET %s HTTP/1.1\r\n", vpninfo->profile_url);
	cstp_common_headers(vpninfo, buf);
	if (vpninfo->xmlpost)
		buf_append(buf, "Cookie: webvpn=%s\r\n", vpninfo->cookie);
	buf_append(buf, "\r\n");

	if (buf_error(buf))
		return buf_free(buf);

	if (vpninfo->ssl_write(vpninfo, buf->data, buf->pos) != buf->pos) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to send GET request for new config\n"));
		buf_free(buf);
		return -EIO;
	}

	result = process_http_response(vpninfo, 0, NULL, buf);
	if (result < 0) {
		/* We'll already have complained about whatever offended us */
		buf_free(buf);
		return -EINVAL;
	}

	if (result != 200) {
		buf_free(buf);
		return -EINVAL;
	}

	openconnect_sha1(local_sha1_bin, buf->data, buf->pos);

	for (i = 0; i < SHA1_SIZE; i++)
		sprintf(&local_sha1_ascii[i*2], "%02x", local_sha1_bin[i]);

	if (strcasecmp(vpninfo->profile_sha1, local_sha1_ascii)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Downloaded config file did not match intended SHA1\n"));
		buf_free(buf);
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_DEBUG, _("Downloaded new XML profile\n"));

	result = vpninfo->write_new_config(vpninfo->cbdata, buf->data, buf->pos);
	buf_free(buf);
	return result;
}

static int run_csd_script(struct openconnect_info *vpninfo, char *buf, int buflen)
{
#ifdef _WIN32
	vpn_progress(vpninfo, PRG_ERR,
		     _("Error: Running the 'Cisco Secure Desktop' trojan on Windows is not yet implemented.\n"));
	return -EPERM;
#else
	char fname[64];
	int fd, ret;

	if (!vpninfo->csd_wrapper && !buflen) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: Server asked us to run CSD hostscan.\n"
			       "You need to provide a suitable --csd-wrapper argument.\n"));
		return -EINVAL;
	}

	if (!vpninfo->uid_csd_given && !vpninfo->csd_wrapper) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: Server asked us to download and run a 'Cisco Secure Desktop' trojan.\n"
			       "This facility is disabled by default for security reasons, so you may wish to enable it.\n"));
		return -EPERM;
	}

#ifndef __linux__
	vpn_progress(vpninfo, PRG_INFO,
		     _("Trying to run Linux CSD trojan script.\n"));
#endif

	fname[0] = 0;
	if (buflen) {
		struct oc_vpn_option *opt;
		const char *tmpdir = NULL;

		/* If the caller wanted $TMPDIR set for the CSD script, that
		   means for us too; look through the csd_env for a TMPDIR
		   override. */
		for (opt = vpninfo->csd_env; opt; opt = opt->next) {
			if (!strcmp(opt->option, "TMPDIR")) {
				tmpdir = opt->value;
				break;
			}
		}
		if (!opt)
			tmpdir = getenv("TMPDIR");

		if (!tmpdir && !access("/var/tmp", W_OK))
			tmpdir = "/var/tmp";
		if (!tmpdir)
			tmpdir = "/tmp";

		if (access(tmpdir, W_OK))
			vpn_progress(vpninfo, PRG_ERR,
				     _("Temporary directory '%s' is not writable: %s\n"),
				     tmpdir, strerror(errno));

		snprintf(fname, 64, "%s/csdXXXXXX", tmpdir);
		fd = mkstemp(fname);
		if (fd < 0) {
			int err = -errno;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open temporary CSD script file: %s\n"),
				     strerror(errno));
			return err;
		}

		ret = write(fd, (void *)buf, buflen);
		if (ret != buflen) {
			int err = -errno;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to write temporary CSD script file: %s\n"),
				     strerror(errno));
			return err;
		}
		fchmod(fd, 0755);
		close(fd);
	}

	if (!fork()) {
		char scertbuf[MD5_SIZE * 2 + 1];
		char ccertbuf[MD5_SIZE * 2 + 1];
		char *csd_argv[32];
		int i = 0;

		if (vpninfo->uid_csd_given && vpninfo->uid_csd != getuid()) {
			struct passwd *pw;

			if (setuid(vpninfo->uid_csd)) {
				fprintf(stderr, _("Failed to set uid %ld\n"),
					(long)vpninfo->uid_csd);
				exit(1);
			}
			if (!(pw = getpwuid(vpninfo->uid_csd))) {
				fprintf(stderr, _("Invalid user uid=%ld\n"),
					(long)vpninfo->uid_csd);
				exit(1);
			}
			setenv("HOME", pw->pw_dir, 1);
			if (chdir(pw->pw_dir)) {
				fprintf(stderr, _("Failed to change to CSD home directory '%s': %s\n"),
					pw->pw_dir, strerror(errno));
				exit(1);
			}
		}
		if (getuid() == 0 && !vpninfo->csd_wrapper) {
			fprintf(stderr, _("Warning: you are running insecure "
					  "CSD code with root privileges\n"
					  "\t Use command line option \"--csd-user\"\n"));
		}
		/* Spurious stdout output from the CSD trojan will break both
		   the NM tool and the various cookieonly modes. */
		dup2(2, 1);
		if (vpninfo->csd_wrapper)
			csd_argv[i++] = openconnect_utf8_to_legacy(vpninfo,
								   vpninfo->csd_wrapper);
		csd_argv[i++] = fname;
		csd_argv[i++] = (char *)"-ticket";
		if (asprintf(&csd_argv[i++], "\"%s\"", vpninfo->csd_ticket) == -1)
			goto out;
		csd_argv[i++] = (char *)"-stub";
		csd_argv[i++] = (char *)"\"0\"";
		csd_argv[i++] = (char *)"-group";
		if (asprintf(&csd_argv[i++], "\"%s\"", vpninfo->authgroup?:"") == -1)
			goto out;

		openconnect_local_cert_md5(vpninfo, ccertbuf);
		scertbuf[0] = 0;
		get_cert_md5_fingerprint(vpninfo, vpninfo->peer_cert, scertbuf);
		csd_argv[i++] = (char *)"-certhash";
		if (asprintf(&csd_argv[i++], "\"%s:%s\"", scertbuf, ccertbuf) == -1)
			goto out;

		csd_argv[i++] = (char *)"-url";
		if (asprintf(&csd_argv[i++], "\"https://%s%s\"", vpninfo->hostname, vpninfo->csd_starturl) == -1)
			goto out;

		csd_argv[i++] = (char *)"-langselen";
		csd_argv[i++] = NULL;

		if (setenv("CSD_TOKEN", vpninfo->csd_token, 1))
			goto out;
		if (setenv("CSD_HOSTNAME", vpninfo->hostname, 1))
			goto out;

		apply_script_env(vpninfo->csd_env);

		execv(csd_argv[0], csd_argv);

out:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to exec CSD script %s\n"), csd_argv[0]);
		exit(1);
	}

	free(vpninfo->csd_stuburl);
	vpninfo->csd_stuburl = NULL;
	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup(vpninfo->csd_waiturl +
				  (vpninfo->csd_waiturl[0] == '/' ? 1 : 0));
	free(vpninfo->csd_waiturl);
	vpninfo->csd_waiturl = NULL;
	vpninfo->csd_scriptname = strdup(fname);

	http_add_cookie(vpninfo, "sdesktop", vpninfo->csd_token, 1);
	return 0;
#endif /* !_WIN32 */
}


/* Return value:
 *  < 0, if the data is unrecognized
 *  = 0, if the page contains an XML document
 *  = 1, if the page is a wait/refresh HTML page
 */
static int check_response_type(struct openconnect_info *vpninfo, char *form_buf)
{
	if (strncmp(form_buf, "<?xml", 5)) {
		/* Not XML? Perhaps it's HTML with a refresh... */
		if (strcasestr(form_buf, "http-equiv=\"refresh\""))
			return 1;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown response from server\n"));
		return -EINVAL;
	}
	return 0;
}

/* Return value:
 *  < 0, on error
 *  > 0, no cookie (user cancel)
 *  = 0, obtained cookie
 */
int cstp_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *opt;
	char *form_buf = NULL;
	struct oc_auth_form *form = NULL;
	int result, buflen, tries;
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *orig_host = NULL, *orig_path = NULL, *form_path = NULL;
	int orig_port = 0;
	int cert_rq, cert_sent = !vpninfo->cert;

#ifdef HAVE_LIBSTOKEN
	/* Step 1: Unlock software token (if applicable) */
	if (vpninfo->token_mode == OC_TOKEN_MODE_STOKEN) {
		result = prepare_stoken(vpninfo);
		if (result)
			return result;
	}
#endif

	if (!vpninfo->xmlpost)
		goto no_xmlpost;

	/*
	 * Step 2: Probe for XML POST compatibility
	 *
	 * This can get stuck in a redirect loop, so give up after any of:
	 *
	 * a) HTTP error (e.g. 400 Bad Request)
	 * b) Same-host redirect (e.g. Location: /foo/bar)
	 * c) Three redirects without seeing a plausible login form
	 */
newgroup:
	buf_truncate(request_body);
	result = xmlpost_initial_req(vpninfo, request_body, 0);
	if (result < 0)
		goto out;

	free(orig_host);
	free(orig_path);
	orig_host = strdup(vpninfo->hostname);
	orig_path = vpninfo->urlpath ? strdup(vpninfo->urlpath) : NULL;
	orig_port = vpninfo->port;

	for (tries = 0; ; tries++) {
		if (tries == 3) {
		fail:
			if (vpninfo->xmlpost) {
			no_xmlpost:
				/* Try without XML POST this time... */
				tries = 0;
				vpninfo->xmlpost = 0;
				request_body_type = NULL;
				buf_truncate(request_body);
				method = "GET";
				if (orig_host) {
					openconnect_set_hostname(vpninfo, orig_host);
					free(orig_host);
					orig_host = NULL;
					free(vpninfo->urlpath);
					vpninfo->urlpath = orig_path;
					orig_path = NULL;
					vpninfo->port = orig_port;
				}
				openconnect_close_https(vpninfo, 0);
			} else {
				result = -EIO;
				goto out;
			}
		}

		result = do_https_request(vpninfo, method, request_body_type, request_body,
					  &form_buf, 0);
		if (vpninfo->got_cancel_cmd) {
			result = 1;
			goto out;
		}
		if (result == -EINVAL)
			goto fail;
		if (result < 0)
			goto out;

		/* Some ASAs forget to send the TLS cert request on the initial connection.
		 * If we have a client cert, disable HTTP keepalive until we get a real
		 * login form (not a redirect). */
		if (!cert_sent)
			openconnect_close_https(vpninfo, 0);

		/* XML POST does not allow local redirects, but GET does. */
		if (vpninfo->xmlpost &&
		    vpninfo->redirect_type == REDIR_TYPE_LOCAL)
			goto fail;
		else if (vpninfo->redirect_type != REDIR_TYPE_NONE)
			continue;

		result = parse_xml_response(vpninfo, form_buf, &form, &cert_rq);
		if (result < 0)
			goto fail;

		if (cert_rq) {
			int cert_failed = 0;

			free_auth_form(form);
			form = NULL;

			if (!cert_sent && vpninfo->cert) {
				/* Try again on a fresh connection. */
				cert_sent = 1;
			} else if (cert_sent && vpninfo->cert) {
				/* Try again with <client-cert-fail/> in the request */
				vpn_progress(vpninfo, PRG_ERR,
					     _("Server requested SSL client certificate after one was provided\n"));
				cert_failed = 1;
			} else {
				vpn_progress(vpninfo, PRG_INFO,
					     _("Server requested SSL client certificate; none was configured\n"));
				cert_failed = 1;
			}
			buf_truncate(request_body);
			result = xmlpost_initial_req(vpninfo, request_body, cert_failed);
			if (result < 0)
				goto fail;
			continue;
		}
		if (form && form->action) {
			vpninfo->redirect_url = strdup(form->action);
			handle_redirect(vpninfo);
		}
		break;
	}
	if (vpninfo->xmlpost)
		vpn_progress(vpninfo, PRG_INFO, _("XML POST enabled\n"));

	/* Step 4: Run the CSD trojan, if applicable */
	if (vpninfo->csd_starturl && vpninfo->csd_waiturl) {
		buflen = 0;

		if (vpninfo->urlpath) {
			form_path = strdup(vpninfo->urlpath);
			if (!form_path) {
				result = -ENOMEM;
				goto out;
			}
		}

		/* fetch the CSD program, if available */
		if (vpninfo->csd_stuburl) {
			vpninfo->redirect_url = vpninfo->csd_stuburl;
			vpninfo->csd_stuburl = NULL;
			handle_redirect(vpninfo);

			buflen = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, 0);
			if (buflen <= 0) {
				result = -EINVAL;
				goto out;
			}
		}

		/* This is the CSD stub script, which we now need to run */
		result = run_csd_script(vpninfo, form_buf, buflen);
		if (result)
			goto out;

		/* vpninfo->urlpath now points to the wait page */
		while (1) {
			result = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, 0);
			if (result <= 0)
				break;

			result = check_response_type(vpninfo, form_buf);
			if (result <= 0)
				break;

			vpn_progress(vpninfo, PRG_INFO,
				     _("Refreshing %s after 1 second...\n"),
				     vpninfo->urlpath);
			sleep(1);
		}
		if (result < 0)
			goto out;

		/* refresh the form page, to see if we're authorized now */
		free(vpninfo->urlpath);
		vpninfo->urlpath = form_path;
		form_path = NULL;

		result = do_https_request(vpninfo,
					  vpninfo->xmlpost ? "POST" : "GET",
					  request_body_type, request_body, &form_buf, 1);
		if (result < 0)
			goto out;

		result = parse_xml_response(vpninfo, form_buf, &form, NULL);
		if (result < 0)
			goto out;
	}

	/* Step 5: Ask the user to fill in the auth form; repeat as necessary */
	while (1) {
		buf_truncate(request_body);
		result = handle_auth_form(vpninfo, form, request_body,
					  &method, &request_body_type);
		if (result < 0 || result == OC_FORM_RESULT_CANCELLED)
			goto out;
		if (result == OC_FORM_RESULT_LOGGEDIN)
			break;
		if (result == OC_FORM_RESULT_NEWGROUP) {
			free(form_buf);
			form_buf = NULL;
			free_auth_form(form);
			form = NULL;
			goto newgroup;
		}

		result = do_https_request(vpninfo, method, request_body_type, request_body,
					  &form_buf, 1);
		if (result < 0)
			goto out;

		result = parse_xml_response(vpninfo, form_buf, &form, NULL);
		if (result < 0)
			goto out;
		if (form->action) {
			vpninfo->redirect_url = strdup(form->action);
			handle_redirect(vpninfo);
		}
	}

	/* A return value of 2 means the XML form indicated
	   success. We _should_ have a cookie... */

	for (opt = vpninfo->cookies; opt; opt = opt->next) {

		if (!strcmp(opt->option, "webvpn")) {
			free(vpninfo->cookie);
			vpninfo->cookie = strdup(opt->value);
		} else if (vpninfo->write_new_config && !strcmp(opt->option, "webvpnc")) {
			char *tok = opt->value;
			char *bu = NULL, *fu = NULL, *sha = NULL;

			do {
				if (tok != opt->value)
					*(tok++) = 0;

				if (!strncmp(tok, "bu:", 3))
					bu = tok + 3;
				else if (!strncmp(tok, "fu:", 3))
					fu = tok + 3;
				else if (!strncmp(tok, "fh:", 3))
					sha = tok + 3;
			} while ((tok = strchr(tok, '&')));

			if (bu && fu && sha) {
				if (asprintf(&vpninfo->profile_url, "%s%s", bu, fu) == -1) {
					result = -ENOMEM;
					goto out;
				}
				vpninfo->profile_sha1 = strdup(sha);
			}
		}
	}
	result = 0;

	fetch_config(vpninfo);

out:
	buf_free(request_body);

	free (orig_host);
	free (orig_path);

	free(form_path);
	free(form_buf);
	free_auth_form(form);

	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
		vpninfo->csd_scriptname = NULL;
	}

	return result;
}
