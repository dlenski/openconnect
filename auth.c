/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2011 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "openconnect-internal.h"

static int append_opt(char *body, int bodylen, char *opt, char *name)
{
	int len = strlen(body);

	if (len) {
		if (len >= bodylen - 1)
			return -ENOSPC;
		body[len++] = '&';
	}

	while (*opt) {
		if (isalnum((int)(unsigned char)*opt)) {
			if (len >= bodylen - 1)
				return -ENOSPC;
			body[len++] = *opt;
		} else {
			if (len >= bodylen - 3)
				return -ENOSPC;
			sprintf(body+len, "%%%02x", *opt);
			len += 3;
		}
		opt++;
	}

	if (len >= bodylen - 1)
		return -ENOSPC;
	body[len++] = '=';

	while (name && *name) {
		if (isalnum((int)(unsigned char)*name)) {
			if (len >= bodylen - 1)
				return -ENOSPC;
			body[len++] = *name;
		} else {
			if (len >= bodylen - 3)
				return -ENOSPC;
			sprintf(body+len, "%%%02X", *name);
			len += 3;
		}
		name++;
	}
	body[len] = 0;

	return 0;
}

static int append_form_opts(struct openconnect_info *vpninfo,
			    struct oc_auth_form *form, char *body, int bodylen)
{
	struct oc_form_opt *opt;
	int ret;

	for (opt = form->opts; opt; opt = opt->next) {
		ret = append_opt(body, bodylen, opt->name, opt->value);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Maybe we should offer this choice to the user. So far we've only
 * ever seen it offer bogus choices though -- between certificate and
 * password authentication, when the former has already failed.
 * So we just accept the first option with an auth-type property.
 */

static int parse_auth_choice(struct openconnect_info *vpninfo, struct oc_auth_form *form,
			     xmlNode *xml_node)
{
	struct oc_form_opt_select *opt;

	opt = calloc(1, sizeof(*opt));
	if (!opt)
		return -ENOMEM;

	opt->form.type = OC_FORM_OPT_SELECT;
	opt->form.name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
	opt->form.label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");

	if (!opt->form.name) {
		vpn_progress(vpninfo, PRG_ERR, _("Form choice has no name\n"));
		free(opt);
		return -EINVAL;
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
			continue;

		opt->nr_choices++;
		opt = realloc(opt, sizeof(*opt) +
				   opt->nr_choices * sizeof(*choice));
		if (!opt)
			return -ENOMEM;

		choice = &opt->choices[opt->nr_choices-1];

		choice->name = form_id;
		choice->label = (char *)xmlNodeGetContent(xml_node);
		choice->auth_type = (char *)xmlGetProp(xml_node, (unsigned char *)"auth-type");
		choice->override_name = (char *)xmlGetProp(xml_node, (unsigned char *)"override-name");
		choice->override_label = (char *)xmlGetProp(xml_node, (unsigned char *)"override-label");
	}

	/* We link the choice _first_ so it's at the top of what we present
	   to the user */
	opt->form.next = form->opts;
	form->opts = &opt->form;
	return 0;
}

/* Return value:
 *  < 0, on error
 *  = 0, when form was cancelled
 *  = 1, when form was parsed
 */
static int parse_form(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		      xmlNode *xml_node, char *body, int bodylen)
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
			vpn_progress(vpninfo, PRG_TRACE,
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

		if (!strcmp(input_type, "hidden")) {
			opt->type = OC_FORM_OPT_HIDDEN;
			opt->value = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		} else if (!strcmp(input_type, "text"))
			opt->type = OC_FORM_OPT_TEXT;
		else if (!strcmp(input_type, "password"))
			opt->type = OC_FORM_OPT_PASSWORD;
		else {
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
		opt->name = input_name;
		opt->label = input_label;

		p = &form->opts;
		while (*p)
			p = &(*p)->next;

		*p = opt;
	}

	vpn_progress(vpninfo, PRG_TRACE, _("Fixed options give %s\n"), body);

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
	free (fmt);

	for (pct = strchr(result, '%'); pct;
	     (pct = strchr(pct, '%'))) {
		int paramlen;

		/* We only cope with '%s' */
		if (pct[1] != 's')
			goto out;

		if (params[nr_params]) {
			paramlen = strlen(params[nr_params]);
			/* Move rest of fmt string up... */
			memmove(pct - 1 + paramlen, pct + 2, strlen(pct) - 1);
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

/* Return value:
 *  < 0, on error
 *  = 0, when form parsed and POST required
 *  = 1, when response was cancelled by user
 *  = 2, when form indicates that login was already successful
 */
int parse_xml_response(struct openconnect_info *vpninfo, char *response,
		       char *request_body, int req_len, const char **method,
		       const char **request_body_type)
{
	struct oc_auth_form *form;
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	int ret;
	struct vpn_option *opt, *next;

	form = calloc(1, sizeof(*form));
	if (!form)
		return -ENOMEM;

	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL, 0);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse server response\n"));
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Response was:%s\n"), response);
		free(form);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	if (xml_node->type != XML_ELEMENT_NODE || strcmp((char *)xml_node->name, "auth")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("XML response has no \"auth\" root node\n"));
		ret = -EINVAL;
		goto out;
	}

	form->auth_id = (char *)xmlGetProp(xml_node, (unsigned char *)"id");
	if (!strcmp(form->auth_id, "success")) {
		ret = 2;
		goto out;
	}

	if (vpninfo->nopasswd) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Asked for password but '--no-passwd' set\n"));
		ret = -EPERM;
		goto out;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "banner")) {
			free(form->banner);
			form->banner = xmlnode_msg(xml_node);
		} else if (!strcmp((char *)xml_node->name, "message")) {
			free(form->message);
			form->message = xmlnode_msg(xml_node);
		} else if (!strcmp((char *)xml_node->name, "error")) {
			free(form->error);
			form->error = xmlnode_msg(xml_node);
		} else if (!strcmp((char *)xml_node->name, "form")) {

			form->method = (char *)xmlGetProp(xml_node, (unsigned char *)"method");
			form->action = (char *)xmlGetProp(xml_node, (unsigned char *)"action");
			if (!form->method || !form->action || 
			    strcasecmp(form->method, "POST") || !form->action[0]) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Cannot handle form method='%s', action='%s'\n"),
					     form->method, form->action);
				ret = -EINVAL;
				goto out;
			}
			vpninfo->redirect_url = strdup(form->action);

			ret = parse_form(vpninfo, form, xml_node, request_body, req_len);
			if (ret < 0)
				goto out;
		} else if (!vpninfo->csd_scriptname && !strcmp((char *)xml_node->name, "csd")) {
			if (!vpninfo->csd_token)
				vpninfo->csd_token = (char *)xmlGetProp(xml_node,
									(unsigned char *)"token");
			if (!vpninfo->csd_ticket)
				vpninfo->csd_ticket = (char *)xmlGetProp(xml_node,
									 (unsigned char *)"ticket");
		} else if (!vpninfo->csd_scriptname && !strcmp((char *)xml_node->name, "csdLinux")) {
			vpninfo->csd_stuburl = (char *)xmlGetProp(xml_node,
								  (unsigned char *)"stuburl");
			vpninfo->csd_starturl = (char *)xmlGetProp(xml_node,
								   (unsigned char *)"starturl");
			vpninfo->csd_waiturl = (char *)xmlGetProp(xml_node,
								  (unsigned char *)"waiturl");
			vpninfo->csd_preurl = strdup(vpninfo->urlpath);
		}
	}
	if (vpninfo->csd_token && vpninfo->csd_ticket && vpninfo->csd_starturl && vpninfo->csd_waiturl) {
		/* First, redirect to the stuburl -- we'll need to fetch and run that */
		vpninfo->redirect_url = strdup(vpninfo->csd_stuburl);

		/* AB: remove all cookies */
		for (opt = vpninfo->cookies; opt; opt = next) {
			next = opt->next;

			free(opt->option);
			free(opt->value);
			free(opt);
		}
		vpninfo->cookies = NULL;

		ret = 0;
		goto out;
	}
	if (!form->opts) {
		if (form->message)
			vpn_progress(vpninfo, PRG_INFO, "%s\n", form->message);
		if (form->error)
			vpn_progress(vpninfo, PRG_ERR, "%s\n", form->error);
		ret = -EPERM;
		goto out;
	}

	if (vpninfo->process_auth_form)
		ret = vpninfo->process_auth_form(vpninfo->cbdata, form);
	else {
		vpn_progress(vpninfo, PRG_ERR, _("No form handler; cannot authentiate."));
		ret = 1;
	}
	if (ret)
		goto out;

	ret = append_form_opts(vpninfo, form, request_body, req_len);
	if (!ret) {
		*method = "POST";
		*request_body_type = "application/x-www-form-urlencoded";
	}
 out:
	xmlFreeDoc(xml_doc);
	while (form->opts) {
		struct oc_form_opt *tmp = form->opts->next;
		if (form->opts->type == OC_FORM_OPT_TEXT ||
		    form->opts->type == OC_FORM_OPT_PASSWORD ||
		    form->opts->type == OC_FORM_OPT_HIDDEN)
			free(form->opts->value);
		else if (form->opts->type == OC_FORM_OPT_SELECT) {
			struct oc_form_opt_select *sel = (void *)form->opts;
			int i;

			for (i=0; i < sel->nr_choices; i++) {
				free(sel->choices[i].name);
				free(sel->choices[i].label);
				free(sel->choices[i].auth_type);
				free(sel->choices[i].override_name);
				free(sel->choices[i].override_label);
			}
		}
		free(form->opts->label);
		free(form->opts->name);
		free(form->opts);
		form->opts = tmp;
	}
	free(form->error);
	free(form->message);
	free(form->banner);
	free(form->auth_id);
	free(form->method);
	free(form->action);
	free(form);
	return ret;
}



