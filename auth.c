/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2009 Intel Corporation.
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

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include <openssl/err.h>
#include <openssl/ui.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "openconnect.h"

static int append_opt(char *body, int bodylen, char *opt, char *name)
{
	int len = strlen(body);

	if (len) {
		if (len >= bodylen - 1)
			return -ENOSPC;
		body[len++] = '&';
	}

	while (*opt) {
		if (isalnum(*opt)) {
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
		if (isalnum(*name)) {
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
		vpninfo->progress(vpninfo, PRG_ERR, "Form choice has no name\n");
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
			vpninfo->progress(vpninfo, PRG_TRACE, "name %s not input\n", xml_node->name);
			continue;
		}

		input_type = (char *)xmlGetProp(xml_node, (unsigned char *)"type");
		if (!input_type) {
			vpninfo->progress(vpninfo, PRG_INFO, "No input type in form\n");
			continue;
		}

		if (!strcmp(input_type, "submit") || !strcmp(input_type, "reset"))
			continue;

		input_name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
		if (!input_name) {
			vpninfo->progress(vpninfo, PRG_INFO, "No input name in form\n");
			continue;
		}
		input_label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");

		opt = calloc(1, sizeof(*opt));
		if (!opt)
			return -ENOMEM;

		if (!strcmp(input_type, "hidden")) {
			opt->type = OC_FORM_OPT_HIDDEN;
			opt->value = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		} else if (!strcmp(input_type, "text"))
			opt->type = OC_FORM_OPT_TEXT;
		else if (!strcmp(input_type, "password"))
			opt->type = OC_FORM_OPT_PASSWORD;
		else {
			vpninfo->progress(vpninfo, PRG_INFO,
					  "Unknown input type %s in form\n",
					  input_type);
			free(opt);
			continue;
		}

		opt->name = input_name;
		opt->label = input_label;

		p = &form->opts;
		while (*p)
			p = &(*p)->next;

		*p = opt;
	}

	vpninfo->progress(vpninfo, PRG_TRACE, "Fixed options give %s\n", body);

	return 0;
}

static int process_auth_form(struct openconnect_info *vpninfo,
			     struct oc_auth_form *form);

/* Return value:
 *  < 0, on error
 *  = 0, when form parsed and POST required
 *  = 1, when response was cancelled by user
 *  = 2, when form indicates that login was already successful
 */
int parse_xml_response(struct openconnect_info *vpninfo, char *response,
		       char *request_body, int req_len)
{
	struct oc_auth_form *form;
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	int ret;

	form = calloc(1, sizeof(*form));
	if (!form)
		return -ENOMEM;

	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL, 0);
	if (!xml_doc) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to parse server response\n");
		vpninfo->progress(vpninfo, PRG_TRACE, "Response was:%s\n", response);
		free(form);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	if (xml_node->type != XML_ELEMENT_NODE || strcmp((char *)xml_node->name, "auth")) {
		vpninfo->progress(vpninfo, PRG_ERR, "XML response has no \"auth\" root node\n");
		ret = -EINVAL;
		goto out;
	}

	form->auth_id = (char *)xmlGetProp(xml_node, (unsigned char *)"id");
	if (!strcmp(form->auth_id, "success")) {
		ret = 2;
		goto out;
	}

	if (vpninfo->nopasswd) {
		vpninfo->progress(vpninfo, PRG_ERR, "Asked for password but '--no-passwd' set\n");
		ret = -EPERM;
		goto out;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "banner")) {
			form->banner = (char *)xmlNodeGetContent(xml_node);
			if (form->banner && !form->banner[0])
				form->banner = NULL;
		} else if (!strcmp((char *)xml_node->name, "message")) {
			form->message = (char *)xmlNodeGetContent(xml_node);
			if (form->message && !form->message[0])
				form->message = NULL;
		} else if (!strcmp((char *)xml_node->name, "error")) {
			form->error = (char *)xmlNodeGetContent(xml_node);
			if (form->error && !form->error[0])
				form->error = NULL;
		}
		else if (!strcmp((char *)xml_node->name, "form")) {

			form->method = (char *)xmlGetProp(xml_node, (unsigned char *)"method");
			form->action = (char *)xmlGetProp(xml_node, (unsigned char *)"action");
			if (!form->method || !form->action || 
			    strcasecmp(form->method, "POST") || form->action[0] != '/') {
				vpninfo->progress(vpninfo, PRG_ERR,
						  "Cannot handle form method='%s', action='%s'\n",
						  form->method, form->action);
				ret = -EINVAL;
				goto out;
			}
			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup(form->action+1);

			ret = parse_form(vpninfo, form, xml_node, request_body, req_len);
			if (ret < 0)
				goto out;
		}
	}

	if (!form->opts) {
		if (form->message)
			vpninfo->progress(vpninfo, PRG_INFO, "%s\n", form->message);
		if (form->error)
			vpninfo->progress(vpninfo, PRG_ERR, "%s\n", form->error);
		return -EPERM;
	}

	if (vpninfo->process_auth_form)
		ret = vpninfo->process_auth_form(vpninfo, form);
	else
		ret = process_auth_form(vpninfo, form);
	if (ret)
		goto out;

	ret = append_form_opts(vpninfo, form, request_body, req_len);
 out:
	xmlFreeDoc(xml_doc);
	while (form->opts) {
		struct oc_form_opt *tmp = form->opts->next;
		if (form->opts->type == OC_FORM_OPT_TEXT ||
		    form->opts->type == OC_FORM_OPT_PASSWORD)
			free(form->opts->value);
		free(form->opts);
		form->opts = tmp;
	}
	free(form);
	return ret;
}



/* Return value:
 *  < 0, on error
 *  = 0, when form was parsed and POST required
 *  = 1, when response was cancelled by user
 */
static int process_auth_form(struct openconnect_info *vpninfo,
			     struct oc_auth_form *form)
{
	UI *ui = UI_new();
	char banner_buf[1024], msg_buf[1024], err_buf[1024];
	char username[80], password[80], tpin[80], *passresult = password;
	char choice_prompt[1024], choice_resp[80];
	int ret = 0, is_securid = 0;
	struct oc_form_opt *opt, *pass_opt = NULL, *user_opt = NULL;
	struct oc_form_opt_select *select_opt = NULL;

	username[0] = 0;
	password[0] = 0;
	tpin[0] = 0;
	choice_resp[0] = 0;

	if (!strcmp(form->auth_id, "next_tokencode"))
		is_securid = 2;

	if (!ui) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to create UI\n");
		return -EINVAL;
	}
	if (form->banner) {
		banner_buf[1023] = 0;
		snprintf(banner_buf, 1023, "%s\n", form->banner);
		UI_add_info_string(ui, banner_buf);
	}
	if (form->error) {
		err_buf[1023] = 0;
		snprintf(err_buf, 1023, "%s\n", form->error);
		UI_add_error_string(ui, err_buf);
	}
	if (form->message) {
		msg_buf[1023] = 0;
		snprintf(msg_buf, 1023, "%s\n", form->message);
		UI_add_info_string(ui, msg_buf);
	}

	for (opt = form->opts; opt; opt = opt->next) {

		if (opt->type == OC_FORM_OPT_TEXT) {
			if (vpninfo->username &&
			    !strcmp(opt->name, "username")) {
				opt->value = strdup(vpninfo->username);
				if (!opt->value)
					return -ENOMEM;
			} else
				user_opt = opt;
		} else if (opt->type == OC_FORM_OPT_PASSWORD) {
			if (vpninfo->password &&
			    !strcmp(opt->name, "password")) {
				opt->value = strdup(vpninfo->password);
				if (!opt->value)
					return -ENOMEM;
			} else
				pass_opt = opt;
		} else if (opt->type == OC_FORM_OPT_SELECT) {
			struct oc_choice *choice = NULL;
			int i;

			select_opt = (void *)opt;

			if (!select_opt->nr_choices)
				continue;

			if (vpninfo->authgroup &&
			    !strcmp(opt->name, "group_list")) {
				for (i = 0; i < select_opt->nr_choices; i++) {
					choice = &select_opt->choices[i];

					if (!strcmp(vpninfo->authgroup,
						    choice->label)) {
						opt->value = choice->name;
						break;
					}
				}
				if (!opt->value)
					vpninfo->progress(vpninfo, PRG_ERR,
							  "Auth choice \"%s\" not available\n",
							  vpninfo->authgroup);
			}
			if (!opt->value && select_opt->nr_choices == 1) {
				choice = &select_opt->choices[0];
				opt->value = choice->name;
			}
			if (opt->value) {
				if (!strcmp(choice->label, "SecureID"))
					is_securid = 1;

				select_opt = NULL;
				continue;
			}
			snprintf(choice_prompt, 1023, "%s [", opt->label);
			for (i = 0; i < select_opt->nr_choices; i++) {
				choice = &select_opt->choices[i];
				if (i)
					strncat(choice_prompt, "|", 1023 - strlen(choice_prompt));

				strncat(choice_prompt, choice->label, 1023 - strlen(choice_prompt));
			}
			strncat(choice_prompt, "]:", 1023 - strlen(choice_prompt));

			UI_add_input_string(ui, choice_prompt, UI_INPUT_FLAG_ECHO, choice_resp, 1, 80);
		}
	}

	if (!user_opt && !pass_opt && !select_opt)
		return 0;

        if (user_opt)
		UI_add_input_string(ui, user_opt->label, UI_INPUT_FLAG_ECHO, username, 1, 80);

	/* This isn't ideal, because we the user could take an arbitrary length
	   of time to enter the PIN, and we should use a tokencode generated
	   _after_ they enter the PIN, not before. Once we have proper tokencode
	   generation rather than evil script hacks, we can look at improving it. */
	if (is_securid) {
		/*
		 * If first tokencode being requested, try to generate them.
		 * We generate the 'next tokencode' here too, in case it's needed.
		 */
		if (is_securid == 1) {
			/* Forget any old tokencodes which evidently failed */
			vpninfo->sid_tokencode[0] = vpninfo->sid_nexttokencode[0] = 0;
			generate_securid_tokencodes(vpninfo);
		}

		/* If we couldn't generate them, we'll have to ask the user */
		if (!vpninfo->sid_tokencode[0])
			UI_add_input_string(ui, "SecurID code:",
					    UI_INPUT_FLAG_ECHO, password, 1, 9);

		/* We need the PIN only the first time, if we already have the
		   'next tokencode' -- we'll mangle the PIN in immediately.
		   Or both times if we're asking the user for tokencodes. */
		if (is_securid == 1 || !vpninfo->sid_tokencode[0])
			UI_add_input_string(ui, "SecurID PIN:", 0, tpin, 0, 9);
	} else if (pass_opt) {
		/* No echo */
		UI_add_input_string(ui, pass_opt->label, 0, password, 1, 80);
	}

	switch (UI_process(ui)) {
	case -2:
		/* cancelled */
		return 1;
	case -1:
		/* error */
		vpninfo->progress(vpninfo, PRG_ERR, "Invalid inputs\n");
		return -EINVAL;
	}

	if (select_opt) {
		struct oc_choice *choice = NULL;
		int i;

		for (i = 0; i < select_opt->nr_choices; i++) {
			choice = &select_opt->choices[i];

			if (!strcmp(choice_resp, choice->label)) {
				select_opt->form.value = choice->name;
				break;
			}
		}
		if (!select_opt->form.value) {
			vpninfo->progress(vpninfo, PRG_ERR,
					  "Auth choice \"%s\" not valid\n",
					  choice_resp);
			return -EINVAL;
		}
	}

	if (user_opt) {
		user_opt->value = strdup(vpninfo->username?:username);
		if (!user_opt->value)
			return -ENOMEM;
	}
	if (is_securid == 1 && vpninfo->sid_tokencode[0]) {
		/* First token request; mangle pin into _both_ first and next
		   token code */
		int ret = add_securid_pin(vpninfo->sid_tokencode, tpin);
		if (ret < 0)
			ret = add_securid_pin(vpninfo->sid_nexttokencode, tpin);
		if (ret < 0)
			return -EINVAL;
		passresult = vpninfo->sid_tokencode;
	} else if (is_securid == 2 && vpninfo->sid_nexttokencode[0]) {
		passresult = vpninfo->sid_nexttokencode;
	} else if (is_securid && tpin[0]) {
		ret = add_securid_pin(password, tpin);
		if (ret < 0)
			return -EINVAL;
	}

	if (pass_opt) {
		pass_opt->value = strdup(passresult);
		if (!pass_opt)
			return -ENOMEM;
	}

	if (vpninfo->password) {
		free(vpninfo->password);
		vpninfo->password = NULL;
	}

	return 0;
}
