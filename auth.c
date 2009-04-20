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

	while (*name) {
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

/*
 * Maybe we should offer this choice to the user. So far we've only
 * ever seen it offer bogus choices though -- between certificate and
 * password authentication, when the former has already failed.
 * So we just accept the first option with an auth-type property.
 */

static int parse_auth_choice(struct openconnect_info *vpninfo,
			     xmlNode *xml_node, char *body, int bodylen,
			     char **user_prompt, char **pass_prompt, int *is_securid)
{
	char *form_name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");

	if (!form_name) {
		vpninfo->progress(vpninfo, PRG_ERR, "Form choice has no name\n");
		return -EINVAL;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		char *authtype, *form_id, *override_name, *override_label, *auth_content;
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp((char *)xml_node->name, "option"))
			continue;

		form_id = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		authtype = (char *)xmlGetProp(xml_node, (unsigned char *)"auth-type");
		override_name = (char *)xmlGetProp(xml_node, (unsigned char *)"override-name");
		override_label = (char *)xmlGetProp(xml_node, (unsigned char *)"override-label");
		if (!form_id)
			continue;
		if (authtype && !strcmp(authtype, "sdi-via-proxy")) {
			char *content = (char *)xmlNodeGetContent(xml_node);
			vpninfo->progress(vpninfo, PRG_ERR, "Unrecognised auth type %s, label '%s'\n",
					  authtype, content);
			/* But continue anyway... */
		}
		vpninfo->progress(vpninfo, PRG_TRACE, "choosing %s %s\n", form_name, form_id);
		append_opt(body, bodylen, form_name, form_id);

		if (override_name && override_label) {
			if (!strcmp(override_name, "username"))
				*user_prompt = override_label;
			else if (!strcmp(override_name, "password"))
				*pass_prompt = override_label;
		}
		auth_content = (char *)xmlNodeGetContent(xml_node);
		if (auth_content && (!strcasecmp(auth_content, "SecureID") ||
				     !strcasecmp(auth_content, "SecurID")))
			*is_securid = 1;

		return 0;
	}
	vpninfo->progress(vpninfo, PRG_ERR, "Didn't find appropriate auth-type choice\n");
	/* Not necessarily an error -- sometimes there are none */
	return 0;
}

/* Return value:
 *  < 0, on error
 *  = 0, when form was cancelled
 *  = 1, when form was parsed
 */
static int parse_form(struct openconnect_info *vpninfo, char *auth_id,
		      char *form_message, char *form_error, xmlNode *xml_node,
		      char *body, int bodylen)
{
	UI *ui = UI_new();
	char msg_buf[1024], err_buf[1024];
	char username[80], password[80], tpin[80], *passresult = password;
	int ret, is_securid = 0;
	char *user_form_prompt = NULL;
	char *user_form_id = NULL;
	char *pass_form_prompt = NULL;
	char *pass_form_id = NULL;

	username[0] = 0;
	password[0] = 0;
	tpin[0] = 0;

	if (!strcmp(auth_id, "next_tokencode"))
		is_securid = 2;

	if (!ui) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to create UI\n");
		return -EINVAL;
	}
	if (form_error) {
		err_buf[1023] = 0;
		snprintf(err_buf, 1023, "%s\n", form_error);
		UI_add_error_string(ui, err_buf);
	}
	if (form_message) {
		msg_buf[1023] = 0;
		snprintf(msg_buf, 1023, "%s\n", form_message);
		UI_add_info_string(ui, msg_buf);
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		char *input_type, *input_name, *input_label;

		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "select")) {
			if (parse_auth_choice(vpninfo, xml_node, body, bodylen,
					      &user_form_prompt, &pass_form_prompt,
					      &is_securid))
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

		input_name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
		if (!input_name) {
			vpninfo->progress(vpninfo, PRG_INFO, "No input name in form\n");
			continue;
		}
		if (!strcmp(input_type, "hidden")) {
			char *value = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
			if (!value) {
				vpninfo->progress(vpninfo, PRG_INFO,
						  "No value for hidden input %s\n",
						  input_name);
				continue;
			}

			/* Add this to the request buffer directly */
			if (append_opt(body, bodylen, input_name, value)) {
				body[0] = 0;
				return -1;
			}
			continue;
		}

		input_label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");

		if (!strcmp(input_type, "text")) {
			user_form_prompt = input_label ?: "Username:";
			user_form_id = input_name;
		} else if (!strcmp(input_type, "password")) {
			pass_form_prompt = input_label ?: "Password:";
			pass_form_id = input_name;
		}
	}

	vpninfo->progress(vpninfo, PRG_TRACE, "Fixed options give %s\n", body);

	if (user_form_id && !vpninfo->username)
		UI_add_input_string(ui, user_form_prompt, UI_INPUT_FLAG_ECHO, username, 1, 80);


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
			UI_add_input_string(ui, pass_form_prompt,
					    UI_INPUT_FLAG_ECHO, password, 1, 9);

		/* We need the PIN only the first time, if we already have the
		   'next tokencode' -- we'll mangle the PIN in immediately.
		   Or both times if we're asking the user for tokencodes. */
		if (is_securid == 1 || !vpninfo->sid_tokencode[0])
			UI_add_input_string(ui, "SecurID PIN:", 0, tpin, 0, 9);
	} else if (!vpninfo->password) {
		/* No echo */
		UI_add_input_string(ui, pass_form_prompt, 0, password, 1, 80);
	}

	switch (UI_process(ui)) {
	case -2:
		/* cancelled */
		return 0;
	case -1:
		/* error */
		vpninfo->progress(vpninfo, PRG_ERR, "Invalid inputs\n");
		return -EINVAL;
	}

	if (user_form_id)
		append_opt(body, bodylen, user_form_id,
			   vpninfo->username ?: username);

	if (is_securid == 1 && vpninfo->sid_tokencode[0]) {
		/* First token request; mangle pin into _both_ first and next
		   token code */
		int ret = add_securid_pin(vpninfo->sid_tokencode, tpin);
		if (ret < 0)
			ret = add_securid_pin(vpninfo->sid_nexttokencode, tpin);
		if (ret < 0)
			return -1;
		passresult = vpninfo->sid_tokencode;
	} else if (is_securid == 2 && vpninfo->sid_nexttokencode[0]) {
		passresult = vpninfo->sid_nexttokencode;
	} else if (is_securid && tpin[0]) {
		ret = add_securid_pin(password, tpin);
		if (ret < 0)
			return -1;
	} else if (vpninfo->password)
		passresult = vpninfo->password;

	append_opt(body, bodylen, pass_form_id, passresult);

	if (vpninfo->password) {
		free(vpninfo->password);
		vpninfo->password = NULL;
	}

	return 1;
}

/* Return value:
 *  < 0, on error
 *  = 0,
 *  = 1, when response was parsed
 *  = 2, when response was cancelled
 */
int parse_xml_response(struct openconnect_info *vpninfo, char *response,
		       char *request_body, int req_len)
{
	char *form_message, *form_error, *auth_id;
	xmlDocPtr xml_doc;
	xmlNode *xml_node;

	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL, 0);
	if (!xml_doc) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to parse server response\n");
		vpninfo->progress(vpninfo, PRG_TRACE, "Response was:%s\n", response);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	if (xml_node->type != XML_ELEMENT_NODE ||
	    strcmp((char *)xml_node->name, "auth")) {
		vpninfo->progress(vpninfo, PRG_ERR, "XML response has no \"auth\" root node\n");
		xmlFreeDoc(xml_doc);
		return -EINVAL;
	}

	auth_id = (char *)xmlGetProp(xml_node, (unsigned char *)"id");
	if (!strcmp(auth_id, "success")) {
		xmlFreeDoc(xml_doc);
		return 0;
	}

	if (vpninfo->nopasswd) {
		vpninfo->progress(vpninfo, PRG_ERR, "Asked for password but '--no-passwd' set\n");
		return -EPERM;
	}

	form_message = form_error = NULL;
	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "message"))
			form_message = (char *)xmlNodeGetContent(xml_node);
		else if (!strcmp((char *)xml_node->name, "error")) {
			form_error = (char *)xmlNodeGetContent(xml_node);
		} else if (!strcmp((char *)xml_node->name, "form")) {
			char *form_method, *form_action;
			int ret;

			form_method = (char *)xmlGetProp(xml_node, (unsigned char *)"method");
			form_action = (char *)xmlGetProp(xml_node, (unsigned char *)"action");
			if (strcasecmp(form_method, "POST") || form_action[0] != '/') {
				vpninfo->progress(vpninfo, PRG_ERR, "Cannot handle form method='%s', action='%s'\n",
						  form_method, form_action);
				xmlFreeDoc(xml_doc);
				return -EINVAL;
			}
			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup(form_action+1);

			ret = parse_form(vpninfo, auth_id, form_message,
					 form_error, xml_node, request_body,
					 req_len);
			if (ret < 0) {
				/* fail */
				xmlFreeDoc(xml_doc);
				return -EINVAL;
			} else if (ret == 0)  {
				/* cancel */
				return 2;
			}

			/* Let the caller know there's a form to be submitted */
			return 1;
		}
	}

	xmlFreeDoc(xml_doc);

	vpninfo->progress(vpninfo, PRG_ERR, "Response neither indicated success nor requested input\n");
	vpninfo->progress(vpninfo, PRG_ERR, "Response was:\n%s\n", response);
	return -EINVAL;
}
