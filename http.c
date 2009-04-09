/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008 Intel Corporation.
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "openconnect.h"

/*
 * We didn't really want to have to do this for ourselves -- one might have 
 * thought that it would be available in a library somewhere. But neither
 * cURL nor Neon have reliable cross-platform ways of either using a cert
 * from the TPM, or just reading from / writing to a transport which is
 * provided by their caller.
 */

static int process_http_response(struct openconnect_info *vpninfo, int *result,
				 int (*header_cb)(struct openconnect_info *, char *, char *),
				 char *body, int buf_len)
{
	char buf[65536];
	int bodylen = 0;
	int done = 0;
	int http10 = 0, closeconn = 0;
	int i;

	if (openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)) < 0) {
		vpninfo->progress(vpninfo, PRG_ERR, "Error fetching HTTPS response\n");
		return -EINVAL;
	}

 cont:
	if (!strncmp(buf, "HTTP/1.0 ", 9)) {
		http10 = 1;
		closeconn = 1;
	}

	if ((!http10 && strncmp(buf, "HTTP/1.1 ", 9)) || !(*result = atoi(buf+9))) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to parse HTTP response '%s'\n", buf);
		return -EINVAL;
	}

	vpninfo->progress(vpninfo, PRG_TRACE, "Got HTTP response: %s\n", buf);

	/* Eat headers... */
	while ((i=openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		char *colon;

		vpninfo->progress(vpninfo, PRG_TRACE, "%s\n", buf);

		if (i < 0) {
			vpninfo->progress(vpninfo, PRG_ERR, "Error processing HTTP response\n");
			return -EINVAL;
		}
		colon = strchr(buf, ':');
		if (!colon) {
			vpninfo->progress(vpninfo, PRG_ERR, "Ignoring unknown HTTP response line '%s'\n", buf);
			continue;
		}
		*(colon++) = 0;
		if (*colon == ' ')
			colon++;

		if (!strcmp(buf, "Connection") && !strcmp(colon, "Close"))
			closeconn = 1;

		if (!strcmp(buf, "Location")) {
			vpninfo->redirect_url = strdup(colon);
			if (!vpninfo->redirect_url)
				return -ENOMEM;
		}
		if (!strcmp(buf, "Content-Length")) {
			bodylen = atoi(colon);
			if (bodylen < 0 || bodylen > buf_len) {
				vpninfo->progress(vpninfo, PRG_ERR, "Response body too large for buffer (%d > %d)\n",
					bodylen, buf_len);
				return -EINVAL;
			}
		}
		if (!strcmp(buf, "Set-Cookie")) {
			struct vpn_option *new, **this;
			char *semicolon = strchr(colon, ';');
			char *equals = strchr(colon, '=');

			if (semicolon)
				*semicolon = 0;

			if (!equals) {
				vpninfo->progress(vpninfo, PRG_ERR, "Invalid cookie offered: %s\n", buf);
				return -EINVAL;
			}
			*(equals++) = 0;

			if (*equals) {
				new = malloc(sizeof(*new));
				if (!new) {
					vpninfo->progress(vpninfo, PRG_ERR, "No memory for allocating cookies\n");
					return -ENOMEM;
				}
				new->next = NULL;
				new->option = strdup(colon);
				new->value = strdup(equals);
			} else {
				/* Kill cookie; don't replace it */
				new = NULL;
			}
			for (this = &vpninfo->cookies; *this; this = &(*this)->next) {
				if (!strcmp(colon, (*this)->option)) {
					/* Replace existing cookie */
					if (new)
						new->next = (*this)->next;
					else
						new = (*this)->next;

					free((*this)->option);
					free((*this)->value);
					free(*this);
					*this = new;
					break;
				}
			}
			if (new && !*this) {
				*this = new;
				new->next = NULL;
			}
		}
		if (!strcmp(buf, "Transfer-Encoding")) {
			if (!strcmp(colon, "chunked"))
				bodylen = -1;
			else {
				vpninfo->progress(vpninfo, PRG_ERR, "Unknown Transfer-Encoding: %s\n", colon);
				return -EINVAL;
			}
		}
		if (header_cb && !strncmp(buf, "X-", 2))
			header_cb(vpninfo, buf, colon);
	}

	/* Handle 'HTTP/1.1 100 Continue'. Not that we should ever see it */
	if (*result == 100)
		goto cont;

	/* Now the body, if there is one */
	if (!bodylen)
		goto fin;

	if (http10) {
		/* HTTP 1.0 response. Just eat all we can. */
		while (1) {
			i = SSL_read(vpninfo->https_ssl, body + done, bodylen - done);
			if (i < 0)
				goto fin;
			done += i;
		}
	}
	/* If we were given Content-Length, it's nice and easy... */
	if (bodylen > 0) {
		while (done < bodylen) {
			i = SSL_read(vpninfo->https_ssl, body + done, bodylen - done);
			if (i < 0) {
				vpninfo->progress(vpninfo, PRG_ERR, "Error reading HTTP response body\n");
				return -EINVAL;
			}
			done += i;
		}
		goto fin;
	}

	/* ... else, chunked */
	while ((i=openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		int chunklen, lastchunk = 0;

		if (i < 0) {
			vpninfo->progress(vpninfo, PRG_ERR, "Error fetching chunk header\n");
			exit(1);
		}
		chunklen = strtol(buf, NULL, 16);
		if (!chunklen) {
			lastchunk = 1;
			goto skip;
		}
		if (chunklen + done > buf_len) {
			vpninfo->progress(vpninfo, PRG_ERR, "Response body too large for buffer (%d > %d)\n",
				chunklen + done, buf_len);
			return -EINVAL;
		}
		while (chunklen) {
			i = SSL_read(vpninfo->https_ssl, body + done, chunklen);
			if (i < 0) {
				vpninfo->progress(vpninfo, PRG_ERR, "Error reading HTTP response body\n");
				return -EINVAL;
			}
			chunklen -= i;
			done += i;
		}
	skip:
		if ((i=openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
			if (i < 0) {
				vpninfo->progress(vpninfo, PRG_ERR, "Error fetching HTTP response body\n");
			} else {
				vpninfo->progress(vpninfo, PRG_ERR, "Error in chunked decoding. Expected '', got: '%s'",
					buf);
			}
			return -EINVAL;
		}

		if (lastchunk) 
			break;
	}
 fin:
	if (closeconn) {
		SSL_free(vpninfo->https_ssl);
		vpninfo->https_ssl = NULL;
		close(vpninfo->ssl_fd);
		vpninfo->ssl_fd = -1;
	}
	body[done] = 0;
	return done;
}

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
		if (!form_id || !authtype)
			continue;
		if (strcmp(authtype, "sdi-via-proxy")) {
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
			user_form_prompt = input_label?:"Username:";
			user_form_id = input_name;
		} else if (!strcmp(input_type, "password")) {
			pass_form_prompt = input_label?:"Password:";
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
			   vpninfo->username?:username);

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
static int parse_xml_response(struct openconnect_info *vpninfo, char *response,
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

static int fetch_config(struct openconnect_info *vpninfo, char *fu, char *bu,
			char *server_sha1)
{
	struct vpn_option *opt;
	char buf[65536];
	int result, buflen;
	unsigned char local_sha1_bin[SHA_DIGEST_LENGTH];
	char local_sha1_ascii[(SHA_DIGEST_LENGTH * 2)+1];
	EVP_MD_CTX c;
	int i;

	sprintf(buf, "GET %s%s HTTP/1.1\r\n", fu, bu);
	sprintf(buf + strlen(buf), "Host: %s\r\n", vpninfo->hostname);
	sprintf(buf + strlen(buf),  "User-Agent: %s\r\n", vpninfo->useragent);
	sprintf(buf + strlen(buf),  "Accept: */*\r\n");
	sprintf(buf + strlen(buf),  "Accept-Encoding: identity\r\n");

	if (vpninfo->cookies) {
		sprintf(buf + strlen(buf),  "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			sprintf(buf + strlen(buf),  "%s=%s%s", opt->option,
				      opt->value, opt->next?"; ":"\r\n");
	}
	sprintf(buf + strlen(buf),  "X-Transcend-Version: 1\r\n\r\n");

	SSL_write(vpninfo->https_ssl, buf, strlen(buf));

	buflen = process_http_response(vpninfo, &result, NULL, buf, 65536);
	if (buflen < 0) {
		/* We'll already have complained about whatever offended us */
		return -EINVAL;
	}

	if (result != 200)
		return -EINVAL;

	
	EVP_MD_CTX_init(&c);
	EVP_Digest(buf, buflen, local_sha1_bin, NULL, EVP_sha1(), NULL);
	EVP_MD_CTX_cleanup(&c);

	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(&local_sha1_ascii[i*2], "%02x", local_sha1_bin[i]);

	if (strcasecmp(server_sha1, local_sha1_ascii)) {
		vpninfo->progress(vpninfo, PRG_ERR, "Downloaded config file did not match intended SHA1\n");
		return -EINVAL;
	}

	return vpninfo->write_new_config(vpninfo, buf, buflen);
}

/* Return value:
 *  < 0, on error
 *  = 0, no cookie (user cancel)
 *  = 1, obtained cookie
 */
int openconnect_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct vpn_option *opt, *next;
	char buf[65536];
	int result, buflen;
	char request_body[2048];
	char *request_body_type = NULL;
	char *method = "GET";

 retry:
	if (!vpninfo->https_ssl && openconnect_open_https(vpninfo)) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to open HTTPS connection to %s\n",
			vpninfo->hostname);
		return -EINVAL;
	}

	/*
	 * It would be nice to use cURL for this, but we really need to guarantee 
	 * that we'll be using OpenSSL (for the TPM stuff), and it doesn't seem 
	 * to have any way to let us provide our own socket read/write functions.
	 * We can only provide a socket _open_ function. Which would require having
	 * a socketpair() and servicing the "other" end of it. 
	 *
	 * So we process the HTTP for ourselves...
	 */
	sprintf(buf, "%s /%s HTTP/1.1\r\n", method, vpninfo->urlpath?:"");
	sprintf(buf + strlen(buf), "Host: %s\r\n", vpninfo->hostname);
	sprintf(buf + strlen(buf),  "User-Agent: %s\r\n", vpninfo->useragent);
	sprintf(buf + strlen(buf),  "Accept: */*\r\n");
	sprintf(buf + strlen(buf),  "Accept-Encoding: identity\r\n");

	if (vpninfo->cookies) {
		sprintf(buf + strlen(buf),  "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			sprintf(buf + strlen(buf),  "%s=%s%s", opt->option,
				      opt->value, opt->next?"; ":"\r\n");
	}
	if (request_body_type) {
		sprintf(buf + strlen(buf),  "Content-Type: %s\r\n",
			      request_body_type);
		sprintf(buf + strlen(buf),  "Content-Length: %zd\r\n",
			      strlen(request_body));
	}
	sprintf(buf + strlen(buf),  "X-Transcend-Version: 1\r\n\r\n");
	if (request_body_type)
		sprintf(buf + strlen(buf), "%s", request_body);

	vpninfo->progress(vpninfo, PRG_INFO, "%s %s/%s\n", method, vpninfo->hostname, vpninfo->urlpath?:"");

	SSL_write(vpninfo->https_ssl, buf, strlen(buf));

	buflen = process_http_response(vpninfo, &result, NULL, buf, 65536);
	if (buflen < 0) {
		/* We'll already have complained about whatever offended us */
		exit(1);
	}

	if (result != 200 && vpninfo->redirect_url) {
		if (!strncmp(vpninfo->redirect_url, "https://", 8)) {
			/* New host. Tear down the existing connection and make a new one */
			char *host = vpninfo->redirect_url + 8;
			char *path = strchr(host, '/');

			free(vpninfo->urlpath);
			if (path) {
				*(path++) = 0;
				vpninfo->urlpath = strdup(path);
			} else
				vpninfo->urlpath = NULL;

			if (strcmp(vpninfo->hostname, host)) {
				free(vpninfo->hostname);
				vpninfo->hostname = strdup(host);

				/* Kill the existing connection, and a new one will happen */
				SSL_free(vpninfo->https_ssl);
				vpninfo->https_ssl = NULL;
				close(vpninfo->ssl_fd);
				vpninfo->ssl_fd = -1;

				for (opt = vpninfo->cookies; opt; opt = next) {
					next = opt->next;

					free(opt->option);
					free(opt->value);
					free(opt);
				}
				vpninfo->cookies = NULL;
			}
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;

			goto retry;
		} else if (vpninfo->redirect_url[0] == '/') {
			/* Absolute redirect within same host */
			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup(vpninfo->redirect_url + 1);
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
			goto retry;
		} else {
			vpninfo->progress(vpninfo, PRG_ERR, "Relative redirect (to '%s') not supported\n",
				vpninfo->redirect_url);
			return -EINVAL;
		}
	}

	request_body[0] = 0;
	result = parse_xml_response(vpninfo, buf, request_body, sizeof(request_body));
	if (result == 2) {
		/* cancel */
		return 0;
	} else if (result == 1) {
		method = "POST";
		request_body_type = "application/x-www-form-urlencoded";
		if (0) {
			/* This doesn't make the second form work any better */
			SSL_free(vpninfo->https_ssl);
			vpninfo->https_ssl = NULL;
			close(vpninfo->ssl_fd);
			vpninfo->ssl_fd = -1;
		}
		goto retry;
	} else if (result < 0)
		return -EINVAL;

	for (opt = vpninfo->cookies; opt; opt = opt->next) {

		if (!strcmp(opt->option, "webvpn"))
			vpninfo->cookie = opt->value;
		else if (vpninfo->write_new_config && !strcmp(opt->option, "webvpnc")) {
			char *tok = opt->value;
			char *bu = NULL, *fu = NULL, *sha = NULL;

			do {
				if (tok != opt->value)
					*(tok++) = 0;

				if (!strncmp(tok, "bu:", 3))
					bu = tok + 3;
				else if (!strncmp(tok, "fu:", 3))
					fu = tok + 3;
				else if (!strncmp(tok, "fh:", 3)) {
					if (!strncasecmp(tok+3, vpninfo->xmlsha1,
							 SHA_DIGEST_LENGTH * 2))
						break;
					sha = tok + 3;
				}
			} while ((tok = strchr(tok, '&')));

			if (bu && fu && sha)
				fetch_config(vpninfo, bu, fu, sha);
		}
	}

	return 1;
}

char *openconnect_create_useragent(char *base)
{
	char *uagent = malloc(strlen(base) + 1 + strlen(openconnect_version));
	sprintf(uagent, "%s%s", base, openconnect_version);
	return uagent;
}
