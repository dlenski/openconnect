/*
 * Open AnyConnect (SSL + DTLS) client
 *
 * © 2008 David Woodhouse <dwmw2@infradead.org>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "anyconnect.h"

/*
 * We didn't really want to have to do this for ourselves -- one might have 
 * thought that it would be available in a library somewhere. But neither
 * cURL nor Neon have reliable cross-platform ways of either using a cert
 * from the TPM, or just reading from / writing to a transport which is
 * provided by their caller.
 */

int process_http_response(struct anyconnect_info *vpninfo, int *result,
			  int (*header_cb)(struct anyconnect_info *, char *, char *),
			  char *body, int buf_len)
{
	char buf[65536];
	int bodylen = 0;
	int done = 0;
	int http10 = 0, closeconn = 0;
	int i;

	if (my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)) < 0) {
		fprintf(stderr, "Error fetching HTTPS response\n");
		exit(1);
	}

 cont:
	if (!strncmp(buf, "HTTP/1.0 ", 9)) {
		http10 = 1;
		closeconn = 1;
	}

	if ((!http10 && strncmp(buf, "HTTP/1.1 ", 9)) || !(*result = atoi(buf+9))) {
		fprintf(stderr, "Failed to parse HTTP response '%s'\n", buf);
		return -EINVAL;
	}

	if (verbose || *result == 100)
		printf("Got HTTP response: %s\n", buf);

	/* Eat headers... */
	while ((i=my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		char *colon;

		if (verbose)
			printf("%s\n", buf);
		if (i < 0) {
			fprintf(stderr, "Error processing HTTP response\n");
			return -EINVAL;
		}
		colon = strchr(buf, ':');
		if (!colon) {
			fprintf(stderr, "Ignoring unknown HTTP response line '%s'\n", buf);
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
				fprintf(stderr, "Response body too large for buffer (%d > %d)\n",
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
				fprintf(stderr, "Invalid cookie offered: %s\n", buf);
				return -EINVAL;
			}
			*(equals++) = 0;

			if (*equals) {
				new = malloc(sizeof(*new));
				if (!new) {
					fprintf(stderr, "No memory for allocating cookies\n");
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
				fprintf(stderr, "Unknown Transfer-Encoding: %s\n", colon);
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
				fprintf(stderr, "Error reading HTTP response body\n");
				return -EINVAL;
			}
			done += i;
		}
		goto fin;
	}

	/* ... else, chunked */
	while ((i=my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		int chunklen, lastchunk = 0;

		if (i < 0) {
			fprintf(stderr, "Error fetching chunk header\n");
			exit(1);
		}
		chunklen = strtol(buf, NULL, 16);
		if (!chunklen) {
			lastchunk = 1;
			goto skip;
		}
		if (chunklen + done > buf_len) {
			fprintf(stderr, "Response body too large for buffer (%d > %d)\n",
				chunklen + done, buf_len);
			return -EINVAL;
		}
		while (chunklen) {
			i = SSL_read(vpninfo->https_ssl, body + done, chunklen);
			if (i < 0) {
				fprintf(stderr, "Error reading HTTP response body\n");
				return -EINVAL;
			}
			chunklen -= i;
			done += i;
		}
	skip:
		if ((i=my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
			if (i < 0) {
				fprintf(stderr, "Error fetching HTTP response body\n");
			} else {
				fprintf(stderr, "Error in chunked decoding. Expected '', got: '%s'",
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

int append_opt(char *body, int bodylen, char *opt, char *name)
{
	int len = strlen(body);

	/* FIXME: len handling. Escaping of chars other than '_' */
	if (len && len < bodylen - 1)
		body[len++] = '&';

	while (*opt && len < bodylen - 1) {
		if (*opt == '_') {
			body[len++] = '%';
			body[len++] = '5';
			body[len++] = 'F';
		} else
			body[len++] = *opt;
		opt++;
	}
	body[len++] = '=';

	while (*name && len < bodylen - 1) {
		if (*name == '_') {
			body[len++] = '%';
			body[len++] = '5';
			body[len++] = 'F';
		} else
			body[len++] = *name;
		name++;
	}
	body[len] = 0;

	return 0;
}

int parse_auth_choice(struct anyconnect_info *vpninfo, xmlNode *xml_node,
		      char *body, int bodylen)
{
	char *form_name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");

	if (!form_name) {
		fprintf(stderr, "Form choice has no name\n");
		return -EINVAL;
	}
	
	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		char *authtype, *form_id;
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp((char *)xml_node->name, "option"))
			continue;

		form_id = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		authtype = (char *)xmlGetProp(xml_node, (unsigned char *)"auth-type");
		if (!form_id || !authtype)
			continue;
		if (strcmp(authtype, "sdi-via-proxy")) {
			char *content = (char *)xmlNodeGetContent(xml_node);
			fprintf(stderr, "Unrecognised auth type %s, label '%s'\n", authtype, content);
		}
		printf("appending %s %s\n", form_name, form_id);
		append_opt(body, bodylen, form_name, form_id);
		return 0;
	}
	fprintf(stderr, "Didn't find appropriate auth-type choice\n");
	return -EINVAL;
}

int parse_form(struct anyconnect_info *vpninfo, char *form_message, char *form_error,
	       xmlNode *xml_node, char *body, int bodylen)
{
	UI *ui = UI_new();
	char msg_buf[1024], err_buf[1024];
	char username[80], token[80];
	int ret;
	char *user_form_id = NULL;
	char *pass_form_id = NULL;

	username[0] = 0;
	token[0] = 0;

	if (!ui) {
		fprintf(stderr, "Failed to create UI\n");
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
		char *input_type;
		char *input_name;

		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "select")) {
			if (parse_auth_choice(vpninfo, xml_node, body, bodylen))
				return -EINVAL;
			continue;
		}
		if (strcmp((char *)xml_node->name, "input")) {
			printf("name %s not input\n", xml_node->name);
			continue;
		}

		input_type = (char *)xmlGetProp(xml_node, (unsigned char *)"type");
		if (!input_type) {
			printf("No input type\n");
			continue;
		}

		input_name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
		if (!input_name) {
			printf("No input name\n");
			continue;
		}

		if (!strcmp(input_type, "hidden")) {
			char *name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
			char *value = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
			if (!name || !value) {
				printf("name %s val %s\n", name, value);
				continue;
			}

			/* Add this to the request buffer directly */
			if (append_opt(body, bodylen, name, value)) {
				body[0] = 0;
				return -1;
			}
			continue;
		}
		if (!strcmp(input_type, "text"))
			user_form_id = input_name;
		else if (!strcmp(input_type, "password"))
			pass_form_id = input_name;
	}
			 
	printf("Fixed options give %s\n", body);

	if (user_form_id && !vpninfo->username)
		UI_add_input_string(ui, "Enter username: ", UI_INPUT_FLAG_ECHO, username, 1, 80);
	UI_add_input_string(ui, "Enter SecurID token: ", UI_INPUT_FLAG_ECHO, token, 1, 80);

	ret = UI_process(ui);
	if (ret) {
		fprintf(stderr, "Invalid inputs\n");
		return -EINVAL;
	}
	if (user_form_id) {
		if (!vpninfo->username)
			vpninfo->username = strdup(username);
		append_opt(body, bodylen, user_form_id, vpninfo->username);
	}
	append_opt(body, bodylen, pass_form_id, token);

	return 0;
}

int parse_xml_response(struct anyconnect_info *vpninfo, char *response,
		       char *request_body, int req_len)
{
	char *form_message, *form_error;
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	int success = 0;

	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL, 0);
	if (!xml_doc) {
		fprintf(stderr, "Failed to parse server response\n");
		if (verbose)
			printf("Response was:%s\n", response);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	if (xml_node->type != XML_ELEMENT_NODE ||
	    strcmp((char *)xml_node->name, "auth")) {
		fprintf(stderr, "XML response has no \"auth\" root node\n");
		xmlFreeDoc(xml_doc);
		return -EINVAL;
	}

	form_message = form_error = NULL;
	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "message"))
			form_message = (char *)xmlNodeGetContent(xml_node);
		else if (!strcmp((char *)xml_node->name, "error")) {
			form_error = (char *)xmlNodeGetContent(xml_node);
			/* Login failure. Forget the username */
			if (vpninfo->username) {
				free(vpninfo->username);
				vpninfo->username = NULL;
			}
		} else if (!strcmp((char *)xml_node->name, "form")) {
			char *form_method, *form_action;
			form_method = (char *)xmlGetProp(xml_node, (unsigned char *)"method");
			form_action = (char *)xmlGetProp(xml_node, (unsigned char *)"action");
			if (strcasecmp(form_method, "POST")) {
				fprintf(stderr, "Cannot handle form method '%s'\n",
					form_method);
				xmlFreeDoc(xml_doc);
				return -EINVAL;
			}
			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup(form_action);
			
			if (parse_form(vpninfo, form_message, form_error, xml_node, request_body, req_len)) {
				xmlFreeDoc(xml_doc);
				return -EINVAL;
			}

			/* Let the caller know there's a form to be submitted */
			return 1;
			
		} else if (!strcmp((char *)xml_node->name, "success")) {
			success = 1;
		}
	}

	xmlFreeDoc(xml_doc);
	if (success)
		return 0;

	fprintf(stderr, "Response neither indicated success nor requested input\n");
	printf("Response was:\n%s\n", response);
	return -EINVAL;
}

int obtain_cookie(struct anyconnect_info *vpninfo)
{
	struct vpn_option *opt, *next;
	char buf[65536];
	int result, buflen;
	char request_body[2048];
	char *request_body_type = NULL;
	char *method = "GET";

 retry:
	if (!vpninfo->https_ssl && open_https(vpninfo)) {
		fprintf(stderr, "Failed to open HTTPS connection to %s\n",
			vpninfo->hostname);
		exit(1);
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
	my_SSL_printf(vpninfo->https_ssl, "%s %s HTTP/1.1\r\n", method, vpninfo->urlpath);
	my_SSL_printf(vpninfo->https_ssl, "Host: %s\r\n", vpninfo->hostname);
	my_SSL_printf(vpninfo->https_ssl, "Accept: */*\r\n");
	my_SSL_printf(vpninfo->https_ssl, "Accept-Encoding: identity\r\n");
	if (vpninfo->cookies) {
		my_SSL_printf(vpninfo->https_ssl, "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			my_SSL_printf(vpninfo->https_ssl, "%s=%s%s", opt->option,
				      opt->value, opt->next?"; ":"\r\n");
	}
	if (request_body_type) {
		my_SSL_printf(vpninfo->https_ssl, "Content-Type: %s\r\n",
			      request_body_type);
		my_SSL_printf(vpninfo->https_ssl, "Content-Length: %zd\r\n",
			      strlen(request_body));
	}
	my_SSL_printf(vpninfo->https_ssl, "X-Transcend-Version: 1\r\n\r\n");
	if (request_body_type) {
		printf("Sending content: %s\n", request_body);
		SSL_write(vpninfo->https_ssl, request_body, strlen(request_body));
	}

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
			if (path)
				*(path++) = 0;
			free(vpninfo->urlpath);
			if (path && path[0])
				vpninfo->urlpath = strdup(path);
			else
				vpninfo->urlpath = strdup("/");
			free(vpninfo->hostname);
			vpninfo->hostname = strdup(host);
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
			SSL_free(vpninfo->https_ssl);
			vpninfo->https_ssl = NULL;

			for (opt = vpninfo->cookies; opt; opt = next) {
				next = opt->next;
				printf("Discard cookie %s\n", opt->option);
				free(opt->option);
				free(opt->value);
				free(opt);
			}
			vpninfo->cookies = NULL;
			goto retry;
		} else if (vpninfo->redirect_url[0] == '/') {
			/* Absolute redirect within same host */
			free(vpninfo->urlpath);
			vpninfo->urlpath = vpninfo->redirect_url;
			vpninfo->redirect_url = NULL;
			goto retry;
		} else {
			fprintf(stderr, "Relative redirect (to '%s') not supported\n",
				vpninfo->redirect_url);
			return -EINVAL;
		}
	}

	request_body[0] = 0;
	result = parse_xml_response(vpninfo, buf, request_body, sizeof(request_body));
	if (result > 0) {
		method = "POST";
		request_body_type = "application/x-www-form-urlencoded";
		goto retry;
	} else if (result < 0)
		return -EINVAL;

	for (opt = vpninfo->cookies; opt; opt = opt->next) {

		if (!strcmp(opt->option, "webvpn"))
			vpninfo->cookie = opt->value;
		else if (vpninfo->xmlconfig && !strcmp(opt->option, "webvpnc")) {
			char *amp = opt->value;
			
			while ((amp = strchr(amp, '&'))) {
				amp++;
				if (!strncmp(amp, "fh:", 3)) {
					if (strncasecmp(amp+3, vpninfo->xmlsha1,
							SHA_DIGEST_LENGTH * 2)) {
						/* FIXME. Obviously */
						printf("SHA1 changed; need new config\n");
						/* URL is $bu: + $fu: */
					} else if (verbose)
						printf("XML config SHA1 match\n");
				}
			}
		}
	}
	if (vpninfo->cookie) {
		printf("WebVPN cookie is %s\n", vpninfo->cookie);
		return 0;
	}

	return -1;
}
