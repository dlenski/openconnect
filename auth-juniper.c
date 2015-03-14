/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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

/*
 * Grateful thanks to Tiebing Zhang, who did much of the hard work
 * of analysing and decoding the protocol.
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif

#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

#include "openconnect-internal.h"

/* XX: This is actually a lot of duplication with the CSTP version. */
void oncp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	http_common_headers(vpninfo, buf);

	buf_append(buf, "Connection: close\r\n");
//	buf_append(buf, "Content-Length: 256\r\n");
	buf_append(buf, "NCP-Version: 3\r\n");
//	buf_append(buf, "Accept-Encoding: gzip\r\n");
}


static xmlNodePtr htmlnode_next(xmlNodePtr top, xmlNodePtr node)
{
	if (node->children)
		return node->children;

	while (!node->next) {
		node = node->parent;
		if (!node || node == top)
			return NULL;
	}
	return node->next;
}

static int oncp_can_gen_tokencode(struct openconnect_info *vpninfo,
				  struct oc_auth_form *form,
				  struct oc_form_opt *opt)
{
	if (vpninfo->token_mode == OC_TOKEN_MODE_NONE ||
	    vpninfo->token_bypassed)
		return -EINVAL;

	if (strcmp(form->auth_id, "frmDefender") &&
	    strcmp(form->auth_id, "frmNextToken"))
		return -EINVAL;

	return can_gen_tokencode(vpninfo, form, opt);
}


static int parse_input_node(struct openconnect_info *vpninfo, struct oc_auth_form *form,
			    xmlNodePtr node, const char *submit_button)
{
	char *type = (char *)xmlGetProp(node, (unsigned char *)"type");
	struct oc_form_opt **p = &form->opts;
	struct oc_form_opt *opt;
	int ret = 0;

	if (!type)
		return -EINVAL;

	opt = calloc(1, sizeof(*opt));
	if (!opt) {
		ret = -ENOMEM;
		goto out;
	}

	if (!strcasecmp(type, "hidden")) {
		opt->type = OC_FORM_OPT_HIDDEN;
		xmlnode_get_prop(node, "name", &opt->name);
		xmlnode_get_prop(node, "value", &opt->_value);
		/* XXX: Handle tz_offset / tz */
	} else if (!strcasecmp(type, "password")) {
		opt->type = OC_FORM_OPT_PASSWORD;
		xmlnode_get_prop(node, "name", &opt->name);
		if (asprintf(&opt->label, "%s:", opt->name) == -1) {
			ret = -ENOMEM;
			goto out;
		}
		if (!oncp_can_gen_tokencode(vpninfo, form, opt))
			opt->type = OC_FORM_OPT_TOKEN;
	} else if (!strcasecmp(type, "text")) {
		opt->type = OC_FORM_OPT_TEXT;
		xmlnode_get_prop(node, "name", &opt->name);
		if (asprintf(&opt->label, "%s:", opt->name) == -1) {
			ret = -ENOMEM;
			goto out;
		}
	} else if (!strcasecmp(type, "submit")) {
		xmlnode_get_prop(node, "name", &opt->name);
		if (!opt->name || strcmp(opt->name, submit_button)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Ignoring unknown form submit item '%s'\n"),
				     opt->name);
			ret = -EINVAL;
			goto out;
		}
		xmlnode_get_prop(node, "value", &opt->_value);
		opt->type = OC_FORM_OPT_HIDDEN;
	} else if (!strcasecmp(type, "checkbox")) {
		opt->type = OC_FORM_OPT_HIDDEN;
		xmlnode_get_prop(node, "name", &opt->name);
		xmlnode_get_prop(node, "value", &opt->_value);
	} else {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Ignoring unknown form input type '%s'\n"),
			     type);
		ret = -EINVAL;
		goto out;
	}

	/* Append to the existing list */
	while (*p) {
		if (!strcmp((*p)->name, opt->name)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Discarding duplicate option '%s'\n"),
				     opt->name);
			goto out;
		}
		p = &(*p)->next;
	}
	*p = opt;
 out:
	if (ret)
		free_opt(opt);
	free(type);
	return ret;
}

static int parse_select_node(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		     xmlNodePtr node)
{
	xmlNodePtr child;
	struct oc_form_opt_select *opt;
	struct oc_choice *choice;

	opt = calloc(1, sizeof(*opt));
	if (!opt)
		return -ENOMEM;

	xmlnode_get_prop(node, "name", &opt->form.name);
	opt->form.label = strdup(opt->form.name);
	opt->form.type = OC_FORM_OPT_SELECT;
	if (!strcmp(opt->form.name, "realm"))
		form->authgroup_opt = opt;

	for (child = node->children; child; child = child->next) {
		struct oc_choice **new_choices;
		if (!child->name || strcasecmp((const char *)child->name, "option"))
			continue;

		choice = calloc(1, sizeof(*choice));
		if (!choice)
			return -ENOMEM;

		xmlnode_get_prop(node, "name", &choice->name);
		choice->label = (char *)xmlNodeGetContent(child);
		choice->name = strdup(choice->label);
		new_choices = realloc(opt->choices, sizeof(opt->choices[0]) * (opt->nr_choices+1));
		if (!new_choices) {
			free_opt((void *)opt);
			free(choice);
			return -ENOMEM;
		}
		opt->choices = new_choices;
		opt->choices[opt->nr_choices++] = choice;
	}

	/* Prepend to the existing list */
	opt->form.next = form->opts;
	form->opts = &opt->form;
	return 0;
}

static struct oc_auth_form *parse_form_node(struct openconnect_info *vpninfo,
					    xmlNodePtr node, const char *submit_button)
{
	struct oc_auth_form *form = calloc(1, sizeof(*form));
	xmlNodePtr child;

	if (!form)
		return NULL;

	xmlnode_get_prop(node, "method", &form->method);
	xmlnode_get_prop(node, "action", &form->action);
	if (!form->method || strcasecmp(form->method, "POST") ||
	    !form->action || !form->action[0]) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Cannot handle form method='%s', action='%s'\n"),
			     form->method, form->action);
		free(form);
		return NULL;
	}
	xmlnode_get_prop(node, "name", &form->auth_id);
	form->banner = strdup(form->auth_id);

	for (child = htmlnode_next(node, node); child && child != node; child = htmlnode_next(node, child)) {
		if (!child->name)
			continue;

		if (!strcasecmp((char *)child->name, "input"))
			parse_input_node(vpninfo, form, child, submit_button);
		else if (!strcasecmp((char *)child->name, "select")) {
			parse_select_node(vpninfo, form, child);
			/* Skip its children */
			while (child->children)
				child = child->last;
		}
	}
	return form;
}

static int oncp_https_submit(struct openconnect_info *vpninfo,
			     struct oc_text_buf *req_buf, xmlDocPtr *doc)
{
	int ret;
	char *form_buf = NULL;
	struct oc_text_buf *url;

	if (req_buf && req_buf->pos)
		ret =do_https_request(vpninfo, "POST",
				      "application/x-www-form-urlencoded",
				      req_buf, &form_buf, 2);
	else
		ret = do_https_request(vpninfo, "GET", NULL, NULL,
				       &form_buf, 2);

	if (ret < 0)
		return ret;

	url = buf_alloc();
	buf_append(url, "https://%s", vpninfo->hostname);
	if (vpninfo->port != 443)
		buf_append(url, ":%d", vpninfo->port);
	buf_append(url, "/");
	if (vpninfo->urlpath)
		buf_append(url, "%s", vpninfo->urlpath);

	if (buf_error(url)) {
		free(form_buf);
		return buf_free(url);
	}

	*doc = htmlReadMemory(form_buf, ret, url->data, NULL,
			     HTML_PARSE_RECOVER|HTML_PARSE_NOERROR|HTML_PARSE_NOWARNING|HTML_PARSE_NONET);
	buf_free(url);
	free(form_buf);
	if (!*doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse HTML document\n"));
		return -EINVAL;
	}
	return 0;
}

static xmlNodePtr find_form_node(xmlDocPtr doc)
{
	xmlNodePtr root, node;

	for (root = node = xmlDocGetRootElement(doc); node; node = htmlnode_next(root, node)) {
		if (node->name && !strcasecmp((char *)node->name, "form"))
			return node;
	}
	return NULL;
}

static int check_cookie_success(struct openconnect_info *vpninfo)
{
	const char *dslast = NULL, *dsfirst = NULL, *dsurl = NULL, *dsid = NULL;
	struct oc_vpn_option *cookie;
	struct oc_text_buf *buf;

	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strcmp(cookie->option, "DSFirstAccess"))
			dsfirst = cookie->value;
		else if (!strcmp(cookie->option, "DSLastAccess"))
			dslast = cookie->value;
		else if (!strcmp(cookie->option, "DSID"))
			dsid = cookie->value;
		else if (!strcmp(cookie->option, "DSSignInUrl"))
			dsurl = cookie->value;
	}
	if (!dsid)
		return -ENOENT;

	buf = buf_alloc();
	if (vpninfo->tncc_fd != -1) {
		buf_append(buf, "setcookie\n");
		buf_append(buf, "Cookie=%s\n", dsid);
		if (buf_error(buf))
			return buf_free(buf);
		send(vpninfo->tncc_fd, buf->data, buf->pos, 0);
		buf_truncate(buf);
	}

	/* XXX: Do these need escaping? Could they theoreetically have semicolons in? */
	buf_append(buf, "DSID=%s", dsid);
	if (dsfirst)
		buf_append(buf, "; DSFirst=%s", dsfirst);
	if (dslast)
		buf_append(buf, "; DSLast=%s", dslast);
	if (dsurl)
		buf_append(buf, "; DSSignInUrl=%s", dsurl);
	if (buf_error(buf))
		return buf_free(buf);
	free(vpninfo->cookie);
	vpninfo->cookie = buf->data;
	buf->data = NULL;
	buf_free(buf);
	return 0;
}
#ifdef _WIN32
static int tncc_preauth(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("TNCC support not implemented yet on Windows\n"));
	return -EOPNOTSUPP;
}
#else
static int tncc_preauth(struct openconnect_info *vpninfo)
{
	int sockfd[2];
	pid_t pid;
	struct oc_text_buf *buf;
	struct oc_vpn_option *cookie;
	const char *dspreauth = NULL, *dssignin = "null";
	char recvbuf[1024], *p;
	int len;

	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strcmp(cookie->option, "DSPREAUTH"))
			dspreauth = cookie->value;
		else if (!strcmp(cookie->option, "DSSIGNIN"))
			dssignin = cookie->value;
	}
	if (!dspreauth) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No DSPREAUTH cookie; not attempting TNCC\n"));
		return -EINVAL;
	}

	buf = buf_alloc();
	buf_append(buf, "start\n");
	buf_append(buf, "IC=%s\n", vpninfo->hostname);
	buf_append(buf, "Cookie=%s\n", dspreauth);
	buf_append(buf, "DSSIGNIN=%s\n", dssignin);
	if (buf_error(buf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate memory for communication with TNCC\n"));
		return buf_free(buf);
	}
#ifdef SOCK_CLOEXEC
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockfd))
#endif
	{
		if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockfd)) {
			buf_free(buf);
			return -errno;
		}
		set_fd_cloexec(sockfd[0]);
		set_fd_cloexec(sockfd[1]);
	}
	pid = fork();
	if (pid == -1) {
		buf_free(buf);
		return -errno;
	}

	if (!pid) {
		int i;
		/* Fork again to detach grandchild */
		if (fork())
			exit(1);

		close(sockfd[1]);
		/* The duplicated fd does not have O_CLOEXEC */
		dup2(sockfd[0], 0);
		/* We really don't want anything going to stdout */
		dup2(1, 2);
		for (i = 3; i < 1024 ; i++)
			close(i);

		execl(vpninfo->csd_wrapper, vpninfo->csd_wrapper, vpninfo->hostname, NULL);
		fprintf(stderr, _("Failed to exec TNCC script %s: %s\n"),
			vpninfo->csd_wrapper, strerror(errno));
		exit(1);
	}
	waitpid(pid, NULL, 0);
	close(sockfd[0]);

	if (send(sockfd[1], buf->data, buf->pos, 0) != buf->pos) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to send start command to TNCC\n"));
		buf_free(buf);
		close(sockfd[1]);
		return -EIO;
	}
	buf_free(buf);
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Sent start; waiting for response from TNCC\n"));

	len = recv(sockfd[1], recvbuf, sizeof(recvbuf) - 1, 0);
	if (len < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read response from TNCC\n"));
		close(sockfd[1]);
		return -EIO;
	}

	recvbuf[len] = 0;

	p = strchr(recvbuf, '\n');
	if (!p) {
	invalid_response:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Received invalid response from TNCC\n"));
	print_response:
		vpn_progress(vpninfo, PRG_TRACE, _("TNCC response: -->\n%s\n<--\n"),
			     recvbuf);
		close(sockfd[1]);
		return -EINVAL;
	}
	*p = 0;
	if (strcmp(recvbuf, "200")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Received unsuccessful %s response from TNCC\n"),
			     recvbuf);
		goto print_response;
	}
	p = strchr(p + 1, '\n');
	if (!p)
		goto invalid_response;
	dspreauth = p + 1;
	p = strchr(p + 1, '\n');
	if (!p)
		goto invalid_response;
	*p = 0;
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Got new DSPREAUTH cookie from TNCC: %s\n"),
		     dspreauth);
	http_add_cookie(vpninfo, "DSPREAUTH", dspreauth, 1);
	vpninfo->tncc_fd = sockfd[1];
	return 0;
}
#endif

int oncp_obtain_cookie(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *resp_buf = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr node;
	struct oc_auth_form *form = NULL;
	char *form_id = NULL;
	int try_tncc = !!vpninfo->csd_wrapper;

	resp_buf = buf_alloc();
	if (buf_error(resp_buf))
		return -ENOMEM;

	while (1) {
		ret = oncp_https_submit(vpninfo, resp_buf, &doc);
		if (ret || !check_cookie_success(vpninfo))
			break;

		buf_truncate(resp_buf);

		node = find_form_node(doc);
		if (!node) {
			if (try_tncc) {
				try_tncc = 0;
				ret = tncc_preauth(vpninfo);
				if (ret)
					return ret;
				goto tncc_done;
			}
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to find or parse web form in login page\n"));
			ret = -EINVAL;
			break;
		}
		free(form_id);
		form_id = (char *)xmlGetProp(node, (unsigned char *)"name");
		if (!form_id) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Encountered form with no ID\n"));
			goto dump_form;
		} else if (!strcmp(form_id, "frmLogin")) {
			form = parse_form_node(vpninfo, node, "btnSubmit");
			if (!form) {
				ret = -EINVAL;
				break;
			}
		} else if (!strcmp(form_id, "frmDefender") ||
			   !strcmp(form_id, "frmNextToken")) {
			form = parse_form_node(vpninfo, node, "btnAction");
			if (!form) {
				ret = -EINVAL;
				break;
			}
		} else if (!strcmp(form_id, "frmConfirmation")) {
			form = parse_form_node(vpninfo, node, "btnContinue");
			if (!form) {
				ret = -EINVAL;
				break;
			}
			/* XXX: Actually ask the user? */
			goto form_done;
		} else {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown form ID '%s'\n"),
				     form_id);
		dump_form:
			fprintf(stderr, _("Dumping unknown HTML form:\n"));
			htmlNodeDumpFileFormat(stderr, node->doc, node, NULL, 1);
			ret = -EINVAL;
			break;
		}

		do {
			ret = process_auth_form(vpninfo, form);
		} while (ret == OC_FORM_RESULT_NEWGROUP);
		if (ret)
			goto out;

		ret = do_gen_tokencode(vpninfo, form);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
			vpninfo->token_bypassed = 1;
			goto out;
		}

	form_done:
		append_form_opts(vpninfo, form, resp_buf);
		ret = buf_error(resp_buf);
		if (ret)
			break;

		vpninfo->redirect_url = form->action;
		form->action = NULL;
		free_auth_form(form);
		form = NULL;
		handle_redirect(vpninfo);

	tncc_done:
		xmlFreeDoc(doc);
		doc = NULL;
	}
 out:
	if (doc)
		xmlFreeDoc(doc);
	free(form_id);
	if (form)
		free_auth_form(form);
	buf_free(resp_buf);
	return ret;
}
