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

static int parse_input_node(struct openconnect_info *vpninfo, struct oc_auth_form *form,
			    xmlNodePtr node, const char *submit_button)
{
	const char *type = (const char *)xmlGetProp(node, (unsigned char *)"type");
	struct oc_form_opt **p = &form->opts;
	struct oc_form_opt *opt;

	if (!type)
		return -EINVAL;

	opt = calloc(1, sizeof(*opt));
	if (!opt)
		return -ENOMEM;

	if (!strcasecmp(type, "hidden")) {
		opt->type = OC_FORM_OPT_HIDDEN;
		xmlnode_get_prop(node, "name", &opt->name);
		xmlnode_get_prop(node, "value", &opt->_value);
		/* XXX: Handle tz_offset / tz */
	} else if (!strcasecmp(type, "password")) {
		opt->type = OC_FORM_OPT_PASSWORD;
		xmlnode_get_prop(node, "name", &opt->name);
		asprintf(&opt->label, "%s:", opt->name);
	} else if (!strcasecmp(type, "text")) {
		opt->type = OC_FORM_OPT_TEXT;
		xmlnode_get_prop(node, "name", &opt->name);
		asprintf(&opt->label, "%s:", opt->name);
	} else if (!strcasecmp(type, "submit")) {
		xmlnode_get_prop(node, "name", &opt->name);
		if (!opt->name || strcmp(opt->name, submit_button)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Ignoring unknown form submit item '%s'\n"),
				     opt->name);
			free_opt(opt);
			return -EINVAL;
		}
		xmlnode_get_prop(node, "value", &opt->_value);
		opt->type = OC_FORM_OPT_HIDDEN;
	} else {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Ignoring unknown form input type '%s'\n"),
			     type);
		free_opt(opt);
		return -EINVAL;
	}

	/* Append to the existing list */
	while (*p)
		p = &(*p)->next;
	*p = opt;
	return 0;
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

	for (child = node->children; child; child = child->next) {
		if (!child->name || strcasecmp((const char *)child->name, "option"))
			continue;

		choice = calloc(1, sizeof(*choice));
		if (!choice) {
			free_opt((void *)choice);
			return -ENOMEM;
		}

		xmlnode_get_prop(node, "name", &choice->name);
		choice->label = (char *)xmlNodeGetContent(child);
		choice->name = strdup(choice->label);
		realloc_inplace(opt->choices, sizeof(opt->choices[0]) * (opt->nr_choices+1));
		if (!opt->choices) {
			opt->nr_choices = 0;
			free_opt((void *)opt);
			return -ENOMEM;
		}
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
		if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockfd))
			return -errno;
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
			vpn_progress(vpninfo, PRG_ERR,
				     _("No support for %s form type yet\n"),
				     form_id);
			ret = -EINVAL;
			break;
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

		ret = process_auth_form(vpninfo, form);
		if (ret)
			goto out;

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

static int parse_cookie(struct openconnect_info *vpninfo)
{
	char *p = vpninfo->cookie;

	/* We currenly expect the "cookie" to be contain multiple cookies:
	 * DSSignInUrl=/; DSID=xxx; DSFirstAccess=xxx; DSLastAccess=xxx
	 * Process those into vpninfo->cookies unless we already had them
	 * (in which case they'll may be newer. */
	while (p && *p) {
		char *semicolon = strchr(p, ';');
		char *equals;

		if (semicolon)
			*semicolon = 0;

		equals = strchr(p, '=');
		if (!equals) {
			vpn_progress(vpninfo, PRG_ERR, _("Invalid cookie '%s'\n"), p);
			return -EINVAL;
		}
		*equals = 0;
		http_add_cookie(vpninfo, p, equals+1, 0);
		*equals = '=';

		p = semicolon;
		if (p) {
			*p = ';';
			p++;
			while (*p && isspace(*p))
				p++;
		}
	}

	return 0;
}

static void buf_append_be16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	b[0] = val >> 8;
	b[1] = val & 0xff;

	buf_append_bytes(buf, b, 2);
}

static void buf_append_le16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	b[0] = val & 0xff;
	b[1] = val >> 8;

	buf_append_bytes(buf, b, 2);
}

static void buf_append_tlv(struct oc_text_buf *buf, uint16_t val, uint32_t len, void *data)
{
	unsigned char b[6];

	b[0] = val >> 8;
	b[1] = val;
	b[2] = len >> 24;
	b[3] = len >> 16;
	b[4] = len >> 8;
	b[5] = len;
	buf_append_bytes(buf, b, 6);
	if (len)
		buf_append_bytes(buf, data, len);
}

static void buf_append_tlv_be32(struct oc_text_buf *buf, uint16_t val, uint32_t data)
{
	unsigned char d[4];

	d[0] = data >> 24;
	d[1] = data >> 16;
	d[2] = data >> 8;
	d[3] = data;

	buf_append_tlv(buf, val, 4, d);
}

static void buf_hexdump(struct openconnect_info *vpninfo, unsigned char *d, int len)
{
	char linebuf[80];
	int i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			if (i)
				vpn_progress(vpninfo, PRG_DEBUG, "%s\n", linebuf);
			sprintf(linebuf, "%04x:", i);
		}
		sprintf(linebuf + strlen(linebuf), " %02x", d[i]);
	}
	vpn_progress(vpninfo, PRG_DEBUG, "%s\n", linebuf);
}

static const char authpkt_head[] = { 0x00, 0x04, 0x00, 0x00, 0x00 };
static const char authpkt_tail[] = { 0xbb, 0x01, 0x00, 0x00, 0x00, 0x00 };

#define GRP_ATTR(g, a) (((g) << 16) | (a))
#define TLV_BE32(data) ((data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3])
#define TLV_BE16(data) ((data[0] << 8) + data[1])

/* We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers. */

static const char *add_option(struct openconnect_info *vpninfo, const char *opt,
			      const char *val, int val_len)
{
	struct oc_vpn_option *new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->option = strdup(opt);
	if (!new->option) {
		free(new);
		return NULL;
	}
	if (val_len >= 0)
		new->value = strndup(val, val_len);
	else
		new->value = strdup(val);
	if (!new->value) {
		free(new->option);
		free(new);
		return NULL;
	}
	new->next = vpninfo->cstp_options;
	vpninfo->cstp_options = new;

	return new->value;
}

static int process_attr(struct openconnect_info *vpninfo, int group, int attr,
			unsigned char *data, int attrlen)
{
	char buf[80];
	int i;

	switch(GRP_ATTR(group, attr)) {
	case GRP_ATTR(6, 2):
		if (attrlen != 4) {
		badlen:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected length %d for TLV %d/%d\n"),
				     attrlen, group, attr);
			return -EINVAL;
			goto badlen;
		}
		vpninfo->ip_info.mtu = TLV_BE32(data);
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received MTU %d from server\n"),
			     vpninfo->ip_info.mtu);
		break;

	case GRP_ATTR(2, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS server %s\n"), buf);

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.dns[i]) {
				vpninfo->ip_info.dns[i] = add_option(vpninfo, "DNS", buf, -1);
				break;
			}
		}
		break;

	case GRP_ATTR(2, 2):
		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS search domain %.*s\n"),
			     attrlen, (char *)data);
		vpninfo->ip_info.domain = add_option(vpninfo, "search", (char *)data, attrlen);
		break;

	case GRP_ATTR(1, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal IP address %s\n"), buf);
		vpninfo->ip_info.addr = add_option(vpninfo, "ipaddr", buf, -1);
		break;

	case GRP_ATTR(1, 2):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received netmask %s\n"), buf);
		vpninfo->ip_info.netmask = add_option(vpninfo, "netmask", buf, -1);
		break;

	case GRP_ATTR(1, 3):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received internal gateway address %s\n"), buf);
		/* Hm, what are we supposed to do with this? It's a tunnel;
		   having a gateway is meaningless. */
		add_option(vpninfo, "ipaddr", buf, -1);
		break;

	case GRP_ATTR(3, 3): {
		struct oc_split_include *inc;
		if (attrlen != 8)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d/%d.%d.%d.%d",
			 data[0], data[1], data[2], data[3],
			 data[4], data[5], data[6], data[7]);
		vpn_progress(vpninfo, PRG_DEBUG, _("Received split include route %s\n"), buf);
		if (!data[4] && !data[5] && !data[6] && !data[7])
			break;
		inc = malloc(sizeof(*inc));
		if (inc) {
			inc->route = add_option(vpninfo, "split-include", buf, -1);
			if (inc->route) {
				inc->next = vpninfo->ip_info.split_includes;
				vpninfo->ip_info.split_includes = inc;
			} else
				free(inc);
		}
		break;
	}
	case GRP_ATTR(4, 1):
		if (attrlen != 4)
			goto badlen;
		snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);

		vpn_progress(vpninfo, PRG_DEBUG, _("Received WINS server %s\n"), buf);

		for (i = 0; i < 3; i++) {
			if (!vpninfo->ip_info.nbns[i]) {
				vpninfo->ip_info.nbns[i] = add_option(vpninfo, "WINS", buf, -1);
				break;
			}
		}
		break;

	case GRP_ATTR(8, 1): {
		const char *enctype;

		if (attrlen != 1)
			goto badlen;
		if (data[0] == 0x02)
			enctype = "AES-128";
		else if (data[0] == 0x05)
			enctype = "AES-256";
		else
			enctype = "unknown";
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP encryption: 0x%02x (%s)\n"),
			      data[0], enctype);
		vpninfo->esp_enc = data[0];
		break;
	}

	case GRP_ATTR(8, 2): {
		const char *mactype;

		if (attrlen != 1)
			goto badlen;
		if (data[0] == 0x01)
			mactype = "MD5";
		else if (data[0] == 0x02)
			mactype = "SHA1";
		else
			mactype = "unknown";
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP HMAC: 0x%02x (%s)\n"),
			      data[0], mactype);
		vpninfo->esp_hmac = data[0];
		break;
	}

	case GRP_ATTR(8, 3):
		if (attrlen != 1)
			goto badlen;
		vpninfo->esp_compr = data[0];
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP compression: %d\n"), data[0]);
		break;

	case GRP_ATTR(8, 4):
		if (attrlen != 2)
			goto badlen;
		i = TLV_BE16(data);
		udp_sockaddr(vpninfo, i);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP port: %d\n"), i);
		break;

	case GRP_ATTR(8, 5):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_lifetime_bytes = TLV_BE32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP key lifetime: %u bytes\n"),
			     vpninfo->esp_lifetime_bytes);
		break;

	case GRP_ATTR(8, 6):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_lifetime_seconds = TLV_BE32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP key lifetime: %u seconds\n"),
			     vpninfo->esp_lifetime_seconds);
		break;

	case GRP_ATTR(8, 9):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_ssl_fallback = TLV_BE32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP to SSL fallback: %u seconds\n"),
			     vpninfo->esp_ssl_fallback);
		break;

	case GRP_ATTR(8, 10):
		if (attrlen != 4)
			goto badlen;
		vpninfo->esp_replay_protect = TLV_BE32(data);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP replay protection: %d\n"),
			     TLV_BE32(data));
		break;

	case GRP_ATTR(7, 1):
		if (attrlen != 4)
			goto badlen;
		memcpy(&vpninfo->esp_out.spi, data, 4);
		vpn_progress(vpninfo, PRG_DEBUG, _("ESP SPI (outbound): %x\n"),
			     TLV_BE32(data));
		break;

	case GRP_ATTR(7, 2):
		if (attrlen != 0x40)
			goto badlen;
		memcpy(vpninfo->esp_out.secrets, data, 0x40);
		vpn_progress(vpninfo, PRG_DEBUG, _("%d bytes of ESP secrets\n"),
			     attrlen);
		break;

	default:
		buf[0] = 0;
		for (i=0; i < 16 && i < attrlen; i++)
			sprintf(buf + strlen(buf), " %02x", data[i]);
		if (attrlen > 16)
			sprintf(buf + strlen(buf), "...");

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Unknown TLV group %d attr %d len %d:%s\n"),
			       group, attr, attrlen, buf);
	}
	return 0;
}

static void put_len16(struct oc_text_buf *buf, int where)
{
	int len = buf->pos - where;

	buf->data[where - 1] = len;
	buf->data[where - 2] = len >> 8;
}

static void put_len32(struct oc_text_buf *buf, int where)
{
	int len = buf->pos - where;

	buf->data[where - 1] = len;
	buf->data[where - 2] = len >> 8;
	buf->data[where - 3] = len >> 16;
	buf->data[where - 4] = len >> 24;
}


/* We don't know what these are so just hope they never change */
static const unsigned char kmp_head[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char kmp_tail[] = { 0x01, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char kmp_tail_out[] = { 0x01, 0x00, 0x00, 0x00, 0x01,
					      0x00, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char data_hdr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					  0x01, 0x2c, 0x01, 0x00, 0x00, 0x00,
					  0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const unsigned char esp_kmp_hdr[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2e,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, /* KMP header */
	0x00, 0x56, /* KMP length */
	0x00, 0x07, 0x00, 0x00, 0x00, 0x50, /* TLV group 7 */
	0x00, 0x01, 0x00, 0x00, 0x00, 0x04, /* Attr 1 (SPI) */
};
/* Followed by 4 bytes of SPI */
static const unsigned char esp_kmp_part2[] = {
	0x00, 0x02, 0x00, 0x00, 0x00, 0x40, /* Attr 2 (secrets) */
};
/* And now 0x40 bytes of random secret for encryption and HMAC key */


static const struct pkt esp_enable_pkt = {
	.oncp_hdr = {
		0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x2f, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x0d
	},
	.data = {
		0x00, 0x06, 0x00, 0x00, 0x00, 0x07, /* Group 6, len 7 */
		0x00, 0x01, 0x00, 0x00, 0x00, 0x01, /* Attr 1, len 1 */
		0x01
	},
	.len = 13
};

static int check_kmp_header(struct openconnect_info *vpninfo, unsigned char *bytes, int pktlen)
{
	if (pktlen < 20 || memcmp(bytes, kmp_head, sizeof(kmp_head)) ||
	    memcmp(bytes + 8, kmp_tail, sizeof(kmp_tail))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse KMP header\n"));
		return -EINVAL;
	}
	return bytes[7] | (bytes[6] << 8);
}

static int parse_conf_pkt(struct openconnect_info *vpninfo, unsigned char *bytes, int pktlen, int kmp)
{
	int kmplen, kmpend, grouplen, groupend, group, attr, attrlen;
	int ofs = 0;

	kmplen = bytes[ofs + 19] + (bytes[ofs + 18] << 8);
	kmpend = ofs + kmplen;
	if (kmpend > pktlen) {
	eparse:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse KMP message\n"));
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Got KMP message %d of size %d\n"),
		     kmp, kmplen);
	ofs += 0x14;

	while (ofs < kmpend) {
		if (ofs + 6 > kmpend)
			goto eparse;
		group = (bytes[ofs] << 8) + bytes[ofs+1];
		grouplen = (bytes[ofs+2] << 24) + (bytes[ofs+3] << 16) +
			(bytes[ofs+4] << 8) + bytes[ofs+5];
		ofs += 6;
		groupend = ofs + grouplen;
		if (groupend > pktlen)
			goto eparse;

		if (kmp == 302 && group != 7 && group != 8) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Received non-ESP TLVs (group %d) in ESP negotiation KMP\n"),
				     group);
			return -EINVAL;
		}

		while (ofs < groupend) {
			if (ofs + 6 > groupend)
				goto eparse;
			attr = (bytes[ofs] << 8) + bytes[ofs+1];
			attrlen = (bytes[ofs+2] << 24) + (bytes[ofs+3] << 16) +
				(bytes[ofs+4] << 8) + bytes[ofs+5];
			ofs += 6;
			if (attrlen + ofs > groupend)
				goto eparse;
			if (process_attr(vpninfo, group, attr, bytes + ofs, attrlen))
				goto eparse;
			ofs += attrlen;
		}
	}
	return 0;
}

int oncp_connect(struct openconnect_info *vpninfo)
{
	int ret, len, kmp, group;
	struct oc_text_buf *reqbuf;
	unsigned char bytes[1024];
	/* XXX: We should do what cstp_connect() does to check that configuration
	   hasn't changed on a reconnect. */

	if (!vpninfo->cookies) {
		ret = parse_cookie(vpninfo);
		if (ret)
			return ret;
	}

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

 	buf_append(reqbuf, "POST /dana/js?prot=1&svc=1 HTTP/1.1\r\n");
	oncp_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating oNCP negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}

	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	/* The server is fairly weird. It sends Connection: close which would
	 * indicate an HTTP 1.0-style body, but doesn't seem to actually close
	 * the connection. So tell process_http_response() it was a CONNECT
	 * request, since we don't care about the body anyway, and then close
	 * the connection for ourselves. */
	ret = process_http_response(vpninfo, 1, NULL, reqbuf);
	openconnect_close_https(vpninfo, 0);
	if (ret < 0) {
		/* We'll already have complained about whatever offended us */
		goto out;
	}
	if (ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	/* Now the second request. We should reduce the duplication
	   here but let's not overthink it for now; we should see what
	   the authentication requests are going to look like, and make
	   do_https_request() or a new helper function work for those
	   too. */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;

	buf_truncate(reqbuf);
	buf_append(reqbuf, "POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n");
	oncp_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating oNCP negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 1, NULL, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	/* This is probably some kind of vestigial authentication packet, although
	 * it's mostly obsolete now that the authentication is really done over
	 * HTTP. We only send the hostname. */
	buf_truncate(reqbuf);
	buf_append_le16(reqbuf, sizeof(authpkt_head) + 2 +
			strlen(vpninfo->localname) + sizeof(authpkt_tail));
	buf_append_bytes(reqbuf, authpkt_head, sizeof(authpkt_head));
	buf_append_le16(reqbuf, strlen(vpninfo->localname));
	buf_append(reqbuf, "%s", vpninfo->localname);
	buf_append_bytes(reqbuf, authpkt_tail, sizeof(authpkt_tail));
	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating oNCP negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	buf_hexdump(vpninfo, (void *)reqbuf->data, reqbuf->pos);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret != reqbuf->pos) {
		if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write in oNCP negotiation\n"));
			ret = -EIO;
		}
		goto out;
	}

	/* Now we expect a three-byte response with what's presumably an
	   error code */
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, 3);
	if (ret < 0)
		goto out;
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Read %d bytes of SSL record\n"), ret);
	
	if (ret != 3 || bytes[0] != 1 || bytes[1] != 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected response of size %d after hostname packet\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}
	if (bytes[2]) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Server response to hostname packet is error 0x%02x\n"),
			     bytes[2]);
		ret = -EINVAL;
		goto out;
	}

	/* And then a KMP message 301 with the IP configuration */
	len = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (len < 0) {
		ret = len;
		goto out;
	}
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Read %d bytes of SSL record\n"), len);

	if (len < 0x16 || bytes[0] + (bytes[1] << 8) + 2 != len) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid packet waiting for KMP 301\n"));
		ret = -EINVAL;
		goto out;
	}

	ret = check_kmp_header(vpninfo, bytes + 2, len);
	if (ret < 0)
		goto out;

	/* We expect KMP message 301 here */
	if (ret != 301) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Expected KMP message 301 from server but got %d\n"),
			     ret);
		ret = -EINVAL;
		goto out;
	}

	ret = parse_conf_pkt(vpninfo, bytes + 2, len, ret);
	if (ret)
		goto out;

	buf_truncate(reqbuf);
	buf_append_le16(reqbuf, 0); /* Length. We'll fix it later. */
	buf_append_bytes(reqbuf, kmp_head, sizeof(kmp_head));
	buf_append_be16(reqbuf, 303); /* KMP message 303 */
	buf_append_bytes(reqbuf, kmp_tail_out, sizeof(kmp_tail_out));
	buf_append_be16(reqbuf, 0); /* KMP message length */
	kmp = reqbuf->pos;
	buf_append_tlv(reqbuf, 6, 0, NULL); /* TLV group 6 */
	group = reqbuf->pos;
	buf_append_tlv_be32(reqbuf, 2, vpninfo->ip_info.mtu);
	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating oNCP negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	put_len32(reqbuf, group);
	put_len16(reqbuf, kmp);

#if defined(ESP_GNUTLS) || defined(ESP_OPENSSL)
	if (!setup_esp_keys(vpninfo)) {
		struct esp *esp = &vpninfo->esp_in[vpninfo->current_esp_in];
		/* Since we'll want to do this in the oncp_mainloop too, where it's easier
		 * *not* to have an oc_text_buf and build it up manually, and since it's
		 * all fixed size and fairly simple anyway, just hard-code the packet */
		buf_append_bytes(reqbuf, esp_kmp_hdr, sizeof(esp_kmp_hdr));
		buf_append_bytes(reqbuf, &esp->spi, sizeof(esp->spi));
		buf_append_bytes(reqbuf, esp_kmp_part2, sizeof(esp_kmp_part2));
		buf_append_bytes(reqbuf, &esp->secrets, sizeof(esp->secrets));
		if (buf_error(reqbuf)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error negotiating ESP keys\n"));
			ret = buf_error(reqbuf);
			goto out;
		}
	}
#endif
	/* Length at the start of the packet is little-endian */
	reqbuf->data[0] = (reqbuf->pos - 2);
	reqbuf->data[1] = (reqbuf->pos - 2) >> 8;

	buf_hexdump(vpninfo, (void *)reqbuf->data, reqbuf->pos);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret == reqbuf->pos)
		ret = 0;
	else if (ret >= 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Short write in oNCP negotiation\n"));
		ret = -EIO;
	}
 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}
	buf_free(reqbuf);
	return ret;
}

static int oncp_receive_espkeys(struct openconnect_info *vpninfo, int len)
{
#if defined(ESP_GNUTLS) || defined(ESP_OPENSSL)
	int ret;

	ret = parse_conf_pkt(vpninfo, vpninfo->cstp_pkt->oncp_hdr + 2, len + 20, 301);
	if (!ret && !setup_esp_keys(vpninfo)) {
		struct esp *esp = &vpninfo->esp_in[vpninfo->current_esp_in];
		unsigned char *p = vpninfo->cstp_pkt->oncp_hdr + 2;

		memcpy(p, esp_kmp_hdr, sizeof(esp_kmp_hdr));
		p += sizeof(esp_kmp_hdr);
		memcpy(p, &esp->spi, sizeof(esp->spi));
		p += sizeof(esp->spi);
		memcpy(p, esp_kmp_part2, sizeof(esp_kmp_part2));
		p += sizeof(esp_kmp_part2);
		memcpy(p, esp->secrets, sizeof(esp->secrets));
		p += sizeof(esp->secrets);
		vpninfo->cstp_pkt->len = p - vpninfo->cstp_pkt->data;
		vpninfo->cstp_pkt->oncp_hdr[0] = (p - vpninfo->cstp_pkt->oncp_hdr - 2);
		vpninfo->cstp_pkt->oncp_hdr[1] = (p - vpninfo->cstp_pkt->oncp_hdr - 2) >> 8;

		queue_packet(&vpninfo->oncp_control_queue, vpninfo->cstp_pkt);
		vpninfo->cstp_pkt = NULL;

		print_esp_keys(vpninfo, _("new incoming"), esp);
		print_esp_keys(vpninfo, _("new outgoing"), &vpninfo->esp_out);
	}
	return ret;
#else
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Ignoring ESP keys since ESP support not available in this build\n"));
	return 0;
#endif
}

static int oncp_receive_data(struct openconnect_info *vpninfo, int len, int unreceived)
{
	struct pkt *pkt = vpninfo->cstp_pkt;
	int pktlen;
	int ret;

	while (1) {
		/*
		 * 'len' is the total amount of data remaining in thie SSL record,
		 * of which 'unreceived' has yet to be received.
		 *
		 * We have already got (len - unreceived) bytes in vpninfo->cstp_pkt,
		 * and if unreceived is not zero then we'll have a full MTU, thus
		 * len - unreceived == vpninfo->ip_info.mtu.
		 *
		 * So we know we should have at least one complete IP packet, and
		 * maybe more. Receive the IP packet, copy any remaining bytes into
		 * a newly-allocated 'struct pkt', read any more bytes from the SSL
		 * record that we need to make the above still true, and repeat.
		 */

		/* Ick. Windows doesn't give us 'struct ip', AFAICT. */
		switch(pkt->data[0] >> 4) {
		case 4:
			pktlen = (pkt->data[2] << 8) | pkt->data[3];
			break;
		case 6:
			pktlen = (pkt->data[4] << 8) | pkt->data[5];
			break;
		default:
		badlen:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unrecognised data packet starting %02x %02x %02x %02x %02x %02x %02x %02x\n"),
				     pkt->data[0], pkt->data[1], pkt->data[2], pkt->data[3],
				     pkt->data[4], pkt->data[5], pkt->data[6], pkt->data[7]);
			/* Drain the unreceived bytes if we want to continue */
			return -EINVAL;
		}

		/* Should never happen, but would cause an endless loop if it did. */
		if (!pktlen || pktlen > vpninfo->ip_info.mtu)
			goto badlen;

		/* Receive this packet */
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received uncompressed data packet of %d bytes\n"),
			     pktlen);
		pkt->len = pktlen;
		queue_packet(&vpninfo->incoming_queue, pkt);
		vpninfo->cstp_pkt = NULL;

		len -= pktlen;
		if (!len) /* Common case */
			return 0;

		/* Allocate the *next* packet to be received */
		vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + vpninfo->ip_info.mtu);
		if (!vpninfo->cstp_pkt) {
			vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
			/* Drain the unreceived bytes if we want to continue */
			return -ENOMEM;
		}

		/* Copy any extra bytes from the tail of 'pkt', which is already
		 * on the RX queue, into the next packet. */
		if (len - unreceived)
			memcpy(vpninfo->cstp_pkt->data,
			       pkt->data + pktlen,
			       len - unreceived);

		pkt = vpninfo->cstp_pkt;

		if (unreceived) {
			int retried = 0;

			/* The length of the previous packet is the amount by
			 * which we need to replenish the buffer. */
			if (pktlen > unreceived)
				pktlen = unreceived;
		retry:
			/* This is a *blocking* read, since if the crypto library
			 * already started returning the first part of this SSL
			 * record then it damn well ought to have the rest of it
			 * available already. */
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Reading additional %d bytes (of %d still unreceived) from oNCP...\n"),
				     pktlen, unreceived);
			ret = vpninfo->ssl_read(vpninfo, (void *)(pkt->data + (len - unreceived)),
						pktlen);
			if (ret < 0)
				return ret;
			if (ret != pktlen && !retried) {
				/* This can happen when there are *so* many IP packets in a single oNCP
				   packet that it exceeds the 16KiB maximum size of a SSL record. So
				   in that case the above comment about a blocking read is invalid; we
				   *could* end up waiting here. We should actually fix things to be
				   completely asynchronous, storing the 'len' and 'unreceived' variables
				   in the vpninfo structure and getting back into this loop directly
				   from oncp_mainloop(). But I'm not going to lose too much sleep
				   over that just yet. After all, we wouldn't be receiving data here
				   if the ESP was up — we know there's no *other* data transport that
				   the mainloop should be servicing while it's blocked. Perhaps we could
				   be sending packets on *this* TCP connection while we wait for the
				   next SSL record to arrive, though. */
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Short read on (%d < %d) on large KMP message. Trying again in case it crossed SSL record boundary\n"),
					     ret, pktlen);
				unreceived -= ret;
				pktlen -= ret;
				retried = 1;
				goto retry;
			}
			if (ret != pktlen) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Short read for end of large KMP message. Expected %d, got %d bytes\n"),
					     pktlen, ret);
				return -EIO;
			}
			unreceived -= pktlen;
		}
	}
}

int oncp_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int ret;
	int work_done = 0;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while (1) {
		int len = vpninfo->ip_info.mtu;
		int kmp, kmplen, reclen;
		int morecoming;
		int followon; /* 0 for the first time round, 2 later to skip the length word */

		followon = 0;

	next_kmp:
		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + len);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		/*
		 * The first two bytes of each SSL record contain the (little-endian)
		 * length of that record. On the wire it's arguably redundant, but
		 * it's nice to have it here and just be able to read() from the SSL
		 * "stream" in the knowledge that a single read call will never cross
		 * record boundaries.
		 *
		 * An SSL record may contain multiple KMP messages. And a KMP message
		 * of type 300 (data) can evidently contain multiple IP packets with
		 * nothing to split them apart except the length field in the IP
		 * packet itself.
		 *
		 * But the *common* case is that we read a full SSL record which
		 * contains a single KMP message 300, which contains a single IP
		 * packet. So receive it into the appropriate place in a struct pkt
		 * so that we can just pass it up the stack. And cope with the rest
		 * as corner cases.
		 */

		len = ssl_nonblock_read(vpninfo, vpninfo->cstp_pkt->oncp_hdr + followon,
					22 - followon);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len != 22 - followon) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read KMP header from SSL stream; only %d bytes available of %d\n"),
				     len, 22 - followon);
			buf_hexdump(vpninfo, vpninfo->cstp_pkt->oncp_hdr + followon, len - followon);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		if (!followon) {
			/* This is the length of the packet (little-endian) */
			reclen = vpninfo->cstp_pkt->oncp_hdr[0] +
				(vpninfo->cstp_pkt->oncp_hdr[1] << 8);
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Incoming oNCP packet of size %d\n"), reclen);
		}
		if (reclen < 20) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Packet too small (%d bytes) to contain KMP message header\n"),
				     reclen);
			vpninfo->quit_reason = "Failed to packetise stream";
			return 1;
		}

		kmp = vpninfo->cstp_pkt->oncp_hdr[9] | (vpninfo->cstp_pkt->oncp_hdr[8] << 8);
		kmplen = (vpninfo->cstp_pkt->oncp_hdr[20] << 8) +
			vpninfo->cstp_pkt->oncp_hdr[21];
		if (kmplen + 20 > reclen) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("KMP message larger than packet (%d > %d)\n"),
				     kmplen + 20, reclen);
			vpninfo->quit_reason = "KMP message too large";
			return 1;
		}
		/* Now read as much of the first KMP message from the packet
		 * as fits into the MTU. */
		if (kmplen > vpninfo->ip_info.mtu) {
			len = vpninfo->ip_info.mtu;
			morecoming = kmplen - len;
		} else {
			len = kmplen;
			morecoming = 0;
		}
		if (len) {
			/* This is a *blocking* read, since if the crypto library
			 * already started returning the first part of this SSL
			 * record then it damn well ought to have the rest of it
			 * available already. */
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Reading additional %d bytes from oNCP...\n"),
				     len);
			ret = vpninfo->ssl_read(vpninfo, (void *)vpninfo->cstp_pkt->data, len);
			if (ret != len) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Short read of KMP message. Expected %d, got %d bytes\n"),
					     len, ret);
				/* Just to set up the debugging hex dump of it... */
				morecoming = len - ret;
				goto unknown_pkt;
			}
		}
		vpn_progress(vpninfo, PRG_DEBUG, _("Incoming KMP message %d of size %d\n"),
			     kmp, kmplen);

		vpninfo->ssl_times.last_rx = time(NULL);
		switch (kmp) {
		case 300:
			ret = oncp_receive_data(vpninfo, kmplen, morecoming);
			if (ret) {
				vpninfo->quit_reason = "Failed to read KMP data message";
				return 1;
			}
			work_done = 1;
			break;

		case 302:
			if (morecoming)
				goto unknown_pkt;
			ret = oncp_receive_espkeys(vpninfo, kmplen);
			work_done = 1;
			break;

		default:
		unknown_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown KMP message %d of size %d:\n"), kmp, kmplen);
			buf_hexdump(vpninfo, vpninfo->cstp_pkt->oncp_hdr,
				    kmplen + 22 - morecoming);
			if (morecoming)
				vpn_progress(vpninfo, PRG_DEBUG,
					     _(".... + %d more bytes unreceived\n"),
					     morecoming);
			vpninfo->quit_reason = "Unknown packet received";
			return 1;
		}

		reclen -= kmplen + 20;
		if (reclen) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Still %d bytes left in this packet. Looping...\n"),
				     reclen);
			followon = 2;
			goto next_kmp;
		}
	}

	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		vpn_progress(vpninfo, PRG_TRACE, _("Packet outgoing:\n"));
		buf_hexdump(vpninfo, vpninfo->current_ssl_pkt->oncp_hdr,
			    vpninfo->current_ssl_pkt->len + 22);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->oncp_hdr,
					 vpninfo->current_ssl_pkt->len + 22);
		if (ret < 0) {
#if 0
			goto do_reconnect;
#else
		do_reconnect:
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect not implemented yet for oNCP\n"));
			vpninfo->quit_reason = "Need reconnect";
			return 1;
#endif
		}
		else if (!ret) {
#if 0 /* Not for Juniper yet */
			/* -EAGAIN: ssl_nonblock_write() will have added the SSL
			   fd to ->select_wfds if appropriate, so we can just
			   return and wait. Unless it's been stalled for so long
			   that DPD kicks in and we kill the connection. */
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_REKEY:
				goto do_rekey;
			case KA_NONE:
				return work_done;
			default:
				/* This should never happen */
				;
			}
#else
			return work_done;
#endif
		}

		if (ret != vpninfo->current_ssl_pkt->len + 22) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 22, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt == vpninfo->deflate_pkt)
			free(vpninfo->pending_deflated_pkt);
		else if (vpninfo->current_ssl_pkt == &esp_enable_pkt) {
			/* If we sent the special ESP enable packet, ESP
			 * is now enabled. And we don't need to free it. */
			if (vpninfo->dtls_state == DTLS_CONNECTING)
				vpninfo->dtls_state = DTLS_CONNECTED;
		} else {
			free(vpninfo->current_ssl_pkt);
		}
		vpninfo->current_ssl_pkt = NULL;
	}

#if 0 /* Not understood for Juniper yet */
	if (vpninfo->owe_ssl_dpd_response) {
		vpninfo->owe_ssl_dpd_response = 0;
		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_resp_pkt;
		goto handle_outgoing;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		/* Not that this will ever happen; we don't even process
		   the setting when we're asked for it. */
		vpn_progress(vpninfo, PRG_INFO, _("CSTP rekey due\n"));
		if (vpninfo->ssl_times.rekey_method == REKEY_TUNNEL)
			goto do_reconnect;
		else if (vpninfo->ssl_times.rekey_method == REKEY_SSL) {
			ret = cstp_handshake(vpninfo, 0);
			if (ret) {
				/* if we failed rehandshake try establishing a new-tunnel instead of failing */
				vpn_progress(vpninfo, PRG_ERR, _("Rehandshake failed; attempting new-tunnel\n"));
				goto do_reconnect;
			}

			goto do_dtls_reconnect;
		}
		break;

	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("CSTP Dead Peer Detection detected dead peer!\n"));
	do_reconnect:
		ret = cstp_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "CSTP reconnect failed";
			return ret;
		}

	do_dtls_reconnect:
		/* succeeded, let's rekey DTLS, if it is not rekeying
		 * itself. */
		if (vpninfo->dtls_state > DTLS_SLEEPING &&
		    vpninfo->dtls_times.rekey_method == REKEY_NONE) {
			vpninfo->dtls_need_reconnect = 1;
		}

		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP DPD\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED && vpninfo->outgoing_queue)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send CSTP Keepalive\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		goto handle_outgoing;

	case KA_NONE:
		;
	}
#endif
	if (vpninfo->oncp_control_queue) {
		vpninfo->current_ssl_pkt = vpninfo->oncp_control_queue;
		vpninfo->oncp_control_queue = vpninfo->oncp_control_queue->next;
		goto handle_outgoing;
	}
	if (vpninfo->dtls_state == DTLS_CONNECTING) {
		vpninfo->current_ssl_pkt = (struct pkt *)&esp_enable_pkt;
		goto handle_outgoing;
	}
	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED && vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		vpninfo->outgoing_queue = this->next;
		vpninfo->outgoing_qlen--;

		/* Little-endian overall record length */
		this->oncp_hdr[0] = (this->len + 20) & 0xff;
		this->oncp_hdr[1] = (this->len + 20) >> 8;
		memcpy(this->oncp_hdr + 2, data_hdr, 18);
		/* Big-endian length in KMP message header */
		this->oncp_hdr[20] = this->len >> 8;
		this->oncp_hdr[21] = this->len & 0xff;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending uncompressed data packet of %d bytes\n"),
			     this->len);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}
