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
		     xmlNodePtr node)
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
		opt->label = strdup(opt->name);
	} else if (!strcasecmp(type, "text")) {
		opt->type = OC_FORM_OPT_TEXT;
		xmlnode_get_prop(node, "name", &opt->name);
		opt->label = strdup(opt->name);
	} else if (!strcasecmp(type, "submit")) {
		xmlnode_get_prop(node, "name", &opt->name);
		if (!opt->name || strcmp(opt->name, "btnSubmit")) {
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
	printf("nr_choices %d\n", opt->nr_choices);
	/* Prepend to the existing list */
	opt->form.next = form->opts;
	form->opts = &opt->form;
	return 0;
}

static struct oc_auth_form *parse_form_node(struct openconnect_info *vpninfo, xmlNodePtr node)
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
	form->banner = form->auth_id;

	for (child = htmlnode_next(node, node); child && child != node; child = htmlnode_next(node, child)) {
		if (!child->name)
			continue;

		if (!strcasecmp((char *)child->name, "input"))
			parse_input_node(vpninfo, form, child);
		else if (!strcasecmp((char *)child->name, "select")) {
			parse_select_node(vpninfo, form, child);
			/* Skip its children */
			while (child->children)
				child = child->last;
		}
	}
	return form;
}

int oncp_obtain_cookie(struct openconnect_info *vpninfo)
{
	int ret;
	char *form_buf = NULL;
	struct oc_text_buf *buf;
	xmlDocPtr doc = NULL;
	xmlNodePtr node, root;
	struct oc_auth_form *form = NULL;

	ret = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, 1);
	if (ret < 0)
		return ret;

	buf = buf_alloc();
	buf_append(buf, "https://%s", vpninfo->hostname);
	if (vpninfo->port != 443)
		buf_append(buf, ":%d", vpninfo->port);
	buf_append(buf, "/");
	if (vpninfo->urlpath)
		buf_append(buf, "%s", vpninfo->urlpath);

	if (buf_error(buf)) {
		free(form_buf);
		return buf_free(buf);
	}

	doc = htmlReadMemory(form_buf, ret, buf->data, NULL,
			     HTML_PARSE_RECOVER|HTML_PARSE_NOERROR|HTML_PARSE_NOWARNING|HTML_PARSE_NONET);
	buf_free(buf);
	buf = NULL;
	free(form_buf);

	if (!doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse HTML document\n"));
		return -EINVAL;
	}
	for (root = node = xmlDocGetRootElement(doc); node; node = htmlnode_next(root, node)) {
		if (node->name && !strcasecmp((char *)node->name, "form")) {
			form = parse_form_node(vpninfo, node);
			break;
		}
	}
	if (!form) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to find or parse web form in login page\n"));
		ret = -EINVAL;
		goto out;
	}
	ret = process_auth_form(vpninfo, form);
	if (ret)
		return ret;
	buf = buf_alloc();
	append_form_opts(vpninfo, form, buf);
	if (buf_error(buf))
		return buf_free(buf);


	printf("Form response '%s'\n", buf->data);
	/* POST it ... */
		
	vpn_progress(vpninfo, PRG_ERR, _("oNCP authentication not yet implemented\n"));
 out:
//	if (form)
//		free_auth_form(form);
	if (doc)
		xmlFreeDoc(doc);
	return -EOPNOTSUPP;
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

static void buf_hexdump(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	char linebuf[80];
	int i;

	for (i = 0; i < buf->pos; i++) {
		if (i % 16 == 0) {
			if (i)
				vpn_progress(vpninfo, PRG_DEBUG, "%s\n", linebuf);
			sprintf(linebuf, "%04x:", i);
		}
		sprintf(linebuf + strlen(linebuf), " %02x", (unsigned char)buf->data[i]);
	}
	vpn_progress(vpninfo, PRG_DEBUG, "%s\n", linebuf);
}

static const char authpkt_head[] = { 0x00, 0x04, 0x00, 0x00, 0x00 };
static const char authpkt_tail[] = { 0xbb, 0x01, 0x00, 0x00, 0x00, 0x00 };

#define GRP_ATTR(g, a) (((g) << 16) | (a))
#define TLV_BE32(data) ((data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3])

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
		vpn_progress(vpninfo, PRG_DEBUG, _("Received DNS search domain %.*s"),
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
		vpninfo->ip_info.addr = add_option(vpninfo, "netmask", buf, -1);
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

		/* ESP SPI is (7,1) and secret (64 bytes) is (7,2) */
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
int oncp_connect(struct openconnect_info *vpninfo)
{
	int ret, ofs, kmp, kmpend, kmplen, attr, attrlen, group, grouplen, groupend;
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

	ret = process_http_response(vpninfo, 0, NULL, reqbuf);
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
	buf_hexdump(vpninfo, reqbuf);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	/* Now we expect a three-byte response with what's presumably an
	   error code */
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, 3);
	if (ret < 0)
		goto out;

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
	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0)
		goto out;

	if (ret < 0x16 || bytes[0] + (bytes[1] << 8) + 2 != ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid packet waiting for KMP 301\n"));
		ret = -EINVAL;
		goto out;
	}

	ofs = 2;

	while (ofs < ret) {
		/* Check the KMP message header. */
		if (ofs + 20 > ret || memcmp(bytes + ofs, kmp_head, sizeof(kmp_head)) ||
		    memcmp(bytes + ofs + 8, kmp_tail, sizeof(kmp_tail))) {
		eparse:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse server response\n"));
			ret = -EINVAL;
			goto out;
		}
		kmp = bytes[ofs + 7] + (bytes[ofs + 6] << 8);
		kmplen = bytes[ofs + 19] + (bytes[ofs + 18] << 8);
		if (ofs + kmplen > ret)
			goto eparse;
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Got KMP message %d of size %d\n"),
			     kmp, kmplen);
		ofs += 0x14;
		kmpend = ofs + kmplen;
		if (kmp != 301)
			goto eparse;

		while (ofs < kmpend) {
			if (ofs + 6 > kmpend)
				goto eparse;
			group = (bytes[ofs] << 8) + bytes[ofs+1];
			grouplen = (bytes[ofs+2] << 24) + (bytes[ofs+3] << 16) +
				(bytes[ofs+4] << 8) + bytes[ofs+5];
			ofs += 6;
			groupend = ofs + grouplen;

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
	}

	buf_truncate(reqbuf);
	buf_append_le16(reqbuf, 0); /* Length. We'll fix it later. */
	buf_append_bytes(reqbuf, kmp_head, sizeof(kmp_head));
	buf_append_le16(reqbuf, 303); /* KMP message 303 */
	buf_append_bytes(reqbuf, kmp_tail_out, sizeof(kmp_tail_out));
	buf_append_le16(reqbuf, 0); /* KMP message length */
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
	/* Length at the start of the packet is little-endian */
	reqbuf->data[0] = (reqbuf->pos - 2);
	reqbuf->data[1] = (reqbuf->pos - 2) >> 8;

	buf_hexdump(vpninfo,reqbuf);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);

 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	buf_free(reqbuf);
	return ret;
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
		int kmp, kmplen;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + len);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, vpninfo->cstp_pkt->oncp_hdr, len + 22);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		if (len < 22) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		if (len != vpninfo->cstp_pkt->oncp_hdr[0] +
		    (vpninfo->cstp_pkt->oncp_hdr[1] << 8) + 2)
			goto unknown_pkt;

		kmplen = (vpninfo->cstp_pkt->oncp_hdr[20] << 8) +
			vpninfo->cstp_pkt->oncp_hdr[21];
		if (len != kmplen + 22)
			goto unknown_pkt;

		kmp = (vpninfo->cstp_pkt->oncp_hdr[0] << 8) +
			vpninfo->cstp_pkt->oncp_hdr[1];
		vpn_progress(vpninfo, PRG_DEBUG, _("Incoming KMP message %d of size %d\n"),
			     kmp, kmplen);
		if (kmp != 300)
			goto unknown_pkt;

		vpninfo->ssl_times.last_rx = time(NULL);
		switch (kmp) {
		case 300:
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received uncompressed data packet of %d bytes\n"),
				     kmplen);
			vpninfo->cstp_pkt->len = kmplen;
			queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			work_done = 1;
			break;

		default:
		unknown_pkt:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown packet (0x%x bytes) %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n"),
				     len,
				     vpninfo->cstp_pkt->oncp_hdr[0], vpninfo->cstp_pkt->oncp_hdr[1],
				     vpninfo->cstp_pkt->oncp_hdr[2], vpninfo->cstp_pkt->oncp_hdr[3],
				     vpninfo->cstp_pkt->oncp_hdr[4], vpninfo->cstp_pkt->oncp_hdr[5],
				     vpninfo->cstp_pkt->oncp_hdr[6], vpninfo->cstp_pkt->oncp_hdr[7],
				     vpninfo->cstp_pkt->oncp_hdr[8], vpninfo->cstp_pkt->oncp_hdr[9],
				     vpninfo->cstp_pkt->oncp_hdr[10], vpninfo->cstp_pkt->oncp_hdr[11],
				     vpninfo->cstp_pkt->oncp_hdr[12], vpninfo->cstp_pkt->oncp_hdr[13],
				     vpninfo->cstp_pkt->oncp_hdr[14], vpninfo->cstp_pkt->oncp_hdr[15],
				     vpninfo->cstp_pkt->oncp_hdr[16], vpninfo->cstp_pkt->oncp_hdr[17],
				     vpninfo->cstp_pkt->oncp_hdr[18], vpninfo->cstp_pkt->oncp_hdr[19],
				     vpninfo->cstp_pkt->oncp_hdr[20], vpninfo->cstp_pkt->oncp_hdr[21]);
			vpninfo->quit_reason = "Unknown packet received";
			return 1;
		}
	}

	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

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
		else
#if 0 /* No DPD or keepalive for Juniper yet */
		if (vpninfo->current_ssl_pkt != &dpd_pkt &&
		    vpninfo->current_ssl_pkt != &dpd_resp_pkt &&
		    vpninfo->current_ssl_pkt != &keepalive_pkt)
#endif
			free(vpninfo->current_ssl_pkt);
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

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_CONNECTED && vpninfo->outgoing_queue) {
		struct pkt *this = vpninfo->outgoing_queue;
		vpninfo->outgoing_queue = this->next;
		vpninfo->outgoing_qlen--;

		/* Little-endian overall record length */
		this->oncp_hdr[0] = (this->len + 22) & 0xff;
		this->oncp_hdr[1] = (this->len + 22) >> 8;
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
