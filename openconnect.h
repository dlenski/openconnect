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

#ifndef __OPENCONNECT_H__
#define __OPENCONNECT_H__

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>


/****************************************************************************/

/* Authentication form processing */

#define OC_FORM_OPT_TEXT	1
#define OC_FORM_OPT_PASSWORD	2
#define OC_FORM_OPT_SELECT	3
#define OC_FORM_OPT_HIDDEN	4

/* char * fields are static (owned by XML parser) and don't need to be
   freed by the form handling code -- except for value, which for TEXT
   and PASSWORD options is allocated by process_form() when
   interacting with the user and must be freed. */
struct oc_form_opt {
	struct oc_form_opt *next;
	int type;
	char *name;
	char *label;
	char *value;
};

/* All fields are static, owned by the XML parser */
struct oc_choice {
	char *name;
	char *label;
	char *auth_type;
	char *override_name;
	char *override_label;
};

struct oc_form_opt_select {
	struct oc_form_opt form;
	int nr_choices;
	struct oc_choice choices[0];
};

/* All char * fields are static, owned by the XML parser */
struct oc_auth_form {
	char *banner;
	char *message;
	char *error;
	char *auth_id;
	char *method;
	char *action;
	struct oc_form_opt *opts;
};

/****************************************************************************/

#define PRG_ERR		0
#define PRG_INFO	1
#define PRG_DEBUG	2
#define PRG_TRACE	3

struct openconnect_info;
struct x509_st;

int get_cert_sha1_fingerprint(struct openconnect_info *vpninfo,
			      struct x509_st *cert, char *buf);
int openconnect_set_http_proxy(struct openconnect_info *vpninfo, char *proxy);
int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo);
int openconnect_obtain_cookie(struct openconnect_info *vpninfo);
void openconnect_close_https(struct openconnect_info *vpninfo);
char *openconnect_create_useragent(char *base);
void openconnect_init_openssl(void);
int openconnect_parse_url(char *url, char **res_proto, char **res_host,
			  int *res_port, char **res_path, int default_port);

#endif /* __OPENCONNECT_H__ */
