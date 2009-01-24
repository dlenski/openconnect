/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008 Intel Corporation.
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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <gconf/gconf-client.h>

#include <gtk/gtk.h>

#include "auth-dlg-settings.h"
#include "openconnect.h"

#include <openssl/bio.h>

static GConfClient *gcl;
static char *config_path;

static char *last_message;

static char* get_title(const char *vpn_name)
{
	if (vpn_name)
		return g_strdup_printf ("Connect to VPN '%s'", vpn_name);
	else
		return g_strdup ("Connect to VPN");
}

static int user_validate_cert(struct openconnect_info *vpninfo, X509 *peer_cert)
{
	BIO *bp = BIO_new(BIO_s_mem());
	char *msg, *title;
	BUF_MEM *certinfo;
	char zero = 0;
	GtkWidget *dlg, *text, *scroll;
	GtkTextBuffer *buffer;
	int result;

	/* There are probably better ways to do this -- getting individual
	   elements of the cert info and formatting it nicely in the dialog
	   box. But this will do for now... */
	X509_print_ex(bp, peer_cert, 0, 0);
	BIO_write(bp, &zero, 1);
	BIO_get_mem_ptr(bp, &certinfo);

	title = get_title(vpninfo->vpn_name);
	msg = g_strdup_printf("Unknown certificate from VPN server \"%s\".\n"
				"Do you want to accept it?", vpninfo->hostname);

	dlg = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_QUESTION,
				     GTK_BUTTONS_OK_CANCEL,
				     msg);
	gtk_window_set_skip_taskbar_hint(GTK_WINDOW(dlg), FALSE);
	gtk_window_set_skip_pager_hint(GTK_WINDOW(dlg), FALSE);
	gtk_window_set_title (GTK_WINDOW(dlg), title);
	gtk_window_set_default_size(GTK_WINDOW(dlg), 768, 768);
	gtk_window_set_resizable(GTK_WINDOW(dlg), TRUE);
	gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_CANCEL);

	g_free(title);
	g_free(msg);

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), scroll, TRUE, TRUE, 0);
	gtk_widget_show(scroll);

	text = gtk_text_view_new();
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text));
	gtk_text_buffer_set_text(buffer, certinfo->data, -1);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text), 0);
	gtk_container_add(GTK_CONTAINER(scroll), text);
	gtk_widget_show(text);

	result = gtk_dialog_run(GTK_DIALOG(dlg));

	BIO_free(bp);
	gtk_widget_destroy(dlg);
	gdk_flush();

	if (result != GTK_RESPONSE_OK)
		return -EINVAL;

	return 0;
}

static int validate_peer_cert(struct openconnect_info *vpninfo,
			      X509 *peer_cert)
{
	ASN1_STRING *signature = peer_cert->signature;
	char *certs_data;
	char *key;
	BIO *bp = BIO_new(BIO_s_mem());
	BUF_MEM *sig;
	char zero = 0;
	int ret = 0;

	i2a_ASN1_STRING(bp, signature, V_ASN1_OCTET_STRING);
	BIO_write(bp, &zero, 1);
	BIO_get_mem_ptr(bp, &sig);

	key = g_strdup_printf("%s/vpn/%s", config_path, "certsigs");
	certs_data = gconf_client_get_string(gcl, key, NULL);
	if (certs_data) {
		char **certs = g_strsplit_set(certs_data, "\t", 0);
		char **this = certs;

		while (*this) {
			if (!strcmp(*this, sig->data)) {
				g_strfreev(certs);
				goto out;
			}
			this++;
		}
		g_strfreev(certs);
	}

	ret = user_validate_cert(vpninfo, peer_cert);
	if (!ret) {
		if (certs_data) {
			char *new = g_strdup_printf("%s\t%s", certs_data, sig->data);
			gconf_client_set_string(gcl, key, new, NULL);
			g_free(new);
		} else {
			gconf_client_set_string(gcl, key, sig->data, NULL);
		}
	}
 out:
	if (certs_data)
		g_free(certs_data);
	BIO_free(bp);
	g_free(key);
	return ret;
}

static char *get_config_path(GConfClient *gcl, const char *vpn_uuid)
{
	GSList *connections, *this;
	char *key, *val;
	char *config_path = NULL;

	connections = gconf_client_all_dirs(gcl,
					    "/system/networking/connections",
					    NULL);

	for (this = connections; this; this = this->next) {
		const char *path = (const char *) this->data;

		key = g_strdup_printf("%s/connection/type", path);
		val = gconf_client_get_string(gcl, key, NULL);
		g_free(key);

		if (!val || strcmp(val, "vpn")) {
			g_free(val);
			continue;
		}
		g_free(val);

		key = g_strdup_printf("%s/connection/uuid", path);
		val = gconf_client_get_string(gcl, key, NULL);
		g_free(key);

		if (!val || strcmp(val, vpn_uuid)) {
			g_free(val);
			continue;
		}
		g_free(val);

		config_path = g_strdup(path);
		break;
	}
	g_slist_foreach(connections, (GFunc)g_free, NULL);
	g_slist_free(connections);

	return config_path;
}

static char *get_gconf_setting(GConfClient *gcl, char *config_path,
			       char *setting)
{
	char *result;
	char *key = g_strdup_printf("%s/vpn/%s", config_path, setting);
	result = gconf_client_get_string(gcl, key, NULL);
	g_free(key);
	return result;
}

static char *lasthost;

static struct vpnhost {
	char *hostname;
	char *hostaddress;
	struct vpnhost *next;
} *vpnhosts;

static int parse_xmlconfig(char *xmlconfig)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *xml_node2;
	struct vpnhost *newhost, **list_end;

	list_end = &vpnhosts;
	xml_doc = xmlReadMemory(xmlconfig, strlen(xmlconfig), "noname.xml", NULL, 0);

	xml_node = xmlDocGetRootElement(xml_doc);
	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
                if (xml_node->type == XML_ELEMENT_NODE &&
                    !strcmp((char *)xml_node->name, "ServerList")) {

                        for (xml_node = xml_node->children; xml_node;
                             xml_node = xml_node->next) {

                                if (xml_node->type == XML_ELEMENT_NODE &&
                                    !strcmp((char *)xml_node->name, "HostEntry")) {
                                        int match = 0;

					newhost = malloc(sizeof(*newhost));
					if (!newhost)
						return -ENOMEM;

					memset(newhost, 0, sizeof(*newhost));
                                        for (xml_node2 = xml_node->children;
                                             match >= 0 && xml_node2; xml_node2 = xml_node2->next) {

                                                if (xml_node2->type != XML_ELEMENT_NODE)
                                                        continue;

                                                if (!strcmp((char *)xml_node2->name, "HostName")) {
                                                        char *content = (char *)xmlNodeGetContent(xml_node2);
							newhost->hostname = content;
						} else if (!strcmp((char *)xml_node2->name, "HostAddress")) {
                                                        char *content = (char *)xmlNodeGetContent(xml_node2);
							newhost->hostaddress = content;
						}
					}
					if (newhost->hostname && newhost->hostaddress) {
						*list_end = newhost;
						list_end = &newhost->next;
                                        } else
						free(newhost);
                                }
                        }
			break;
                }
        }
        xmlFreeDoc(xml_doc);
	return 0;
}

static int get_config(char *vpn_uuid, struct openconnect_info *vpninfo)
{
	char *authtype;
	char *xmlconfig;

	gcl = gconf_client_get_default();
	config_path = get_config_path(gcl, vpn_uuid);

	if (!config_path)
		return -EINVAL;

	vpninfo->hostname = get_gconf_setting(gcl, config_path,
					      NM_OPENCONNECT_KEY_GATEWAY);
	if (!vpninfo->hostname) {
		fprintf(stderr, "No gateway configured\n");
		return -EINVAL;
	}

	lasthost = get_gconf_setting(gcl, config_path, "lasthost");

	xmlconfig = get_gconf_setting(gcl, config_path, NM_OPENCONNECT_KEY_XMLCONFIG);
	if (xmlconfig) {
		unsigned char sha1[SHA_DIGEST_LENGTH];
		EVP_MD_CTX c;
		int i;

		EVP_MD_CTX_init(&c);
		EVP_Digest(xmlconfig, strlen(xmlconfig), sha1, NULL, EVP_sha1(), NULL);
		EVP_MD_CTX_cleanup(&c);

		for (i = 0; i < SHA_DIGEST_LENGTH; i++)
			sprintf(&vpninfo->xmlsha1[i*2], "%02x", sha1[i]);

		parse_xmlconfig(xmlconfig);
		g_free(xmlconfig);
	}

	vpninfo->cafile = get_gconf_setting(gcl, config_path, NM_OPENCONNECT_KEY_CACERT);

	authtype = get_gconf_setting(gcl, config_path, NM_OPENCONNECT_KEY_AUTHTYPE);
	if (!authtype) {
		fprintf(stderr, "No authentication type configured\n");
		return -EINVAL;
	}

	if (!strcmp(authtype, NM_OPENCONNECT_AUTHTYPE_PASSWORD)) {
		vpninfo->username = get_gconf_setting(gcl, config_path,
						      NM_OPENCONNECT_KEY_USERNAME);
		return 0;
	}
	if (!strcmp(authtype, NM_OPENCONNECT_AUTHTYPE_CERT_TPM))
		vpninfo->tpm = 1;
	else if (strcmp(authtype, NM_OPENCONNECT_AUTHTYPE_CERT)) {
		fprintf(stderr, "Unknown authentication type '%s'\n", authtype);
		return -EINVAL;
	}

	/* It's a certificate */
	vpninfo->cert = get_gconf_setting(gcl, config_path, NM_OPENCONNECT_KEY_USERCERT);
	if (!vpninfo->cert) {
		fprintf(stderr, "No user certificate configured\n");
		return -EINVAL;
	}

	vpninfo->sslkey = get_gconf_setting(gcl, config_path, NM_OPENCONNECT_KEY_PRIVKEY);
	if (!vpninfo->sslkey)
		vpninfo->sslkey = vpninfo->cert;

	return 0;
}

static int choose_vpnhost(struct openconnect_info *vpninfo)
{
	GtkWidget *dlg, *label, *combo;
	struct vpnhost *host;
	int i = 0, result;
	char *title;

	if (!lasthost)
		lasthost = vpninfo->hostname;

	title = get_title(vpninfo->vpn_name);
	dlg = gtk_dialog_new_with_buttons(title, NULL, GTK_DIALOG_MODAL,
					  GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					  GTK_STOCK_CONNECT, GTK_RESPONSE_ACCEPT,
					  NULL);
	g_free(title);

	GtkWidget *box;
	box = gtk_hbox_new (FALSE, 4);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dlg)->vbox), box, FALSE, FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER(box),8);
	gtk_widget_show (box);

	label = gtk_label_new("Select host");
	gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
	gtk_widget_show(label);
	
	combo = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(combo), vpninfo->hostname);
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);

	for (host = vpnhosts; host; host = host->next) {
		gtk_combo_box_append_text(GTK_COMBO_BOX(combo), host->hostname);
		i++;

		if (!strcmp(host->hostaddress, lasthost))
			gtk_combo_box_set_active(GTK_COMBO_BOX(combo), i);
	}
			
	gtk_box_pack_start(GTK_BOX(box), combo, FALSE, FALSE, 0);
	gtk_widget_show(combo);

	result = gtk_dialog_run(GTK_DIALOG(dlg));
	if (result != GTK_RESPONSE_ACCEPT) {
		if (last_message)
			g_free(last_message);
		last_message = NULL;
		return -EINVAL;
	}

	result = gtk_combo_box_get_active(GTK_COMBO_BOX(combo));

	if (result) {
		host = vpnhosts;

		for (i = 1; i < result; i++)
			host = host->next;

		vpninfo->hostname = host->hostaddress;
	}
	gtk_widget_destroy(dlg);
	gdk_flush();
	return 0;

}

static int get_cookie(struct openconnect_info *vpninfo)
{
	if (vpnhosts && choose_vpnhost(vpninfo))
		return -ENOENT;
	openconnect_init_openssl();
	openconnect_obtain_cookie(vpninfo);

	if (!vpninfo->cookie)
		return -ENOENT;
	return 0;
}

int write_new_config(struct openconnect_info *vpninfo, char *buf, int buflen)
{
	char *key = g_strdup_printf("%s/vpn/%s", config_path,
				    NM_OPENCONNECT_KEY_XMLCONFIG);
	gconf_client_set_string(gcl, key, buf, NULL);
	return 0;
}

void write_progress(struct openconnect_info *info, int level, const char *fmt, ...)
{
	va_list args;

	if (level <= PRG_INFO) {
		/* FIXME: Put into dialog box as they happen */

		if (last_message)
			g_free(last_message);
		va_start(args, fmt);
		last_message = g_strdup_vprintf(fmt, args);
		va_end(args);
		fprintf(stderr, "%s", last_message);
	}
}

static struct option long_options[] = {
	{"reprompt", 0, 0, 'r'},
	{"uuid", 1, 0, 'u'},
	{"name", 1, 0, 'n'},
	{"service", 1, 0, 's'},
	{NULL, 0, 0, 0},
};

int main (int argc, char **argv)
{
	char *vpn_name = NULL, *vpn_uuid = NULL, *vpn_service = NULL;
	int reprompt;
	struct openconnect_info *vpninfo;
	int opt;
	char read_buf;

	while ((opt = getopt_long(argc, argv, "ru:n:s:", long_options, NULL))) {
		if (opt < 0)
			break;

		switch(opt) {
		case 'r':
			reprompt = 1;
			break;

		case 'u':
			vpn_uuid = optarg;
			break;

		case 'n':
			vpn_name = optarg;
			break;

		case 's':
			vpn_service = optarg;
			break;

		default:
			fprintf(stderr, "Unknown option\n");
			return 1;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Superfluous command line options\n");
		return 1;
	}

	if (!vpn_uuid || !vpn_name || !vpn_service) {
		fprintf (stderr, "Have to supply UUID, name, and service\n");
		return 1;
	}

	if (strcmp(vpn_service, NM_DBUS_SERVICE_OPENCONNECT) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n",
			 NM_DBUS_SERVICE_OPENCONNECT);
		return 1;
	}

	vpninfo = malloc(sizeof(*vpninfo));
	memset(vpninfo, 0, sizeof(*vpninfo));

	vpninfo->urlpath = strdup("/");
	vpninfo->mtu = 1406;
	vpninfo->useragent = openconnect_create_useragent("OpenConnect VPN Agent (NetworkManager)");
	vpninfo->ssl_fd = -1;
	vpninfo->write_new_config = write_new_config;
	vpninfo->progress = write_progress;
	vpninfo->validate_peer_cert = validate_peer_cert;
	vpninfo->vpn_name = vpn_name;

	set_openssl_ui();

	if (get_config(vpn_uuid, vpninfo)) {
		fprintf(stderr, "Failed to find VPN UUID %s in gconf\n", vpn_uuid);
		return 1;
	}

	if (get_cookie(vpninfo) || !vpninfo->hostname || !vpninfo->cookie) {
		if (last_message) {
			char *title, *msg;
			GtkWidget *dlg;

			msg = g_strdup_printf("Error: %s", last_message);
			title = get_title (vpninfo->vpn_name);
			
			dlg = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_ERROR,
						     GTK_BUTTONS_OK, msg);
			gtk_window_set_title(GTK_WINDOW(dlg), title);
			gtk_window_set_skip_taskbar_hint(GTK_WINDOW(dlg), FALSE);
			gtk_window_set_skip_pager_hint(GTK_WINDOW(dlg), FALSE);

			g_free(msg);
			g_free(title);

			gtk_dialog_run(GTK_DIALOG(dlg));
			gtk_widget_destroy (dlg);
		}
		return 1;
	}
	printf("%s\n%s\n", NM_OPENCONNECT_KEY_GATEWAY, vpninfo->hostname);
	printf("%s\n%s\n", NM_OPENCONNECT_KEY_COOKIE, vpninfo->cookie);
	printf("\n\n");

	memset((void *)vpninfo->cookie, 0, strlen(vpninfo->cookie));

	fflush (stdout);
	(void)read(0, &read_buf, 1);

	return 0;
}
