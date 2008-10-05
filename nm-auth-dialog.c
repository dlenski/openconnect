/*
 * Open AnyConnect (SSL + DTLS) client
 *
 * © 2008 David Woodhouse <dwmw2@infradead.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
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

#include <gconf/gconf-client.h>

#include "auth-dlg-settings.h"
#include "version.h"
#include "openconnect.h"

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

static GConfClient *gcl;
static char *config_path;

static int get_config(char *vpn_uuid, struct openconnect_info *vpninfo)
{
	char *authtype;

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


static int get_cookie(const char *vpn_uuid, struct openconnect_info *vpninfo)
{
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

int verbose = 0;

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

	set_openssl_ui();

	if (get_config(vpn_uuid, vpninfo)) {
		fprintf(stderr, "Failed to find VPN UUID %s in gconf\n", vpn_uuid);
		return 1;
	}

	if (get_cookie(vpn_uuid, vpninfo) || !vpninfo->hostname || !vpninfo->cookie)
		return 1;

	printf("%s\n%s\n", NM_OPENCONNECT_KEY_GATEWAY, vpninfo->hostname);
	printf("%s\n%s\n", NM_OPENCONNECT_KEY_COOKIE, vpninfo->cookie);
	printf("\n\n");

	memset((void *)vpninfo->cookie, 0, strlen(vpninfo->cookie));

	fflush (stdout);
	(void)read(0, &read_buf, 1);

	return 0;
}
