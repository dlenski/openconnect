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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "openconnect-internal.h"

static int load_xml_conf_file(struct openconnect_info *vpninfo, char **ptr,
			      size_t *size)
{
	struct stat st;
	int fd;
	char *xmlfile;

	fd = open(vpninfo->xmlconfig, O_RDONLY);
	if (fd < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open XML config file: %s\n"),
			     strerror(errno));
		return 0;
	}

	if (fstat(fd, &st)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to fstat() XML config file: %s\n"),
			     strerror(errno));
		close(fd);
		return -1;
	}

	xmlfile = malloc(st.st_size);
	if (!xmlfile) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate %lu bytes for XML config file\n"),
			     (unsigned long)st.st_size);
		return -1;
	}

	if (read(fd, xmlfile, st.st_size) != st.st_size) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read XML config file: %s\n"),
			     strerror(errno));
		close(fd);
		free(xmlfile);
		return -1;
	}

	*ptr = xmlfile;
	*size = st.st_size;

	close(fd);

	return 1;
}

int config_lookup_host(struct openconnect_info *vpninfo, const char *host)
{
	int i, ret;
	size_t size;
	char *xmlfile;
	unsigned char sha1[SHA1_SIZE];
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *xml_node2;

	if (!vpninfo->xmlconfig)
		return 0;

	ret = load_xml_conf_file(vpninfo, &xmlfile, &size);
	if (ret <= 0) {
		if (ret == 0)
			fprintf(stderr, _("Treating host \"%s\" as a raw hostname\n"),
				host);
		return ret;
	}

	if (openconnect_sha1(sha1, xmlfile, size)) {
		fprintf(stderr, _("Failed to SHA1 existing file\n"));
		return -1;
	}

	for (i = 0; i < SHA1_SIZE; i++)
		sprintf(&vpninfo->xmlsha1[i*2], "%02x", sha1[i]);

	vpn_progress(vpninfo, PRG_TRACE, _("XML config file SHA1: %s\n"),
		     vpninfo->xmlsha1);

	xml_doc = xmlReadMemory(xmlfile, size, "noname.xml", NULL, 0);

	free(xmlfile);

	if (!xml_doc) {
		fprintf(stderr, _("Failed to parse XML config file %s\n"),
			vpninfo->xmlconfig);
		fprintf(stderr, _("Treating host \"%s\" as a raw hostname\n"),
			host);
		return 0;
	}
	xml_node = xmlDocGetRootElement(xml_doc);

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type == XML_ELEMENT_NODE &&
		    !strcmp((char *)xml_node->name, "ServerList")) {

			for (xml_node = xml_node->children; xml_node && !vpninfo->hostname;
			     xml_node = xml_node->next) {

				if (xml_node->type == XML_ELEMENT_NODE &&
				    !strcmp((char *)xml_node->name, "HostEntry")) {
					int match = 0;

					for (xml_node2 = xml_node->children;
					     match >= 0 && xml_node2; xml_node2 = xml_node2->next) {

						if (xml_node2->type != XML_ELEMENT_NODE)
							continue;

						if (!match && !strcmp((char *)xml_node2->name, "HostName")) {
							char *content = (char *)xmlNodeGetContent(xml_node2);
							if (content && !strcmp(content, host))
								match = 1;
							else
								match = -1;
							free(content);
						} else if (match &&
							   !strcmp((char *)xml_node2->name, "HostAddress")) {
							char *content = (char *)xmlNodeGetContent(xml_node2);
							if (content) {
								vpninfo->hostname = content;
								printf(_("Host \"%s\" has address \"%s\"\n"),
								       host, content);
							}
						} else if (match &&
							   !strcmp((char *)xml_node2->name, "UserGroup")) {
							char *content = (char *)xmlNodeGetContent(xml_node2);
							if (content) {
								free(vpninfo->urlpath);
								vpninfo->urlpath = content;
								printf(_("Host \"%s\" has UserGroup \"%s\"\n"),
								       host, content);
							}
						}
					}
				}

			}
			break;
		}
	}
	xmlFreeDoc(xml_doc);

	if (!vpninfo->hostname) {
		fprintf(stderr, _("Host \"%s\" not listed in config; treating as raw hostname\n"),
			host);
	}

	return 0;
}
