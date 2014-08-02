/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>
#include <errno.h>

#include "openconnect-internal.h"

ssize_t read_file_into_string(struct openconnect_info *vpninfo, const char *fname,
			      char **ptr)
{
	int fd, len;
	struct stat st;
	char *buf;

	/* FIXME: UTF-8 fname may need conversion */
	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open %s: %s\n"),
			     fname, strerror(errno));
		return -ENOENT;
	}

	if (fstat(fd, &st)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to fstat() %s: %s\n"),
			     fname, strerror(errno));
		close(fd);
		return -EIO;
	}

	len = st.st_size;
	buf = malloc(len + 1);
	if (!buf) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate %d bytes for %s\n"),
			     len + 1, fname);
		close(fd);
		return -ENOMEM;
	}

	if (read(fd, buf, len) != len) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read %s: %s\n"),
			     fname, strerror(errno));
		free(buf);
		close(fd);
		return -EIO;
	}

	buf[len] = 0;
	close(fd);
	*ptr = buf;
	return len;
}

int config_lookup_host(struct openconnect_info *vpninfo, const char *host)
{
	int i;
	ssize_t size;
	char *xmlfile;
	unsigned char sha1[SHA1_SIZE];
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *xml_node2;

	if (!vpninfo->xmlconfig)
		return 0;

	size = read_file_into_string(vpninfo, vpninfo->xmlconfig, &xmlfile);
	if (size == -ENOENT) {
		fprintf(stderr, _("Treating host \"%s\" as a raw hostname\n"), host);
		return 0;
	} else if (size <= 0) {
		return size;
	}

	if (openconnect_sha1(sha1, xmlfile, size)) {
		fprintf(stderr, _("Failed to SHA1 existing file\n"));
		return -1;
	}

	for (i = 0; i < SHA1_SIZE; i++)
		snprintf(&vpninfo->xmlsha1[i*2], 3, "%02x", sha1[i]);

	vpn_progress(vpninfo, PRG_DEBUG, _("XML config file SHA1: %s\n"),
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
