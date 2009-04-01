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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "openconnect.h"

int config_lookup_host(struct openconnect_info *vpninfo, const char *host)
{
	int fd, i;
	struct stat st;
	char *xmlfile;
	EVP_MD_CTX c;
	unsigned char sha1[SHA_DIGEST_LENGTH];
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *xml_node2;
	
	if (!vpninfo->xmlconfig)
		return 0;

	fd = open(vpninfo->xmlconfig, O_RDONLY);
	if (fd < 0) {
		perror("Open XML config file");
		fprintf(stderr, "Treating host \"%s\" as a raw hostname\n", host);
		return 0;
	}

	if (fstat(fd, &st)) {
		perror("fstat XML config file");
		return -1;
	}

	xmlfile = malloc(st.st_size);
	if (!xmlfile) {
		fprintf(stderr, "Could not allocate %zd bytes for XML config file\n", st.st_size);
		close(fd);
		return -1;
	}

	xmlfile = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (xmlfile == MAP_FAILED) {
		perror("mmap XML config file");
		close(fd);
		return -1;
	}

	EVP_MD_CTX_init(&c);
	EVP_Digest(xmlfile, st.st_size, sha1, NULL, EVP_sha1(), NULL);
	EVP_MD_CTX_cleanup(&c);

	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(&vpninfo->xmlsha1[i*2], "%02x", sha1[i]);

	vpninfo->progress(vpninfo, PRG_TRACE, "XML config file SHA1: %s\n", vpninfo->xmlsha1);

	xml_doc = xmlReadMemory(xmlfile, st.st_size, "noname.xml", NULL, 0);
	if (!xml_doc) {
		fprintf(stderr, "Failed to parse XML config file %s\n", vpninfo->xmlconfig);
		fprintf(stderr, "Treating host \"%s\" as a raw hostname\n", host);
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
						} else if (match &&
							   !strcmp((char *)xml_node2->name, "HostAddress")) {
							char *content = (char *)xmlNodeGetContent(xml_node2);
							if (content) {
								vpninfo->hostname = strdup(content);
								printf("Host \"%s\" has address \"%s\"\n",
								       host, content);
							}
						} else if (match &&
							   !strcmp((char *)xml_node2->name, "UserGroup")) {
							char *content = (char *)xmlNodeGetContent(xml_node2);
							if (content) {
								free(vpninfo->urlpath);
								vpninfo->urlpath = strdup(content);
								printf("Host \"%s\" has UserGroup \"%s\"\n",
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
		fprintf(stderr, "Host \"%s\" not listed in config; treating as raw hostname\n",
			host);
	}
		
	return 0;
}
