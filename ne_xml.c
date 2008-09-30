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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ne_xml.h>

#include "anyconnect.h"

char *elem_names[3] = { "AnyConnectProfile", "ServerList", "HostEntry" };

static int startelm_cb_tree(void *userdata, int parent,
			    const char *nspace, const char *name,
			    const char **atts)
{
	/* Just walk down the tree */
	if (parent < 3 && !strcmp(name, elem_names[parent]))
		return parent + 1;
	return 0;
}

static int startelm_cb_hostname(void *userdata, int parent,
				const char *nspace, const char *name,
				const char **atts)
{
	struct anyconnect_info *vpninfo = userdata;

	if (!strcmp(name, "HostName")) {
		vpninfo->host_matched = 0;
		return 1;
	}
	return 0;
}

static int cdata_cb_hostname(void *userdata, int state,
			     const char *cdata, size_t len)
{
	struct anyconnect_info *vpninfo = userdata;

	if (!strncmp(vpninfo->hostarg, cdata, len))
		vpninfo->host_matched = 1;

	return 0;
}

static int startelm_cb_hostaddr(void *userdata, int parent,
				const char *nspace, const char *name,
				const char **atts)
{
	struct anyconnect_info *vpninfo = userdata;

	if (vpninfo->host_matched && !strcmp(name, "HostAddress"))
		return 1;
	return 0;
}

static int cdata_cb_hostaddr(void *userdata, int state,
			     const char *cdata, size_t len)
{
	struct anyconnect_info *vpninfo = userdata;
	char *hostname = malloc(len + 1);

	memcpy(hostname, cdata, len);
	hostname[len] = 0;
	vpninfo->hostname = hostname;
	return 1;
}

int config_lookup_host(struct anyconnect_info *vpninfo, const char *host)
{
	int fd, i;
	struct stat st;
	char *xmlfile;
	EVP_MD_CTX c;
	unsigned char sha1[SHA_DIGEST_LENGTH];
	ne_xml_parser *ne_parser;

	if (!vpninfo->xmlconfig) {
		vpninfo->hostname = host;
		return 0;
	}

	fd = open(vpninfo->xmlconfig, O_RDONLY);
	if (fd < 0) {
		perror("Open XML config file");
		fprintf(stderr, "Treating host \"%s\" as a raw hostname\n", host);
		vpninfo->hostname = host;
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

	if (verbose)
		printf("XML config file SHA1: %s\n", vpninfo->xmlsha1);

	vpninfo->hostarg = host;

	ne_parser = ne_xml_create();
	ne_xml_push_handler(ne_parser, startelm_cb_tree, NULL, NULL, vpninfo);
	ne_xml_push_handler(ne_parser, startelm_cb_hostname, cdata_cb_hostname, NULL, vpninfo);
	ne_xml_push_handler(ne_parser, startelm_cb_hostaddr, cdata_cb_hostaddr, NULL, vpninfo);
	ne_xml_parse(ne_parser, xmlfile, st.st_size);
	ne_xml_destroy(ne_parser);

	if (!vpninfo->hostname) {
		fprintf(stderr, "Host \"%s\" not listed in config; treating as raw hostname\n",
			host);
		vpninfo->hostname = host;
	} else if (verbose) {
		printf("Host \"%s\" mapped to address: %s\n", vpninfo->hostarg, vpninfo->hostname);
	}

	return 0;
}
