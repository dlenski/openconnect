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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <openssl/rand.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "anyconnect.h"

int verbose = 0;

static struct option long_options[] = {
	{"certificate", 1, 0, 'c'},
	{"sslkey", 1, 0, 'k'},
	{"cookie", 1, 0, 'C'},
	{"deflate", 0, 0, 'd'},
	{"no-deflate", 0, 0, 'D'},
	{"help", 0, 0, 'h'},
	{"interface", 1, 0, 'i'},
	{"mtu", 1, 0, 'm'},
	{"script", 1, 0, 's'},
	{"tpm-key", 1, 0, 't'},
	{"tpm-password", 1, 0, 'p'},
	{"user", 1, 0, 'u'},
	{"verbose", 1, 0, 'v'},
	{"cafile", 1, 0, '0'},
	{"no-dtls", 0, 0, '1'},
	{"xmlconfig", 1, 0, 'x'},
};

void usage(void)
{
	printf("Usage:  anyconnect [options] <server>\n");
	printf("Connect to Cisco AnyConnect server.\n\n");
	printf("  -c, --certificate=CERT          Use SSL client certificate CERT\n");
	printf("  -k, --sslkey=KEY                Use SSL private key file KEY\n");
	printf("  -C, --cookie=COOKIE             Use WebVPN cookie COOKIE\n");
	printf("  -d, --deflate                   Enable compression (default)\n");
	printf("  -D, --no-deflate                Disable compression\n");
	printf("  -h, --help                      Display help text\n");
	printf("  -i, --interface=IFNAME          Use IFNAME for tunnel interface\n");
	printf("  -m, --mtu=MTU                   Request MTU from server\n");
	printf("  -p, --tpm-password=PASS         Set TPM SRK PIN\n");
	printf("  -s, --script=SCRIPT             Use vpnc-compatible config script\n");
	printf("  -t, --tpm                       Use TPM engine for private key\n");
	printf("  -u, --user=NAME                 Set login username\n");
	printf("  -v, --verbose                   More output\n");
	printf("  -x, --xmlconfig=CONFIG          XML config file\n");
	printf("      --cafile=FILE               Cert file for server verification\n");
	printf("      --no-dtls                   Disable DTLS\n");
	exit(1);
}

int main(int argc, char **argv)
{
	struct anyconnect_info *vpninfo;
	struct utsname utsbuf;
	int opt;

	vpn_init_openssl();

	vpninfo = malloc(sizeof(*vpninfo));
	if (!vpninfo) {
		fprintf(stderr, "Failed to allocate vpninfo structure\n");
		exit(1);
	}
	memset(vpninfo, 0, sizeof(*vpninfo));

	/* Set up some defaults */
	vpninfo->ifname = "cisco0";
	vpninfo->tun_fd = vpninfo->ssl_fd = vpninfo->dtls_fd = -1;
	vpninfo->useragent = "Open AnyConnect VPN Agent v0.01";
	vpninfo->mtu = 1406;
	vpninfo->deflate = 1;
	vpninfo->trydtls = 1;

	if (RAND_bytes(vpninfo->dtls_secret, sizeof(vpninfo->dtls_secret)) != 1) {
		fprintf(stderr, "Failed to initialise DTLS secret\n");
		exit(1);
	}
	if (!uname(&utsbuf))
		vpninfo->localname = utsbuf.nodename;
	else
		vpninfo->localname = "localhost";

	while ((opt = getopt_long(argc, argv, "C:c:hvdDu:i:tk:p:s:hx:",
				  long_options, NULL))) {
		if (opt < 0)
			break;

		switch (opt) {
		case '0':
			vpninfo->cafile = optarg;
			break;
		case '1':
			vpninfo->trydtls = 0;
			break;
		case 'C':
			vpninfo->cookie = optarg;
			break;
		case 'c':
			vpninfo->cert = optarg;
			break;
		case 'k':
			vpninfo->sslkey = optarg;
			break;
		case 'd':
			vpninfo->deflate = 1;
			break;
		case 'D':
			vpninfo->deflate = 0;
			break;
		case 'h':
			usage();
		case 'i':
			vpninfo->ifname = optarg;
			break;
		case 'm':
			vpninfo->mtu = atol(optarg);
			if (vpninfo->mtu < 576) {
				fprintf(stderr, "MTU %d too small\n", vpninfo->mtu);
				vpninfo->mtu = 576;
			}
			break;
		case 'p':
			vpninfo->tpmpass = optarg;
			break;
		case 's':
			vpninfo->vpnc_script = optarg;
			break;
		case 't':
			vpninfo->tpm = 1;
			break;
		case 'u':
			vpninfo->username = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'x':
			vpninfo->xmlconfig = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind != argc - 1) {
		fprintf(stderr, "No server specified\n");
		usage();
	}

	if (!vpninfo->sslkey)
		vpninfo->sslkey = vpninfo->cert;

	if (config_lookup_host(vpninfo, argv[optind]))
		exit(1);

	if (!vpninfo->hostname)
		vpninfo->hostname = strdup(argv[optind]);
	vpninfo->urlpath = strdup("/");

	if (vpninfo->deflate) {
		if (inflateInit2(&vpninfo->inflate_strm, -12) ||
		    deflateInit2(&vpninfo->deflate_strm, Z_DEFAULT_COMPRESSION,
				 Z_DEFLATED, -12, 9, Z_DEFAULT_STRATEGY)) {
			fprintf(stderr, "Compression setup failed\n");
			vpninfo->deflate = 0;
		}
	}
	vpninfo->deflate_adler32 = 1;
	vpninfo->inflate_adler32 = 1;

	if (!vpninfo->cookie && obtain_cookie(vpninfo)) {
		fprintf(stderr, "Failed to obtain WebVPN cookie\n");
		exit(1);
	}

	if (make_ssl_connection(vpninfo)) {
		fprintf(stderr, "Creating SSL connection failed\n");
		exit(1);
	}
	
	if (setup_tun(vpninfo)) {
		fprintf(stderr, "Set up tun device failed\n");
		exit(1);
	}

	if (vpninfo->trydtls && setup_dtls(vpninfo))
		fprintf(stderr, "Set up DTLS failed; using SSL instead\n");

	printf("Connected as %s, using %s\n", vpninfo->vpn_addr,
	       (vpninfo->dtls_fd==-1)?(vpninfo->deflate?"SSL + deflate":"SSL"):"DTLS");

	vpn_mainloop(vpninfo);
	exit(1);
}
