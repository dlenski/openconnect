/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2010 Intel Corporation.
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
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/syslog.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <openssl/ui.h>
#ifdef OPENCONNECT_LIBPROXY
#include LIBPROXY_HDR
#endif

#define _GNU_SOURCE
#include <getopt.h>

#include "openconnect-internal.h"

static int write_new_config(struct openconnect_info *vpninfo, char *buf, int buflen);
static void write_progress(struct openconnect_info *info, int level, const char *fmt, ...);
static void syslog_progress(struct openconnect_info *info, int level, const char *fmt, ...);
static int validate_peer_cert(struct openconnect_info *info, X509 *peer_cert, const char *reason);

int verbose = PRG_INFO;
int background;
int do_passphrase_from_fsid;
int nocertcheck;

enum {
	OPT_AUTHGROUP = 0x100,
	OPT_CAFILE,
	OPT_COOKIEONLY,
	OPT_COOKIE_ON_STDIN,
	OPT_CSD_USER,
	OPT_CSD_WRAPPER,
	OPT_DISABLE_IPV6,
	OPT_DTLS_CIPHERS,
	OPT_FORCE_DPD,
	OPT_KEY_PASSWORD_FROM_FSID,
	OPT_LIBPROXY,
	OPT_NO_CERT_CHECK,
	OPT_NO_DTLS,
	OPT_NO_HTTP_KEEPALIVE,
	OPT_NO_PASSWD,
	OPT_NO_PROXY,
	OPT_PASSWORD_ON_STDIN,
	OPT_PRINTCOOKIE,
	OPT_RECONNECT_TIMEOUT,
	OPT_SERVERCERT,
	OPT_USERAGENT,
};

static struct option long_options[] = {
	{"background", 0, 0, 'b'},
	{"certificate", 1, 0, 'c'},
	{"sslkey", 1, 0, 'k'},
	{"cookie", 1, 0, 'C'},
	{"deflate", 0, 0, 'd'},
	{"no-deflate", 0, 0, 'D'},
	{"usergroup", 1, 0, 'g'},
	{"help", 0, 0, 'h'},
	{"interface", 1, 0, 'i'},
	{"mtu", 1, 0, 'm'},
	{"setuid", 1, 0, 'U'},
	{"script", 1, 0, 's'},
	{"script-tun", 0, 0, 'S'},
	{"syslog", 0, 0, 'l'},
	{"key-type", 1, 0, 'K'},
	{"key-password", 1, 0, 'p'},
	{"proxy", 1, 0, 'P'},
	{"user", 1, 0, 'u'},
	{"verbose", 0, 0, 'v'},
	{"version", 0, 0, 'V'},
	{"cafile", 1, 0, OPT_CAFILE},
	{"no-dtls", 0, 0, OPT_NO_DTLS},
	{"cookieonly", 0, 0, OPT_COOKIEONLY},
	{"printcookie", 0, 0, OPT_PRINTCOOKIE},
	{"quiet", 0, 0, 'q'},
	{"queue-len", 1, 0, 'Q'},
	{"xmlconfig", 1, 0, 'x'},
	{"cookie-on-stdin", 0, 0, OPT_COOKIE_ON_STDIN},
	{"passwd-on-stdin", 0, 0, OPT_PASSWORD_ON_STDIN},
	{"no-passwd", 0, 0, OPT_NO_PASSWD},
	{"reconnect-timeout", 1, 0, OPT_RECONNECT_TIMEOUT},
	{"dtls-ciphers", 1, 0, OPT_DTLS_CIPHERS},
	{"authgroup", 1, 0, OPT_AUTHGROUP},
	{"servercert", 1, 0, OPT_SERVERCERT},
	{"key-password-from-fsid", 0, 0, OPT_KEY_PASSWORD_FROM_FSID},
	{"useragent", 1, 0, OPT_USERAGENT},
	{"csd-user", 1, 0, OPT_CSD_USER},
	{"csd-wrapper", 1, 0, OPT_CSD_WRAPPER},
	{"disable-ipv6", 0, 0, OPT_DISABLE_IPV6},
	{"no-proxy", 0, 0, OPT_NO_PROXY},
	{"libproxy", 0, 0, OPT_LIBPROXY},
	{"no-http-keepalive", 0, 0, OPT_NO_HTTP_KEEPALIVE},
	{"no-cert-check", 0, 0, OPT_NO_CERT_CHECK},
	{"force-dpd", 1, 0, OPT_FORCE_DPD},
	{NULL, 0, 0, 0},
};

void usage(void)
{
	printf("Usage:  openconnect [options] <server>\n");
	printf("Open client for Cisco AnyConnect VPN, version %s\n\n", openconnect_version);
	printf("  -b, --background                Continue in background after startup\n");
	printf("  -c, --certificate=CERT          Use SSL client certificate CERT\n");
	printf("  -k, --sslkey=KEY                Use SSL private key file KEY\n");
	printf("  -K, --key-type=TYPE             Private key type (PKCS#12 / TPM / PEM)\n");
	printf("  -C, --cookie=COOKIE             Use WebVPN cookie COOKIE\n");
	printf("      --cookie-on-stdin           Read cookie from standard input\n");
	printf("  -d, --deflate                   Enable compression (default)\n");
	printf("  -D, --no-deflate                Disable compression\n");
	printf("      --force-dpd=INTERVAL        Set minimum Dead Peer Detection interval\n");
	printf("  -g, --usergroup=GROUP           Set login usergroup\n");
	printf("  -h, --help                      Display help text\n");
	printf("  -i, --interface=IFNAME          Use IFNAME for tunnel interface\n");
	printf("  -l, --syslog                    Use syslog for progress messages\n");
	printf("  -U, --setuid=USER               Drop privileges after connecting\n");
	printf("      --csd-user=USER             Drop privileges during CSD execution\n");
	printf("      --csd-wrapper=SCRIPT        Run SCRIPT instead of CSD binary\n");
	printf("  -m, --mtu=MTU                   Request MTU from server\n");
	printf("  -p, --key-password=PASS         Set key passphrase or TPM SRK PIN\n");
	printf("      --key-password-from-fsid    Key passphrase is fsid of file system\n");
	printf("  -P, --proxy=URL                 Set proxy server\n");
	printf("      --no-proxy                  Disable proxy\n");
	printf("      --libproxy                  Use libproxy to automatically configure proxy\n");
#ifndef OPENCONNECT_LIBPROXY
	printf("                                  (NOTE: libproxy disabled in this build)\n");
#endif
	printf("  -q, --quiet                     Less output\n");
	printf("  -Q, --queue-len=LEN             Set packet queue limit to LEN pkts\n");
	printf("  -s, --script=SCRIPT             Use vpnc-compatible config script\n");
	printf("  -S, --script-tun                Pass traffic to 'script' program, not tun\n");
	printf("  -u, --user=NAME                 Set login username\n");
	printf("  -V, --version                   Report version number\n");
	printf("  -v, --verbose                   More output\n");
	printf("  -x, --xmlconfig=CONFIG          XML config file\n");
	printf("      --authgroup=GROUP           Choose authentication login selection\n");
	printf("      --cookieonly                Fetch webvpn cookie only; don't connect\n");
	printf("      --printcookie               Print webvpn cookie before connecting\n");
	printf("      --cafile=FILE               Cert file for server verification\n");
	printf("      --disable-ipv6              Do not ask for IPv6 connectivity\n");
	printf("      --dtls-ciphers=LIST         OpenSSL ciphers to support for DTLS\n");
	printf("      --no-dtls                   Disable DTLS\n");
	printf("      --no-http-keepalive         Disable HTTP connection re-use\n");
	printf("      --no-passwd                 Disable password/SecurID authentication\n");
	printf("      --no-cert-check             Do not require server SSL cert to be valid\n");
	printf("      --passwd-on-stdin           Read password from standard input\n");
	printf("      --reconnect-timeout         Connection retry timeout in seconds\n");
	printf("      --servercert=FINGERPRINT    Server's certificate SHA1 fingerprint\n");
	printf("      --useragent=STRING          HTTP header User-Agent: field\n");
	exit(1);
}

static void read_stdin(char **string)
{
	char *c = malloc(100);
	if (!c) {
		fprintf(stderr, "Allocation failure for string from stdin\n");
		exit(1);
	}
	if (!fgets(c, 100, stdin)) {
		perror("fgets (stdin)");
		exit(1);
	}

	*string = c;

	c = strchr(*string, '\n');
	if (c)
		*c = 0;
}
static void handle_sigusr(int sig)
{
	if (sig == SIGUSR1)
		verbose = PRG_TRACE;
	else if (sig == SIGUSR2)
		verbose = PRG_INFO;
}

int main(int argc, char **argv)
{
	struct openconnect_info *vpninfo;
	struct utsname utsbuf;
	struct sigaction sa;
	int cookieonly = 0;
	int use_syslog = 0;
	char *proxy = getenv("https_proxy");
	int autoproxy = 0;
	uid_t uid = getuid();
	int opt;

	openconnect_init_openssl();

	vpninfo = malloc(sizeof(*vpninfo));
	if (!vpninfo) {
		fprintf(stderr, "Failed to allocate vpninfo structure\n");
		exit(1);
	}
	memset(vpninfo, 0, sizeof(*vpninfo));

	/* Set up some defaults */
	vpninfo->tun_fd = vpninfo->ssl_fd = vpninfo->dtls_fd = vpninfo->new_dtls_fd = -1;
	vpninfo->useragent = openconnect_create_useragent("Open AnyConnect VPN Agent");
	vpninfo->mtu = 1406;
	vpninfo->deflate = 1;
	vpninfo->dtls_attempt_period = 60;
	vpninfo->max_qlen = 10;
	vpninfo->reconnect_interval = RECONNECT_INTERVAL_MIN;
	vpninfo->reconnect_timeout = 300;
	vpninfo->uid_csd = 0;
	vpninfo->uid_csd_given = 0;
	vpninfo->validate_peer_cert = validate_peer_cert;

	if (!uname(&utsbuf))
		vpninfo->localname = utsbuf.nodename;
	else
		vpninfo->localname = "localhost";

	while ((opt = getopt_long(argc, argv, "bC:c:Ddg:hi:k:K:lpP:Q:qSs:U:u:Vvx:",
				  long_options, NULL))) {
		if (opt < 0)
			break;

		switch (opt) {
		case OPT_CAFILE:
			vpninfo->cafile = optarg;
			break;
		case OPT_SERVERCERT:
			vpninfo->servercert = optarg;
			break;
		case OPT_NO_DTLS:
			vpninfo->dtls_attempt_period = 0;
			break;
		case OPT_COOKIEONLY:
			cookieonly = 1;
			break;
		case OPT_PRINTCOOKIE:
			cookieonly = 2;
			break;
		case OPT_COOKIE_ON_STDIN:
			read_stdin(&vpninfo->cookie);
			/* If the cookie is empty, ignore it */
			if (! *vpninfo->cookie) {
				vpninfo->cookie = NULL;
			}
			break;
		case OPT_PASSWORD_ON_STDIN:
			read_stdin(&vpninfo->password);
			break;
		case OPT_NO_PASSWD:
			vpninfo->nopasswd = 1;
			break;
		case OPT_RECONNECT_TIMEOUT:
			vpninfo->reconnect_timeout = atoi(optarg);
			break;
		case OPT_DTLS_CIPHERS:
			vpninfo->dtls_ciphers = optarg;
			break;
		case OPT_AUTHGROUP:
			vpninfo->authgroup = optarg;
			break;
		case 'b':
			background = 1;
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
		case 'K':
			if (!strcasecmp(optarg, "PKCS#12") ||
			    !strcasecmp(optarg, "PKCS12")) {
				vpninfo->cert_type = CERT_TYPE_PKCS12;
			} else if (!strcasecmp(optarg, "TPM")) {
				vpninfo->cert_type = CERT_TYPE_TPM;
			} else if (!strcasecmp(optarg, "PEM")) {
				vpninfo->cert_type = CERT_TYPE_PEM;
			} else {
				fprintf(stderr, "Unknown certificate type '%s'\n",
					optarg);
				usage();
			}
		case 'd':
			vpninfo->deflate = 1;
			break;
		case 'D':
			vpninfo->deflate = 0;
			break;
		case 'g':
			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup(optarg);
			break;
		case 'h':
			usage();
		case 'i':
			vpninfo->ifname = optarg;
			break;
		case 'l':
			use_syslog = 1;
			break;
		case 'm':
			vpninfo->mtu = atol(optarg);
			if (vpninfo->mtu < 576) {
				fprintf(stderr, "MTU %d too small\n", vpninfo->mtu);
				vpninfo->mtu = 576;
			}
			break;
		case 'p':
			vpninfo->cert_password = optarg;
			break;
		case 'P': 
			proxy = optarg;
			autoproxy = 0;
			break;
		case OPT_NO_PROXY:
			autoproxy = 0;
			proxy = NULL;
		case OPT_LIBPROXY:
#ifndef OPENCONNECT_LIBPROXY
			fprintf(stderr, "This version of openconnect was built without libproxy support\n");
			exit(1);
#endif
			autoproxy = 1;
			proxy = NULL;
			break;
		case OPT_NO_HTTP_KEEPALIVE:
			fprintf(stderr, "Disabling all HTTP connection re-use due to --no-http-keepalive option.\n"
				"If this helps, please report to <openconnect-devel@lists.infradead.org>.\n");
			vpninfo->no_http_keepalive = 1;
			break;
		case OPT_NO_CERT_CHECK:
			nocertcheck = 1;
			break;
		case 's':
			vpninfo->vpnc_script = optarg;
			break;
		case 'S':
			vpninfo->script_tun = 1;
			break;
		case 'u':
			vpninfo->username = optarg;
			break;
		case 'U': {
			char *strend;
			uid = strtol(optarg, &strend, 0);
			if (strend[0]) {
				struct passwd *pw = getpwnam(optarg);
				if (!pw) {
					fprintf(stderr, "Invalid user \"%s\"\n",
						optarg);
					exit(1);
				}
				uid = pw->pw_uid;
			}
			break;
		}
		case OPT_CSD_USER: {
			char *strend;
			vpninfo->uid_csd = strtol(optarg, &strend, 0);
			if (strend[0]) {
				struct passwd *pw = getpwnam(optarg);
				if (!pw) {
					fprintf(stderr, "Invalid user \"%s\"\n",
						optarg);
					exit(1);
				}
				vpninfo->uid_csd = pw->pw_uid;
			}
			vpninfo->uid_csd_given = 1;
			break;
		}
		case OPT_CSD_WRAPPER:
			vpninfo->csd_wrapper = optarg;
			break;
		case OPT_DISABLE_IPV6:
			vpninfo->disable_ipv6 = 1;
			break;
		case 'Q':
			vpninfo->max_qlen = atol(optarg);
			if (!vpninfo->max_qlen) {
				fprintf(stderr, "Queue length zero not permitted; using 1\n");
				vpninfo->max_qlen = 1;
			}
			break;
		case 'q':
			verbose = PRG_ERR;
			break;
		case 'v':
			verbose = PRG_TRACE;
			break;
		case 'V':
			printf("OpenConnect version %s\n", openconnect_version);
			exit(0);
		case 'x':
			vpninfo->xmlconfig = optarg;
			vpninfo->write_new_config = write_new_config;
			break;
		case OPT_KEY_PASSWORD_FROM_FSID:
			do_passphrase_from_fsid = 1;
			break;
		case OPT_USERAGENT:
			free(vpninfo->useragent);
			vpninfo->useragent = optarg;
			break;
		case OPT_FORCE_DPD:
			vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = atoi(optarg);
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

	vpninfo->progress = write_progress;

#ifdef OPENCONNECT_LIBPROXY
	if (autoproxy)
		vpninfo->proxy_factory = px_proxy_factory_new();
#endif
	if (proxy && openconnect_set_http_proxy(vpninfo, proxy))
		exit(1);

	if (use_syslog) {
		openlog("openconnect", LOG_PID, LOG_DAEMON);
		vpninfo->progress = syslog_progress;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sigusr;

	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	if (vpninfo->sslkey && do_passphrase_from_fsid)
		openconnect_passphrase_from_fsid(vpninfo);

	if (config_lookup_host(vpninfo, argv[optind]))
		exit(1);

	if (!vpninfo->hostname) {
		char *url = strdup(argv[optind]);
		char *scheme;
		char *group;

		if (internal_parse_url(url, &scheme, &vpninfo->hostname, &vpninfo->port,
			      &group, 443)) {
			fprintf(stderr, "Failed to parse server URL '%s'\n",
				url);
			exit(1);
		}
		if (scheme && strcmp(scheme, "https")) {
			fprintf(stderr, "Only https:// permitted for server URL\n");
			exit(1);
		}
		if (group) {
			free(vpninfo->urlpath);
			vpninfo->urlpath = group;
		}
		free(scheme);
		free(url);
	}

#ifdef SSL_UI
	set_openssl_ui();
#endif

	if (!vpninfo->cookie && openconnect_obtain_cookie(vpninfo)) {
		fprintf(stderr, "Failed to obtain WebVPN cookie\n");
		exit(1);
	}

	if (cookieonly) {
		printf("%s\n", vpninfo->cookie);
		if (cookieonly == 1)
			/* We use cookieonly=2 for 'print it and continue' */
			exit(0);
	}
	if (make_cstp_connection(vpninfo)) {
		fprintf(stderr, "Creating SSL connection failed\n");
		exit(1);
	}

	if (setup_tun(vpninfo)) {
		fprintf(stderr, "Set up tun device failed\n");
		exit(1);
	}

	if (uid != getuid()) {
		if (setuid(uid)) {
			fprintf(stderr, "Failed to set uid %d\n", uid);
			exit(1);
		}
	}

	if (vpninfo->dtls_attempt_period && setup_dtls(vpninfo))
		fprintf(stderr, "Set up DTLS failed; using SSL instead\n");

	vpninfo->progress(vpninfo, PRG_INFO,
			  "Connected %s as %s%s%s, using %s\n", vpninfo->ifname,
			  vpninfo->vpn_addr?:"",
			  (vpninfo->vpn_addr6 && vpninfo->vpn_addr)?" + ":"",
			  vpninfo->vpn_addr6?:"",
			  (vpninfo->dtls_fd == -1) ?
			      (vpninfo->deflate ? "SSL + deflate" : "SSL")
			      : "DTLS");

	if (!vpninfo->vpnc_script)
		vpninfo->progress(vpninfo, PRG_INFO,
				  "No --script argument provided; DNS and routing are not configured\n");

	if (background) {
		int pid;
		if ((pid = fork())) {
			vpninfo->progress(vpninfo, PRG_INFO,
					  "Continuing in background; pid %d\n",
					  pid);
			exit(0);
		}
	}
	vpn_mainloop(vpninfo);
	exit(1);
}

static int write_new_config(struct openconnect_info *vpninfo, char *buf, int buflen)
{
	int config_fd;
	int err;

	config_fd = open(vpninfo->xmlconfig, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if (config_fd < 0) {
		err = errno;
		fprintf(stderr, "Failed to open %s for write: %s\n",
			vpninfo->xmlconfig, strerror(err));
		return -err;
	}

	/* FIXME: We should actually write to a new tempfile, then rename */
	if(write(config_fd, buf, buflen) != buflen) {
		err = errno;
		fprintf(stderr, "Failed to write config to %s: %s\n",
			vpninfo->xmlconfig, strerror(err));

		return -err;
	}
	  
	return 0;
}

void write_progress(struct openconnect_info *info, int level, const char *fmt, ...)
{
	FILE *outf = level ? stdout : stderr;
	va_list args;

	if (verbose >= level) {
		va_start(args, fmt);
		vfprintf(outf, fmt, args);
		va_end(args);
	}
}

void syslog_progress(struct openconnect_info *info, int level,
		     const char *fmt, ...)
{
	int priority = level ? LOG_INFO : LOG_NOTICE;
	va_list args;

	if (verbose >= level) {
		va_start(args, fmt);
		vsyslog(priority, fmt, args);
		va_end(args);
	}
}


struct accepted_cert {
	struct accepted_cert *next;
	char fingerprint[EVP_MAX_MD_SIZE * 2 + 1];
	char host[0];
} *accepted_certs;

static int validate_peer_cert(struct openconnect_info *vpninfo, X509 *peer_cert,
			      const char *reason)
{
	char fingerprint[EVP_MAX_MD_SIZE * 2 + 1];
	struct accepted_cert *this;
	int ret;

	if (nocertcheck)
		return 0;

	ret = get_cert_sha1_fingerprint(vpninfo, peer_cert, fingerprint);
	if (ret)
		return ret;

	for (this = accepted_certs; this; this = this->next) {
		if (!strcasecmp(this->host, vpninfo->hostname) &&
		    !strcasecmp(this->fingerprint, fingerprint))
			return 0;
	}
	
	while (1) {
		UI *ui;
		char buf[6];
		int ret;

		fprintf(stderr, "\nCertificate from VPN server \"%s\" failed verification.\n"
			"Reason: %s\n",	vpninfo->hostname, reason);
		fflush(stderr);

		ui = UI_new();
		UI_add_input_string(ui, "Enter 'yes' to accept, 'no' to abort; anything else to view: ",
				    UI_INPUT_FLAG_ECHO, buf, 2, 5);
		ret = UI_process(ui);
		UI_free(ui);
		if (ret == -2)
			return -EINVAL;
		if (ret == -1)
			buf[0] = 0;

		if (!strcasecmp(buf, "yes")) {
			struct accepted_cert *newcert = malloc(sizeof(*newcert) +
							       strlen(vpninfo->hostname) + 1);
			if (newcert) {
				newcert->next = accepted_certs;
				accepted_certs = newcert;
				strcpy(newcert->fingerprint, fingerprint);
				strcpy(newcert->host, vpninfo->hostname);
			}
			return 0;
		}
		if (!strcasecmp(buf, "no"))
			return -EINVAL;

		X509_print_fp(stderr, peer_cert);
	}
				
}
