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
#ifdef ANDROID
#include <android/log.h>
#else
#include <syslog.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <openssl/ui.h>
#ifdef LIBPROXY_HDR
#include LIBPROXY_HDR
#endif

#include <getopt.h>

#include "openconnect-internal.h"

static int write_new_config(void *_vpninfo,
			    char *buf, int buflen);
static void write_progress(void *_vpninfo,
			   int level, const char *fmt, ...);
static void syslog_progress(void *_vpninfo,
			    int level, const char *fmt, ...);
static int validate_peer_cert(void *_vpninfo,
			      X509 *peer_cert, const char *reason);

int verbose = PRG_INFO;
int background;
int do_passphrase_from_fsid;
int nocertcheck;
int non_inter;

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
	OPT_PIDFILE,
	OPT_PASSWORD_ON_STDIN,
	OPT_PRINTCOOKIE,
	OPT_RECONNECT_TIMEOUT,
	OPT_SERVERCERT,
	OPT_USERAGENT,
	OPT_NON_INTER,
};

static struct option long_options[] = {
	{"background", 0, 0, 'b'},
	{"pid-file", 1, 0, OPT_PIDFILE},
	{"certificate", 1, 0, 'c'},
	{"sslkey", 1, 0, 'k'},
	{"cookie", 1, 0, 'C'},
	{"deflate", 0, 0, 'd'},
	{"no-deflate", 0, 0, 'D'},
	{"cert-expire-warning", 1, 0, 'e'},
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
	{"non-inter", 0, 0, OPT_NON_INTER},
	{NULL, 0, 0, 0},
};

static void usage(void)
{
	printf(_("Usage:  openconnect [options] <server>\n"));
	printf(_("Open client for Cisco AnyConnect VPN, version %s\n\n"), openconnect_version);
	printf("  -b, --background                %s\n", _("Continue in background after startup"));
	printf("      --pid-file=PIDFILE          %s\n", _("Write the daemons pid to this file"));
	printf("  -c, --certificate=CERT          %s\n", _("Use SSL client certificate CERT"));
	printf("  -e, --cert-expire-warning=DAYS  %s\n", _("Warn when certificate lifetime < DAYS"));
	printf("  -k, --sslkey=KEY                %s\n", _("Use SSL private key file KEY"));
	printf("  -K, --key-type=TYPE             %s\n", _("Private key type (PKCS#12 / TPM / PEM)"));
	printf("  -C, --cookie=COOKIE             %s\n", _("Use WebVPN cookie COOKIE"));
	printf("      --cookie-on-stdin           %s\n", _("Read cookie from standard input"));
	printf("  -d, --deflate                   %s\n", _("Enable compression (default)"));
	printf("  -D, --no-deflate                %s\n", _("Disable compression"));
	printf("      --force-dpd=INTERVAL        %s\n", _("Set minimum Dead Peer Detection interval"));
	printf("  -g, --usergroup=GROUP           %s\n", _("Set login usergroup"));
	printf("  -h, --help                      %s\n", _("Display help text"));
	printf("  -i, --interface=IFNAME          %s\n", _("Use IFNAME for tunnel interface"));
	printf("  -l, --syslog                    %s\n", _("Use syslog for progress messages"));
	printf("  -U, --setuid=USER               %s\n", _("Drop privileges after connecting"));
	printf("      --csd-user=USER             %s\n", _("Drop privileges during CSD execution"));
	printf("      --csd-wrapper=SCRIPT        %s\n", _("Run SCRIPT instead of CSD binary"));
	printf("  -m, --mtu=MTU                   %s\n", _("Request MTU from server"));
	printf("  -p, --key-password=PASS         %s\n", _("Set key passphrase or TPM SRK PIN"));
	printf("      --key-password-from-fsid    %s\n", _("Key passphrase is fsid of file system"));
	printf("  -P, --proxy=URL                 %s\n", _("Set proxy server"));
	printf("      --no-proxy                  %s\n", _("Disable proxy"));
	printf("      --libproxy                  %s\n", _("Use libproxy to automatically configure proxy"));
#ifndef LIBPROXY_HDR
	printf("                                  %s\n", _("(NOTE: libproxy disabled in this build)"));
#endif
	printf("  -q, --quiet                     %s\n", _("Less output"));
	printf("  -Q, --queue-len=LEN             %s\n", _("Set packet queue limit to LEN pkts"));
	printf("  -s, --script=SCRIPT             %s\n", _("Shell command line for using a vpnc-compatible config script"));
	printf("  -S, --script-tun                %s\n", _("Pass traffic to 'script' program, not tun"));
	printf("  -u, --user=NAME                 %s\n", _("Set login username"));
	printf("  -V, --version                   %s\n", _("Report version number"));
	printf("  -v, --verbose                   %s\n", _("More output"));
	printf("  -x, --xmlconfig=CONFIG          %s\n", _("XML config file"));
	printf("      --authgroup=GROUP           %s\n", _("Choose authentication login selection"));
	printf("      --cookieonly                %s\n", _("Fetch webvpn cookie only; don't connect"));
	printf("      --printcookie               %s\n", _("Print webvpn cookie before connecting"));
	printf("      --cafile=FILE               %s\n", _("Cert file for server verification"));
	printf("      --disable-ipv6              %s\n", _("Do not ask for IPv6 connectivity"));
	printf("      --dtls-ciphers=LIST         %s\n", _("OpenSSL ciphers to support for DTLS"));
	printf("      --no-dtls                   %s\n", _("Disable DTLS"));
	printf("      --no-http-keepalive         %s\n", _("Disable HTTP connection re-use"));
	printf("      --no-passwd                 %s\n", _("Disable password/SecurID authentication"));
	printf("      --no-cert-check             %s\n", _("Do not require server SSL cert to be valid"));
	printf("      --non-inter                 %s\n", _("Do not expect user input; exit if it is required"));
	printf("      --passwd-on-stdin           %s\n", _("Read password from standard input"));
	printf("      --reconnect-timeout         %s\n", _("Connection retry timeout in seconds"));
	printf("      --servercert=FINGERPRINT    %s\n", _("Server's certificate SHA1 fingerprint"));
	printf("      --useragent=STRING          %s\n", _("HTTP header User-Agent: field"));
	exit(1);
}

static void read_stdin(char **string)
{
	char *c = malloc(100);
	if (!c) {
		fprintf(stderr, _("Allocation failure for string from stdin\n"));
		exit(1);
	}
	if (!fgets(c, 100, stdin)) {
		perror(_("fgets (stdin)"));
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
	char *pidfile = NULL;
	FILE *fp = NULL;

#ifdef ENABLE_NLS
	setlocale(LC_ALL, "");
#endif

	openconnect_init_openssl();

	vpninfo = malloc(sizeof(*vpninfo));
	if (!vpninfo) {
		fprintf(stderr, _("Failed to allocate vpninfo structure\n"));
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
	vpninfo->cbdata = vpninfo;
	vpninfo->cert_expire_warning = 60 * 86400;

	if (!uname(&utsbuf))
		vpninfo->localname = utsbuf.nodename;
	else
		vpninfo->localname = "localhost";

	while ((opt = getopt_long(argc, argv, "bC:c:e:Ddg:hi:k:K:lpP:Q:qSs:U:u:Vvx:",
				  long_options, NULL))) {
		if (opt < 0)
			break;

		switch (opt) {
		case OPT_CAFILE:
			vpninfo->cafile = optarg;
			break;
		case OPT_PIDFILE:
			pidfile = optarg;
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
		case OPT_NON_INTER:
			non_inter = 1;
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
		case 'e':
			vpninfo->cert_expire_warning = 86400 * atoi(optarg);
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
				fprintf(stderr, _("Unknown certificate type '%s'\n"),
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
				fprintf(stderr, _("MTU %d too small\n"), vpninfo->mtu);
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
			autoproxy = 1;
			proxy = NULL;
			break;
		case OPT_NO_HTTP_KEEPALIVE:
			fprintf(stderr,
				_("Disabling all HTTP connection re-use due to --no-http-keepalive option.\n"
				  "If this helps, please report to <openconnect-devel@lists.infradead.org>.\n"));
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
					fprintf(stderr, _("Invalid user \"%s\"\n"),
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
					fprintf(stderr, _("Invalid user \"%s\"\n"),
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
				fprintf(stderr, _("Queue length zero not permitted; using 1\n"));
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
			printf(_("OpenConnect version %s\n"), openconnect_version);
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
		fprintf(stderr, _("No server specified\n"));
		usage();
	}

	if (!vpninfo->sslkey)
		vpninfo->sslkey = vpninfo->cert;

	vpninfo->progress = write_progress;

	if (autoproxy) {
#ifdef LIBPROXY_HDR
		vpninfo->proxy_factory = px_proxy_factory_new();
#else
		fprintf(stderr, _("This version of openconnect was built without libproxy support\n"));
		exit(1);
#endif
	}

	if (proxy && openconnect_set_http_proxy(vpninfo, strdup(proxy)))
		exit(1);

	if (use_syslog) {
#ifndef ANDROID
		openlog("openconnect", LOG_PID, LOG_DAEMON);
#endif
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
			fprintf(stderr, _("Failed to parse server URL '%s'\n"),
				url);
			exit(1);
		}
		if (scheme && strcmp(scheme, "https")) {
			fprintf(stderr, _("Only https:// permitted for server URL\n"));
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
		fprintf(stderr, _("Failed to obtain WebVPN cookie\n"));
		exit(1);
	}

	if (cookieonly) {
		printf("%s\n", vpninfo->cookie);
		if (cookieonly == 1)
			/* We use cookieonly=2 for 'print it and continue' */
			exit(0);
	}
	if (make_cstp_connection(vpninfo)) {
		fprintf(stderr, _("Creating SSL connection failed\n"));
		exit(1);
	}

	if (setup_tun(vpninfo)) {
		fprintf(stderr, _("Set up tun device failed\n"));
		exit(1);
	}

	if (uid != getuid()) {
		if (setuid(uid)) {
			fprintf(stderr, _("Failed to set uid %d\n"), uid);
			exit(1);
		}
	}

	if (vpninfo->dtls_attempt_period && setup_dtls(vpninfo))
		fprintf(stderr, _("Set up DTLS failed; using SSL instead\n"));

	vpn_progress(vpninfo, PRG_INFO,
		     _("Connected %s as %s%s%s, using %s\n"), vpninfo->ifname,
		     vpninfo->vpn_addr?:"",
		     (vpninfo->vpn_addr6 && vpninfo->vpn_addr)?" + ":"",
		     vpninfo->vpn_addr6?:"",
		     (vpninfo->dtls_fd == -1) ?
		     (vpninfo->deflate ? "SSL + deflate" : "SSL")
		     : "DTLS");

	if (!vpninfo->vpnc_script)
		vpn_progress(vpninfo, PRG_INFO,
			     _("No --script argument provided; DNS and routing are not configured\n"));

	if (background) {
		int pid;

		/* Open the pidfile before forking, so we can report errors
		   more sanely. It's *possible* that we'll fail to write to
		   it, but very unlikely. */
		if (pidfile != NULL) {
			fp = fopen(pidfile, "w");
			if (!fp) {
				fprintf(stderr, _("Failed to open '%s' for write: %s\n"),
					pidfile, strerror(errno));
				exit(1);
			}
		}
		if ((pid = fork())) {
			if (fp) {
				fprintf(fp, "%d\n", pid);
				fclose(fp);
			}
			vpn_progress(vpninfo, PRG_INFO,
				     _("Continuing in background; pid %d\n"),
				     pid);
			exit(0);
		}
		if (fp)
			fclose(fp);
	}
	vpn_mainloop(vpninfo);
	if (fp)
		unlink(pidfile);
	exit(1);
}

static int write_new_config(void *_vpninfo, char *buf, int buflen)
{
	struct openconnect_info *vpninfo = _vpninfo;
	int config_fd;
	int err;

	config_fd = open(vpninfo->xmlconfig, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if (config_fd < 0) {
		err = errno;
		fprintf(stderr, _("Failed to open %s for write: %s\n"),
			vpninfo->xmlconfig, strerror(err));
		return -err;
	}

	/* FIXME: We should actually write to a new tempfile, then rename */
	if(write(config_fd, buf, buflen) != buflen) {
		err = errno;
		fprintf(stderr, _("Failed to write config to %s: %s\n"),
			vpninfo->xmlconfig, strerror(err));

		return -err;
	}
	  
	return 0;
}

void write_progress(void *_vpninfo, int level, const char *fmt, ...)
{
	FILE *outf = level ? stdout : stderr;
	va_list args;

	if (verbose >= level) {
		va_start(args, fmt);
		vfprintf(outf, fmt, args);
		va_end(args);
	}
}

#ifdef ANDROID
void syslog_progress(void *_vpninfo, int level, const char *fmt, ...)
{
        static int l[4] = {
		ANDROID_LOG_ERROR,	/* PRG_ERR   */
		ANDROID_LOG_INFO,	/* PRG_INFO  */
		ANDROID_LOG_DEBUG,	/* PRG_DEBUG */
		ANDROID_LOG_DEBUG	/* PRG_TRACE */
        };
	va_list args, args2;

	if (verbose >= level) {
		va_start(args, fmt);
		va_copy(args2, args);
		__android_log_vprint(l[level], "openconnect", fmt, args);
		/* Android wants it to stderr too, so the GUI can scrape
		   it and display it as well as going to syslog */
		vfprintf(stderr, fmt, args2);
		va_end(args);
		va_end(args2);
	}
}
#else /* !ANDROID */
void syslog_progress(void *_vpninfo, int level, const char *fmt, ...)
{
	int priority = level ? LOG_INFO : LOG_NOTICE;
	va_list args;

	if (verbose >= level) {
		va_start(args, fmt);
		vsyslog(priority, fmt, args);
		va_end(args);
	}
}
#endif

struct accepted_cert {
	struct accepted_cert *next;
	char fingerprint[EVP_MAX_MD_SIZE * 2 + 1];
	char host[0];
} *accepted_certs;

static int validate_peer_cert(void *_vpninfo, X509 *peer_cert,
			      const char *reason)
{
	struct openconnect_info *vpninfo = _vpninfo;
	char fingerprint[EVP_MAX_MD_SIZE * 2 + 1];
	struct accepted_cert *this;
	int ret;

	if (nocertcheck)
		return 0;

	ret = openconnect_get_cert_sha1(vpninfo, peer_cert, fingerprint);
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

		fprintf(stderr,
			_("\nCertificate from VPN server \"%s\" failed verification.\n"
			  "Reason: %s\n"), vpninfo->hostname, reason);
		if (non_inter)
			return -EINVAL;

		fflush(stderr);

		ui = UI_new();
		UI_add_input_string(ui, _("Enter 'yes' to accept, 'no' to abort; anything else to view: "),
				    UI_INPUT_FLAG_ECHO, buf, 2, 5);
		ret = UI_process(ui);
		UI_free(ui);
		if (ret == -2)
			return -EINVAL;
		if (ret == -1)
			buf[0] = 0;

		if (!strcasecmp(buf, _("yes"))) {
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
		if (!strcasecmp(buf, _("no")))
			return -EINVAL;

		X509_print_fp(stderr, peer_cert);
		fprintf(stderr, _("SHA1 fingerprint: %s\n"), fingerprint);
	}
				
}
