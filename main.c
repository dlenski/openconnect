/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
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

#ifdef HAVE_GETLINE
/* Various BSD systems require this for getline() to be visible */
#define _WITH_GETLINE
#endif

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
#include <termios.h>
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
			      OPENCONNECT_X509 *peer_cert,
			      const char *reason);
static int process_auth_form(void *_vpninfo,
			     struct oc_auth_form *form);
static void init_stoken(struct openconnect_info *vpninfo,
			const char *token_str);

/* A sanity check that the openconnect executable is running against a
   library of the same version */
#define openconnect_version_str openconnect_binary_version
#include "version.c"
#undef openconnect_version_str

int verbose = PRG_INFO;
int background;
int do_passphrase_from_fsid;
int nocertcheck;
int non_inter;
int cookieonly;

enum {
	OPT_AUTHENTICATE = 0x100,
	OPT_AUTHGROUP,
	OPT_BASEMTU,
	OPT_CAFILE,
	OPT_CONFIGFILE,
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
	OPT_DTLS_LOCAL_PORT,
	OPT_STOKEN,
};

#ifdef __sun__
/*
 * The 'name' field in Solaris 'struct option' lacks the 'const', and causes
 * lots of warnings unless we cast it... https://www.illumos.org/issues/1881
*/
#define OPTION(name, arg, abbrev) {(char *)name, arg, NULL, abbrev}
#else
#define OPTION(name, arg, abbrev) {name, arg, NULL, abbrev}
#endif

static struct option long_options[] = {
	OPTION("background", 0, 'b'),
	OPTION("pid-file", 1, OPT_PIDFILE),
	OPTION("certificate", 1, 'c'),
	OPTION("sslkey", 1, 'k'),
	OPTION("cookie", 1, 'C'),
	OPTION("deflate", 0, 'd'),
	OPTION("no-deflate", 0, 'D'),
	OPTION("cert-expire-warning", 1, 'e'),
	OPTION("usergroup", 1, 'g'),
	OPTION("help", 0, 'h'),
	OPTION("interface", 1, 'i'),
	OPTION("mtu", 1, 'm'),
	OPTION("base-mtu", 1, OPT_BASEMTU),
	OPTION("setuid", 1, 'U'),
	OPTION("script", 1, 's'),
	OPTION("script-tun", 0, 'S'),
	OPTION("syslog", 0, 'l'),
	OPTION("key-password", 1, 'p'),
	OPTION("proxy", 1, 'P'),
	OPTION("user", 1, 'u'),
	OPTION("verbose", 0, 'v'),
	OPTION("version", 0, 'V'),
	OPTION("cafile", 1, OPT_CAFILE),
	OPTION("config", 1, OPT_CONFIGFILE),
	OPTION("no-dtls", 0, OPT_NO_DTLS),
	OPTION("authenticate", 0, OPT_AUTHENTICATE),
	OPTION("cookieonly", 0, OPT_COOKIEONLY),
	OPTION("printcookie", 0, OPT_PRINTCOOKIE),
	OPTION("quiet", 0, 'q'),
	OPTION("queue-len", 1, 'Q'),
	OPTION("xmlconfig", 1, 'x'),
	OPTION("cookie-on-stdin", 0, OPT_COOKIE_ON_STDIN),
	OPTION("passwd-on-stdin", 0, OPT_PASSWORD_ON_STDIN),
	OPTION("no-passwd", 0, OPT_NO_PASSWD),
	OPTION("reconnect-timeout", 1, OPT_RECONNECT_TIMEOUT),
	OPTION("dtls-ciphers", 1, OPT_DTLS_CIPHERS),
	OPTION("authgroup", 1, OPT_AUTHGROUP),
	OPTION("servercert", 1, OPT_SERVERCERT),
	OPTION("key-password-from-fsid", 0, OPT_KEY_PASSWORD_FROM_FSID),
	OPTION("useragent", 1, OPT_USERAGENT),
	OPTION("csd-user", 1, OPT_CSD_USER),
	OPTION("csd-wrapper", 1, OPT_CSD_WRAPPER),
	OPTION("disable-ipv6", 0, OPT_DISABLE_IPV6),
	OPTION("no-proxy", 0, OPT_NO_PROXY),
	OPTION("libproxy", 0, OPT_LIBPROXY),
	OPTION("no-http-keepalive", 0, OPT_NO_HTTP_KEEPALIVE),
	OPTION("no-cert-check", 0, OPT_NO_CERT_CHECK),
	OPTION("force-dpd", 1, OPT_FORCE_DPD),
	OPTION("non-inter", 0, OPT_NON_INTER),
	OPTION("dtls-local-port", 1, OPT_DTLS_LOCAL_PORT),
	OPTION("stoken", 2, OPT_STOKEN),
	OPTION(NULL, 0, 0)
};

static void helpmessage(void)
{
	printf(_("For assistance with OpenConnect, please see the web page at\n"
		 "  http://www.infradead.org/openconnect/mail.html\n"));
}

static void print_build_opts(void)
{
	const char *comma = ", ", *sep = comma + 1;

#if defined (OPENCONNECT_OPENSSL)
	printf(_("Using OpenSSL. Features present:"));
#elif defined (OPENCONNECT_GNUTLS)
	printf(_("Using GnuTLS. Features present:"));
#endif

	if (openconnect_has_tss_blob_support()) {
		printf("%sTPM", sep);
		sep = comma;
	}
#if defined (OPENCONNECT_OPENSSL) && defined (HAVE_ENGINE)
	else {
		printf("%sTPM (%s)", sep, _("OpenSSL ENGINE not present"));
		sep = comma;
	}
#endif
	if (openconnect_has_pkcs11_support()) {
		printf("%sPKCS#11", sep);
		sep = comma;
	}
	if (openconnect_has_stoken_support()) {
		printf("%sSoftware token", sep);
		sep = comma;
	}

#ifdef HAVE_DTLS
	printf("%sDTLS", sep);
#if defined (OPENCONNECT_GNUTLS) && defined (DTLS_OPENSSL)
	printf(" (%s)", _("using OpenSSL"));
#endif
	printf("\n");
#else
	printf(_("\nWARNING: No DTLS support in this binary. Performance will be impaired.\n"));
#endif
}

static void usage(void)
{
	printf(_("Usage:  openconnect [options] <server>\n"));
	printf(_("Open client for Cisco AnyConnect VPN, version %s\n\n"), openconnect_version_str);
	print_build_opts();
	printf("      --config=CONFIGFILE         %s\n", _("Read options from config file"));
	printf("  -b, --background                %s\n", _("Continue in background after startup"));
	printf("      --pid-file=PIDFILE          %s\n", _("Write the daemon's PID to this file"));
	printf("  -c, --certificate=CERT          %s\n", _("Use SSL client certificate CERT"));
	printf("  -e, --cert-expire-warning=DAYS  %s\n", _("Warn when certificate lifetime < DAYS"));
	printf("  -k, --sslkey=KEY                %s\n", _("Use SSL private key file KEY"));
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
	printf("      --base-mtu=MTU              %s\n", _("Indicate path MTU to/from server"));
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
	printf("                                  %s: \"%s\"\n", _("default"), DEFAULT_VPNCSCRIPT);
	printf("  -S, --script-tun                %s\n", _("Pass traffic to 'script' program, not tun"));
	printf("  -u, --user=NAME                 %s\n", _("Set login username"));
	printf("  -V, --version                   %s\n", _("Report version number"));
	printf("  -v, --verbose                   %s\n", _("More output"));
	printf("  -x, --xmlconfig=CONFIG          %s\n", _("XML config file"));
	printf("      --authgroup=GROUP           %s\n", _("Choose authentication login selection"));
	printf("      --authenticate              %s\n", _("Authenticate only and print login info"));
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
	printf("      --stoken[=TOKENSTRING]      %s\n", _("Use software token to generate password"));
#ifndef LIBSTOKEN_HDR
	printf("                                  %s\n", _("(NOTE: libstoken disabled in this build)"));
#endif
	printf("      --reconnect-timeout         %s\n", _("Connection retry timeout in seconds"));
	printf("      --servercert=FINGERPRINT    %s\n", _("Server's certificate SHA1 fingerprint"));
	printf("      --useragent=STRING          %s\n", _("HTTP header User-Agent: field"));
	printf("      --dtls-local-port=PORT      %s\n", _("Set local port for DTLS datagrams"));
	printf("\n");

	helpmessage();
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

static FILE *config_file = NULL;
static int config_line_num = 0;

/* There are three ways to handle config_arg:
 *
 * 1. We only care about it transiently and it can be lost entirely
 *    (e.g. vpninfo->reconnect_timeout = atoi(config_arg);
 * 2. We need to keep it, but it's a static string and will never be freed
 *    so when it's part of argv[] we can use it in place, but when it comes
 *    from a file we have to strdup() because otherwise it'll be overwritten.
 *    For this we use the keep_config_arg() macro below.
 * 3. It may be freed during normal operation, so we have to use strdup()
 *    even when it's an option from argv[]. (e.g. vpninfo->cert_password).
 */
#define keep_config_arg() (config_file && config_arg ? strdup(config_arg) : config_arg)

static int next_option(int argc, char **argv, char **config_arg)
{
	/* These get re-used */
	static char *line_buf = NULL;
	static size_t line_size = 0;

	ssize_t llen;
	int opt, optlen;
	struct option *this;
	char *line;
	int ate_equals = 0;

 next:
	if (!config_file) {
		opt = getopt_long(argc, argv,
				  "bC:c:e:Ddg:hi:k:lp:P:Q:qSs:U:u:Vvx:",
				  long_options, NULL);

		*config_arg = optarg;
		return opt;
	}

	llen = getline(&line_buf, &line_size, config_file);
	if (llen < 0) {
		if (feof(config_file)) {
			fclose(config_file);
			config_file = NULL;
			goto next;
		}
		fprintf(stderr, _("Failed to get line from config file: %s\n"),
			strerror(errno));
		exit(1);
	}
	line = line_buf;

	/* Strip the trailing newline (coping with DOS newlines) */
	if (llen && line[llen-1] == '\n')
		line[--llen] = 0;
	if (llen && line[llen-1] == '\r')
		line[--llen] = 0;

	/* Skip and leading whitespace */
	while (line[0] == ' ' || line[0] == '\t' || line[0] == '\r')
		line++;

	/* Ignore comments and empty lines */
	if (!line[0] || line[0] == '#') {
		config_line_num++;
		goto next;
	}

	/* Try to match on a known option... naïvely. This could be improved. */
	for (this = long_options; this->name; this++) {
		optlen = strlen(this->name);
		/* If the option isn't followed by whitespace or NUL, or
		   perhaps an equals sign if the option takes an argument,
		   then it's not a match */
		if (!strncmp(this->name, line, optlen) &&
		    (!line[optlen] || line[optlen] == ' ' || line[optlen] == '\t' ||
		     line[optlen] == '='))
		    break;
	}
	if (!this->name) {
		char *l;

		for (l = line; *l && *l != ' ' && *l != '\t'; l++)
			;

		*l = 0;
		fprintf(stderr, _("Unrecognised option at line %d: '%s'\n"),
			config_line_num, line);
		return '?';
	}
	line += optlen;
	while (*line == ' ' || *line == '\t' ||
	       (*line == '=' && this->has_arg && !ate_equals && ++ate_equals))
		line++;

	if (!this->has_arg && *line) {
		fprintf(stderr, _("Option '%s' does not take an argument at line %d\n"),
			this->name, config_line_num);
		return '?';
	} else if (this->has_arg == 1 && !*line) {
		fprintf(stderr, _("Option '%s' requires an argument at line %d\n"),
			this->name, config_line_num);
		return '?';
	} else if (this->has_arg == 2 && !*line) {
		line = NULL;
	}

	config_line_num++;
	*config_arg = line;
	return this->val;

}

int main(int argc, char **argv)
{
	struct openconnect_info *vpninfo;
	struct utsname utsbuf;
	struct sigaction sa;
	int use_syslog = 0;
	char *urlpath = NULL;
	char *proxy = getenv("https_proxy");
	int autoproxy = 0;
	uid_t uid = getuid();
	int opt;
	char *pidfile = NULL;
	FILE *fp = NULL;
	char *config_arg;
	int use_stoken = 0;
	char *token_str = NULL;

#ifdef ENABLE_NLS
	bindtextdomain("openconnect", LOCALEDIR);
	setlocale(LC_ALL, "");
#endif

	if (strcmp(openconnect_version_str, openconnect_binary_version)) {
		fprintf(stderr, _("WARNING: This version of openconnect is %s but\n"
				  "         the libopenconnect library is %s\n"),
			openconnect_binary_version, openconnect_version_str);
	}
			
	openconnect_init_ssl();

	vpninfo = malloc(sizeof(*vpninfo));
	if (!vpninfo) {
		fprintf(stderr, _("Failed to allocate vpninfo structure\n"));
		exit(1);
	}
	memset(vpninfo, 0, sizeof(*vpninfo));

	/* Set up some defaults */
	vpninfo->tun_fd = vpninfo->ssl_fd = vpninfo->dtls_fd = vpninfo->new_dtls_fd = -1;
	vpninfo->useragent = openconnect_create_useragent("Open AnyConnect VPN Agent");
	vpninfo->reqmtu = 0;
	vpninfo->deflate = 1;
	vpninfo->dtls_attempt_period = 60;
	vpninfo->max_qlen = 10;
	vpninfo->reconnect_interval = RECONNECT_INTERVAL_MIN;
	vpninfo->reconnect_timeout = 300;
	vpninfo->uid_csd = 0;
	/* We could let them override this on the command line some day, perhaps */
#ifdef __APPLE__
	vpninfo->csd_xmltag = "csdMac";
#else
	vpninfo->csd_xmltag = "csdLinux";
#endif
	vpninfo->uid_csd = 0;
	vpninfo->uid_csd_given = 0;
	vpninfo->validate_peer_cert = validate_peer_cert;
	vpninfo->process_auth_form = process_auth_form;
	vpninfo->cbdata = vpninfo;
	vpninfo->cert_expire_warning = 60 * 86400;
	vpninfo->vpnc_script = DEFAULT_VPNCSCRIPT;
	vpninfo->cancel_fd = -1;

	if (!uname(&utsbuf))
		vpninfo->localname = utsbuf.nodename;
	else
		vpninfo->localname = "localhost";

	while ((opt = next_option(argc, argv, &config_arg))) {

		if (opt < 0)
			break;

		switch (opt) {
		case OPT_CONFIGFILE:
			if (config_file) {
				fprintf(stderr, _("Cannot use 'config' option inside config file\n"));
				exit(1);
			}
			config_file = fopen(config_arg, "r");
			if (!config_file) {
				fprintf(stderr, _("Cannot open config file '%s': %s\n"),
					config_arg, strerror(errno));
				exit(1);
			}
			config_line_num = 1;
			/* The next option will come from the file... */
			break;
		case OPT_CAFILE:
			vpninfo->cafile = keep_config_arg();
			break;
		case OPT_PIDFILE:
			pidfile = keep_config_arg();
			break;
		case OPT_SERVERCERT:
			vpninfo->servercert = keep_config_arg();
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
		case OPT_AUTHENTICATE:
			cookieonly = 3;
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
			break;
		case OPT_RECONNECT_TIMEOUT:
			vpninfo->reconnect_timeout = atoi(config_arg);
			break;
		case OPT_DTLS_CIPHERS:
			vpninfo->dtls_ciphers = keep_config_arg();
			break;
		case OPT_AUTHGROUP:
			vpninfo->authgroup = keep_config_arg();
			break;
		case 'b':
			background = 1;
			break;
		case 'C':
			vpninfo->cookie = keep_config_arg();
			break;
		case 'c':
			vpninfo->cert = strdup(config_arg);
			break;
		case 'e':
			vpninfo->cert_expire_warning = 86400 * atoi(config_arg);
			break;
		case 'k':
			vpninfo->sslkey = strdup(config_arg);
			break;
		case 'd':
			vpninfo->deflate = 1;
			break;
		case 'D':
			vpninfo->deflate = 0;
			break;
		case 'g':
			free(urlpath);
			urlpath = strdup(config_arg);
			break;
		case 'h':
			usage();
		case 'i':
			vpninfo->ifname = keep_config_arg();
			break;
		case 'l':
			use_syslog = 1;
			break;
		case 'm':
			vpninfo->reqmtu = atol(config_arg);
			if (vpninfo->reqmtu < 576) {
				fprintf(stderr, _("MTU %d too small\n"), vpninfo->reqmtu);
				vpninfo->reqmtu = 576;
			}
			break;
		case OPT_BASEMTU:
			vpninfo->basemtu = atol(config_arg);
			if (vpninfo->basemtu < 576) {
				fprintf(stderr, _("MTU %d too small\n"), vpninfo->basemtu);
				vpninfo->basemtu = 576;
			}
			break;
		case 'p':
			vpninfo->cert_password = strdup(config_arg);
			break;
		case 'P': 
			proxy = keep_config_arg();
			autoproxy = 0;
			break;
		case OPT_NO_PROXY:
			autoproxy = 0;
			proxy = NULL;
			break;
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
			vpninfo->vpnc_script = keep_config_arg();
			break;
		case 'S':
			vpninfo->script_tun = 1;
			break;
		case 'u':
			vpninfo->username = keep_config_arg();
			break;
		case 'U': {
			char *strend;
			uid = strtol(config_arg, &strend, 0);
			if (strend[0]) {
				struct passwd *pw = getpwnam(config_arg);
				if (!pw) {
					fprintf(stderr, _("Invalid user \"%s\"\n"),
						config_arg);
					exit(1);
				}
				uid = pw->pw_uid;
			}
			break;
		}
		case OPT_CSD_USER: {
			char *strend;
			vpninfo->uid_csd = strtol(config_arg, &strend, 0);
			if (strend[0]) {
				struct passwd *pw = getpwnam(config_arg);
				if (!pw) {
					fprintf(stderr, _("Invalid user \"%s\"\n"),
						config_arg);
					exit(1);
				}
				vpninfo->uid_csd = pw->pw_uid;
			}
			vpninfo->uid_csd_given = 1;
			break;
		}
		case OPT_CSD_WRAPPER:
			vpninfo->csd_wrapper = keep_config_arg();
			break;
		case OPT_DISABLE_IPV6:
			vpninfo->disable_ipv6 = 1;
			break;
		case 'Q':
			vpninfo->max_qlen = atol(config_arg);
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
			printf(_("OpenConnect version %s\n"), openconnect_version_str);
			print_build_opts();
			exit(0);
		case 'x':
			vpninfo->xmlconfig = keep_config_arg();
			vpninfo->write_new_config = write_new_config;
			break;
		case OPT_KEY_PASSWORD_FROM_FSID:
			do_passphrase_from_fsid = 1;
			break;
		case OPT_USERAGENT:
			free(vpninfo->useragent);
			vpninfo->useragent = strdup(config_arg);
			break;
		case OPT_FORCE_DPD:
			vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = atoi(config_arg);
			break;
		case OPT_DTLS_LOCAL_PORT:
			vpninfo->dtls_local_port = atoi(config_arg);
			break;
		case OPT_STOKEN:
			use_stoken = 1;
			token_str = keep_config_arg();
			break;
		default:
			usage();
		}
	}

	if (optind < argc - 1) {
		fprintf(stderr, _("Too many arguments on command line\n"));
		usage();
	} else if (optind > argc - 1) {
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

	if (use_stoken)
		init_stoken(vpninfo, token_str);

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

		if (openconnect_parse_url(vpninfo, url))
			exit(1);

		free(url);
	}

	/* Historically, the path in the URL superseded the one in the
	 * --usergroup argument, just because of the order in which they
	 * were processed. Preserve that behaviour. */
	if (urlpath && !vpninfo->urlpath) {
		vpninfo->urlpath = urlpath;
		urlpath = NULL;
	}
	free(urlpath);

#ifdef SSL_UI
	set_openssl_ui();
#endif

	if (!vpninfo->cookie && openconnect_obtain_cookie(vpninfo)) {
		if (vpninfo->csd_scriptname) {
			unlink(vpninfo->csd_scriptname);
			vpninfo->csd_scriptname = NULL;
		}
		fprintf(stderr, _("Failed to obtain WebVPN cookie\n"));
		exit(1);
	}

	if (cookieonly == 3) {
		/* --authenticate */
		printf("COOKIE='%s'\n", vpninfo->cookie);
		printf("HOST='%s'\n", vpninfo->hostname);
		if (vpninfo->peer_cert) {
			char buf[41] = {0, };
			openconnect_get_cert_sha1(vpninfo, vpninfo->peer_cert, buf);
			printf("FINGERPRINT='%s'\n", buf);
		}
		openconnect_vpninfo_free(vpninfo);
		exit(0);
	} else if (cookieonly) {
		printf("%s\n", vpninfo->cookie);
		if (cookieonly == 1) {
			/* We use cookieonly=2 for 'print it and continue' */
			openconnect_vpninfo_free(vpninfo);
			exit(0);
		}
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
			fprintf(stderr, _("Failed to set uid %ld\n"),
				(long)uid);
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

	if (!vpninfo->vpnc_script) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("No --script argument provided; DNS and routing are not configured\n"));
		vpn_progress(vpninfo, PRG_INFO,
			     _("See http://www.infradead.org/openconnect/vpnc-script.html\n"));
	}

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
		close(config_fd);
		return -err;
	}

	close(config_fd);
	return 0;
}

void write_progress(void *_vpninfo, int level, const char *fmt, ...)
{
	FILE *outf = level ? stdout : stderr;
	va_list args;

	if (cookieonly)
		outf = stderr;

	if (verbose >= level) {
		va_start(args, fmt);
		vfprintf(outf, fmt, args);
		va_end(args);
		fflush(outf);
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
	char fingerprint[SHA1_SIZE * 2 + 1];
	char host[0];
} *accepted_certs;

static int validate_peer_cert(void *_vpninfo, OPENCONNECT_X509 *peer_cert,
			      const char *reason)
{
	struct openconnect_info *vpninfo = _vpninfo;
	char fingerprint[SHA1_SIZE * 2 + 1];
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
		char buf[80];
		char *details;
		char *p;

		fprintf(stderr, _("\nCertificate from VPN server \"%s\" failed verification.\n"
			 "Reason: %s\n"), vpninfo->hostname, reason);

		if (non_inter)
			return -EINVAL;

		fprintf(stderr, _("Enter '%s' to accept, '%s' to abort; anything else to view: "),
		       _("yes"), _("no"));
		if (!fgets(buf, sizeof(buf), stdin))
			return -EINVAL;
		p = strchr(buf, '\n');
		if (p)
			*p = 0;

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

		details = openconnect_get_cert_details(vpninfo, peer_cert);
		fputs(details, stderr);
		free(details);
		fprintf(stderr, _("SHA1 fingerprint: %s\n"), fingerprint);
	}
}


/* Return value:
 *  < 0, on error
 *  = 0, when form was parsed and POST required
 *  = 1, when response was cancelled by user
 */
static int process_auth_form(void *_vpninfo,
			     struct oc_auth_form *form)
{
	struct openconnect_info *vpninfo = _vpninfo;
	struct oc_form_opt *opt;
	char response[1024];
	char *p;

	if (form->banner)
		fprintf(stderr, "%s\n", form->banner);

	if (form->error)
		fprintf(stderr, "%s\n", form->error);

	if (form->message)
		fprintf(stderr, "%s\n", form->message);

	/* scan for select options first so they are displayed first */
	for (opt = form->opts; opt; opt = opt->next) {
		if (opt->type == OC_FORM_OPT_SELECT) {
			struct oc_form_opt_select *select_opt = (void *)opt;
			struct oc_choice *choice = NULL;
			int i;

			if (!select_opt->nr_choices)
				continue;

			if (vpninfo->authgroup &&
			    !strcmp(opt->name, "group_list")) {
				for (i = 0; i < select_opt->nr_choices; i++) {
					choice = &select_opt->choices[i];

					if (!strcmp(vpninfo->authgroup,
						    choice->label)) {
						opt->value = choice->name;
						break;
					}
				}
				if (!opt->value)
					vpn_progress(vpninfo, PRG_ERR,
						     _("Auth choice \"%s\" not available\n"),
						     vpninfo->authgroup);
			}
			if (!opt->value && select_opt->nr_choices == 1) {
				choice = &select_opt->choices[0];
				opt->value = choice->name;
			}
			if (opt->value) {
				select_opt = NULL;
				continue;
			}
			if (non_inter) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("User input required in non-interactive mode\n"));
				goto err;
			}
			fprintf(stderr, "%s [", opt->label);
			for (i = 0; i < select_opt->nr_choices; i++) {
				choice = &select_opt->choices[i];
				if (i)
					fprintf(stderr, "|");

				fprintf(stderr, "%s", choice->label);
			}
			fprintf(stderr, "]:");
			fflush(stderr);

			if (!fgets(response, sizeof(response), stdin) || !strlen(response))
				goto err;

			p = strchr(response, '\n');
			if (p)
				*p = 0;

			for (i = 0; i < select_opt->nr_choices; i++) {
				choice = &select_opt->choices[i];

				if (!strcmp(response, choice->label)) {
					select_opt->form.value = choice->name;
					break;
				}
			}
			if (!select_opt->form.value) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Auth choice \"%s\" not valid\n"),
					     response);
				goto err;
			}
		}
	}

	for (opt = form->opts; opt; opt = opt->next) {

		if (opt->type == OC_FORM_OPT_TEXT) {
			if (vpninfo->username &&
			    !strcmp(opt->name, "username")) {
				opt->value = strdup(vpninfo->username);
				if (!opt->value)
					goto err;
			} else if (non_inter) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("User input required in non-interactive mode\n"));
				goto err;
			} else {
				opt->value=malloc(80);
				if (!opt->value)
					goto err;

				fprintf(stderr, "%s", opt->label);
				fflush(stderr);

				if (!fgets(opt->value, 80, stdin) || !strlen(opt->value))
					goto err;

				p = strchr(opt->value, '\n');
				if (p)
					*p = 0;
			}

		} else if (opt->type == OC_FORM_OPT_PASSWORD) {
			if (vpninfo->password &&
			    !strcmp(opt->name, "password")) {
				opt->value = vpninfo->password;
				vpninfo->password = NULL;
				if (!opt->value)
					goto err;
			} else if (non_inter) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("User input required in non-interactive mode\n"));
				goto err;
			} else {
				struct termios t;
				opt->value=malloc(80);
				if (!opt->value)
					goto err;

				fprintf(stderr, "%s", opt->label);
				fflush(stderr);

				tcgetattr(0, &t);
				t.c_lflag &= ~ECHO;
				tcsetattr(0, TCSANOW, &t);

				p = fgets(opt->value, 80, stdin);

				t.c_lflag |= ECHO;
				tcsetattr(0, TCSANOW, &t);
				fprintf(stderr, "\n");

				if (!p || !strlen(opt->value))
					goto err;

				p = strchr(opt->value, '\n');
				if (p)
					*p = 0;
			}

		}
	}

	if (vpninfo->password) {
		free(vpninfo->password);
		vpninfo->password = NULL;
	}

	return 0;

 err:
	for (opt = form->opts; opt; opt = opt->next) {
		if (opt->value && (opt->type == OC_FORM_OPT_TEXT ||
				   opt->type == OC_FORM_OPT_PASSWORD)) {
			free(opt->value);
			opt->value = NULL;
		}
	}
	return -EINVAL;
}

static void init_stoken(struct openconnect_info *vpninfo,
			const char *token_str)
{
	int ret = openconnect_set_stoken_mode(vpninfo, 1, token_str);

	switch (ret) {
	case 0:
		return;
	case -EINVAL:
		fprintf(stderr, _("Soft token string is invalid\n"));
		exit(1);
	case -ENOENT:
		fprintf(stderr, _("Can't open ~/.stokenrc file\n"));
		exit(1);
	case -EOPNOTSUPP:
		fprintf(stderr, _("OpenConnect was not built with soft token support\n"));
		exit(1);
	default:
		fprintf(stderr, _("General failure in libstoken\n"));
		exit(1);
	}
}
