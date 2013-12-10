/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
 * Copyright © 2013 John Morrissey <jwm@horde.net>
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
#ifdef __ANDROID__
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
#include <time.h>

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
static int process_auth_form_cb(void *_vpninfo,
				struct oc_auth_form *form);
static void init_token(struct openconnect_info *vpninfo,
		       oc_token_mode_t token_mode, const char *token_str);

/* A sanity check that the openconnect executable is running against a
   library of the same version */
#define openconnect_version_str openconnect_binary_version
#include <version.c>
#undef openconnect_version_str

int verbose = PRG_INFO;
int timestamp;
int background;
int do_passphrase_from_fsid;
int nocertcheck;
int non_inter;
int cookieonly;

char *username;
char *password;
char *authgroup;
int authgroup_set;
int last_form_empty;

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
	OPT_DUMP_HTTP,
	OPT_FORCE_DPD,
	OPT_KEY_PASSWORD_FROM_FSID,
	OPT_LIBPROXY,
	OPT_NO_CERT_CHECK,
	OPT_NO_DTLS,
	OPT_NO_HTTP_KEEPALIVE,
	OPT_NO_PASSWD,
	OPT_NO_PROXY,
	OPT_NO_XMLPOST,
	OPT_PIDFILE,
	OPT_PASSWORD_ON_STDIN,
	OPT_PRINTCOOKIE,
	OPT_RECONNECT_TIMEOUT,
	OPT_SERVERCERT,
	OPT_USERAGENT,
	OPT_NON_INTER,
	OPT_DTLS_LOCAL_PORT,
	OPT_TOKEN_MODE,
	OPT_TOKEN_SECRET,
	OPT_OS,
	OPT_TIMESTAMP,
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
	OPTION("timestamp", 0, OPT_TIMESTAMP),
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
	OPTION("token-mode", 1, OPT_TOKEN_MODE),
	OPTION("token-secret", 1, OPT_TOKEN_SECRET),
	OPTION("os", 1, OPT_OS),
	OPTION("no-xmlpost", 0, OPT_NO_XMLPOST),
	OPTION("dump-http-traffic", 0, OPT_DUMP_HTTP),
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

#if defined(OPENCONNECT_OPENSSL)
	printf(_("Using OpenSSL. Features present:"));
#elif defined(OPENCONNECT_GNUTLS)
	printf(_("Using GnuTLS. Features present:"));
#endif

	if (openconnect_has_tss_blob_support()) {
		printf("%sTPM", sep);
		sep = comma;
	}
#if defined(OPENCONNECT_OPENSSL) && defined(HAVE_ENGINE)
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
		printf("%sRSA software token", sep);
		sep = comma;
	}
	if (openconnect_has_oath_support()) {
		printf("%sTOTP software token", sep);
		sep = comma;
	}

#ifdef HAVE_DTLS
	printf("%sDTLS", sep);
#if defined(OPENCONNECT_GNUTLS) && defined(DTLS_OPENSSL)
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
	printf("      --timestamp                 %s\n", _("Prepend timestamp to progress messages"));
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
	printf("      --dump-http-traffic         %s\n", _("Dump HTTP authentication traffic (implies --verbose"));
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
	printf("      --no-xmlpost                %s\n", _("Do not attempt XML POST authentication"));
	printf("      --non-inter                 %s\n", _("Do not expect user input; exit if it is required"));
	printf("      --passwd-on-stdin           %s\n", _("Read password from standard input"));
	printf("      --token-mode=MODE           %s\n", _("Software token type: rsa or totp"));
	printf("      --token-secret=STRING       %s\n", _("Software token secret"));
#ifndef HAVE_LIBSTOKEN
	printf("                                  %s\n", _("(NOTE: libstoken (RSA SecurID) disabled in this build)"));
#endif
#ifndef HAVE_LIBOATH
	printf("                                  %s\n", _("(NOTE: liboath (TOTP) disabled in this build)"));
#endif
	printf("      --reconnect-timeout         %s\n", _("Connection retry timeout in seconds"));
	printf("      --servercert=FINGERPRINT    %s\n", _("Server's certificate SHA1 fingerprint"));
	printf("      --useragent=STRING          %s\n", _("HTTP header User-Agent: field"));
	printf("      --os=STRING                 %s\n", _("OS type (linux,linux-64,mac,win) to report"));
	printf("      --dtls-local-port=PORT      %s\n", _("Set local port for DTLS datagrams"));
	printf("\n");

	helpmessage();
	exit(1);
}

static void read_stdin(char **string, int hidden)
{
	struct termios t;
	char *c = malloc(1025), *ret;
	int fd = fileno(stdin);

	if (!c) {
		fprintf(stderr, _("Allocation failure for string from stdin\n"));
		exit(1);
	}

	if (hidden) {
		tcgetattr(fd, &t);
		t.c_lflag &= ~ECHO;
		tcsetattr(fd, TCSANOW, &t);

		ret = fgets(c, 1025, stdin);

		t.c_lflag |= ECHO;
		tcsetattr(fd, TCSANOW, &t);
		fprintf(stderr, "\n");
	} else
		ret = fgets(c, 1025, stdin);

	if (!ret) {
		perror(_("fgets (stdin)"));
		exit(1);
	}

	*string = c;

	c = strchr(*string, '\n');
	if (c)
		*c = 0;
}

static int sig_cmd_fd;
static int sig_caught;

static void handle_sigint(int sig)
{
	char x = OC_CMD_CANCEL;

	sig_caught = sig;
	if (write(sig_cmd_fd, &x, 1) < 0) {
		/* suppress warn_unused_result */
	}
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
 *    For this we use the xstrdup() function below.
 */
#define keep_config_arg() (config_file && config_arg ? strdup(config_arg) : config_arg)

static char *xstrdup(const char *arg)
{
	char *ret = strdup(arg);

	if (!ret) {
		fprintf(stderr, _("Failed to allocate string\n"));
		exit(1);
	}
	return ret;
}

static int next_option(int argc, char **argv, char **config_arg)
{
	/* These get re-used */
	static char *line_buf = NULL;
	static size_t line_size = 0;

	ssize_t llen;
	int opt, optlen = 0;
	struct option *this;
	char *line;
	int ate_equals = 0;

 next:
	if (!config_file) {
		opt = getopt_long(argc, argv,
				  "bC:c:Dde:g:hi:k:lm:P:p:Q:qSs:U:u:Vvx:",
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
	int script_tun = 0;
	char *vpnc_script = NULL, *ifname = NULL;
	const struct oc_ip_info *ip_info;
	int autoproxy = 0;
	uid_t uid = getuid();
	int opt;
	char *pidfile = NULL;
	int use_dtls = 1;
	FILE *fp = NULL;
	char *config_arg;
	char *token_str = NULL;
	oc_token_mode_t token_mode = OC_TOKEN_MODE_NONE;
	int reconnect_timeout = 300;
	int ret;

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

	vpninfo = openconnect_vpninfo_new((char *)"Open AnyConnect VPN Agent",
		validate_peer_cert, NULL, process_auth_form_cb, write_progress, NULL);
	if (!vpninfo) {
		fprintf(stderr, _("Failed to allocate vpninfo structure\n"));
		exit(1);
	}

	vpninfo->cbdata = vpninfo;
	if (!uname(&utsbuf)) {
		free(vpninfo->localname);
		vpninfo->localname = xstrdup(utsbuf.nodename);
	}

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
			openconnect_set_cafile(vpninfo, xstrdup(config_arg));
			break;
		case OPT_PIDFILE:
			pidfile = keep_config_arg();
			break;
		case OPT_SERVERCERT:
			openconnect_set_server_cert_sha1(vpninfo, xstrdup(config_arg));
			break;
		case OPT_NO_DTLS:
			use_dtls = 0;
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
			read_stdin(&vpninfo->cookie, 0);
			/* If the cookie is empty, ignore it */
			if (!*vpninfo->cookie)
				vpninfo->cookie = NULL;
			break;
		case OPT_PASSWORD_ON_STDIN:
			read_stdin(&password, 0);
			break;
		case OPT_NO_PASSWD:
			vpninfo->nopasswd = 1;
			break;
		case OPT_NO_XMLPOST:
			openconnect_set_xmlpost(vpninfo, 0);
			break;
		case OPT_NON_INTER:
			non_inter = 1;
			break;
		case OPT_RECONNECT_TIMEOUT:
			reconnect_timeout = atoi(config_arg);
			break;
		case OPT_DTLS_CIPHERS:
			vpninfo->dtls_ciphers = keep_config_arg();
			break;
		case OPT_AUTHGROUP:
			authgroup = keep_config_arg();
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
			ifname = xstrdup(config_arg);
			break;
		case 'l':
			use_syslog = 1;
			break;
		case 'm': {
			int mtu = atol(config_arg);
			if (mtu < 576) {
				fprintf(stderr, _("MTU %d too small\n"), mtu);
				mtu = 576;
			}
			openconnect_set_reqmtu(vpninfo, mtu);
			break;
		}
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
			vpnc_script = xstrdup(config_arg);
			break;
		case 'S':
			script_tun = 1;
			break;
		case 'u':
			free(username);
			username = strdup(config_arg);
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
		case OPT_DUMP_HTTP:
			vpninfo->dump_http_traffic = 1;
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
		case OPT_TOKEN_MODE:
			if (strcasecmp(config_arg, "rsa") == 0) {
				token_mode = OC_TOKEN_MODE_STOKEN;
			} else if (strcasecmp(config_arg, "totp") == 0) {
				token_mode = OC_TOKEN_MODE_TOTP;
			} else {
				fprintf(stderr, _("Invalid software token mode \"%s\"\n"),
					config_arg);
				exit(1);
			}
			break;
		case OPT_TOKEN_SECRET:
			token_str = keep_config_arg();
			break;
		case OPT_OS:
			if (openconnect_set_reported_os(vpninfo, config_arg)) {
				fprintf(stderr, _("Invalid OS identity \"%s\"\n"),
					config_arg);
				exit(1);
			}
			if (!strcmp(config_arg, "android") || !strcmp(config_arg, "apple-ios")) {
				/* generic defaults */
				openconnect_set_mobile_info(vpninfo,
					xstrdup("1.0"),
					xstrdup(config_arg),
					xstrdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
			}
			break;
		case OPT_TIMESTAMP:
			timestamp = 1;
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

	if (token_mode != OC_TOKEN_MODE_NONE)
		init_token(vpninfo, token_mode, token_str);

	if (proxy && openconnect_set_http_proxy(vpninfo, strdup(proxy)))
		exit(1);

	if (use_syslog) {
#ifndef __ANDROID__
		openlog("openconnect", LOG_PID, LOG_DAEMON);
#endif
		vpninfo->progress = syslog_progress;
	}

	sig_cmd_fd = openconnect_setup_cmd_pipe(vpninfo);
	if (sig_cmd_fd < 0) {
		fprintf(stderr, _("Error opening cmd pipe\n"));
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = handle_sigusr;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = handle_sigint;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

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
		printf("HOST='%s'\n", openconnect_get_hostname(vpninfo));
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
	if (openconnect_make_cstp_connection(vpninfo)) {
		fprintf(stderr, _("Creating SSL connection failed\n"));
		openconnect_vpninfo_free(vpninfo);
		exit(1);
	}

	if (!vpnc_script)
		vpnc_script = xstrdup(DEFAULT_VPNCSCRIPT);
	if (script_tun) {
		if (openconnect_setup_tun_script(vpninfo, vpnc_script)) {
			fprintf(stderr, _("Set up tun script failed\n"));
			openconnect_vpninfo_free(vpninfo);
			exit(1);
		}
	} else if (openconnect_setup_tun_device(vpninfo, vpnc_script, ifname)) {
		fprintf(stderr, _("Set up tun device failed\n"));
		openconnect_vpninfo_free(vpninfo);
		exit(1);
	}

	if (uid != getuid()) {
		if (setuid(uid)) {
			fprintf(stderr, _("Failed to set uid %ld\n"),
				(long)uid);
			openconnect_vpninfo_free(vpninfo);
			exit(1);
		}
	}

	if (use_dtls && openconnect_setup_dtls(vpninfo, 60))
		fprintf(stderr, _("Set up DTLS failed; using SSL instead\n"));

	openconnect_get_ip_info(vpninfo, &ip_info, NULL, NULL);
	vpn_progress(vpninfo, PRG_INFO,
		     _("Connected %s as %s%s%s, using %s\n"), openconnect_get_ifname(vpninfo),
		     ip_info->addr?:"",
		     (ip_info->addr6 && ip_info->addr) ? " + " : "",
		     ip_info->addr6 ? : "",
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
				openconnect_vpninfo_free(vpninfo);
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
			openconnect_vpninfo_free(vpninfo);
			exit(0);
		}
		if (fp)
			fclose(fp);
	}
	ret = openconnect_mainloop(vpninfo, reconnect_timeout, RECONNECT_INTERVAL_MIN);
	if (fp)
		unlink(pidfile);

	if (sig_caught) {
		vpn_progress(vpninfo, PRG_INFO, _("Caught signal: %s\n"), strsignal(sig_caught));
		ret = 0;
	} else if (ret == -EPERM)
		ret = 2;
	else
		ret = 1;

	openconnect_vpninfo_free(vpninfo);
	exit(ret);
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
	if (write(config_fd, buf, buflen) != buflen) {
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
		if (timestamp) {
			char ts[64];
			time_t t = time(NULL);
			struct tm *tm = localtime(&t);

			strftime(ts, 64, "[%Y-%m-%d %H:%M:%S] ", tm);
			fprintf(outf, "%s", ts);
		}
		va_start(args, fmt);
		vfprintf(outf, fmt, args);
		va_end(args);
		fflush(outf);
	}
}

#ifdef __ANDROID__
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
#else /* !__ANDROID__ */
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

static int match_choice_label(struct openconnect_info *vpninfo,
			      struct oc_form_opt_select *select_opt,
			      char *label)
{
	int i, input_len, partial_matches = 0;
	char *match = NULL;

	input_len = strlen(label);
	if (input_len < 1)
		return -EINVAL;

	for (i = 0; i < select_opt->nr_choices; i++) {
		struct oc_choice *choice = select_opt->choices[i];

		if (!strncasecmp(label, choice->label, input_len)) {
			if (strlen(choice->label) == input_len) {
				select_opt->form.value = choice->name;
				return 0;
			} else {
				match = choice->name;
				partial_matches++;
			}
		}
	}

	if (partial_matches == 1) {
		select_opt->form.value = match;
		return 0;
	} else if (partial_matches > 1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Auth choice \"%s\" matches multiple options\n"), label);
		return -EINVAL;
	} else {
		vpn_progress(vpninfo, PRG_ERR, _("Auth choice \"%s\" not available\n"), label);
		return -EINVAL;
	}
}

static char *prompt_for_input(const char *prompt,
			      struct openconnect_info *vpninfo,
			      int hidden)
{
	char *response;

	fprintf(stderr, "%s", prompt);
	fflush(stderr);

	if (non_inter) {
		fprintf(stderr, "***\n");
		vpn_progress(vpninfo, PRG_ERR,
			     _("User input required in non-interactive mode\n"));
		return NULL;
	}

	read_stdin(&response, hidden);
	return response;
}

static int prompt_opt_select(struct openconnect_info *vpninfo,
			     struct oc_form_opt_select *select_opt,
			     char **saved_response)
{
	int i;
	char *response;

	if (!select_opt->nr_choices)
		return -EINVAL;

retry:
	fprintf(stderr, "%s [", select_opt->form.label);
	for (i = 0; i < select_opt->nr_choices; i++) {
		struct oc_choice *choice = select_opt->choices[i];
		if (i)
			fprintf(stderr, "|");

		fprintf(stderr, "%s", choice->label);
	}
	fprintf(stderr, "]:");

	if (select_opt->nr_choices == 1) {
		response = strdup(select_opt->choices[0]->label);
		fprintf(stderr, "%s\n", response);
	} else
		response = prompt_for_input("", vpninfo, 0);

	if (!response)
		return -EINVAL;

	if (match_choice_label(vpninfo, select_opt, response) < 0) {
		free(response);
		goto retry;
	}

	if (saved_response)
		*saved_response = response;
	else
		free(response);

	return 0;
}

/* Return value:
 *  < 0, on error
 *  = 0, when form was parsed and POST required
 *  = 1, when response was cancelled by user
 */
static int process_auth_form_cb(void *_vpninfo,
				struct oc_auth_form *form)
{
	struct openconnect_info *vpninfo = _vpninfo;
	struct oc_form_opt *opt;
	int empty = 1;

	if (form->banner && verbose > PRG_ERR)
		fprintf(stderr, "%s\n", form->banner);

	if (form->error)
		fprintf(stderr, "%s\n", form->error);

	if (form->message && verbose > PRG_ERR)
		fprintf(stderr, "%s\n", form->message);

	/* Special handling for GROUP: field if present, as different group
	   selections can make other fields disappear/reappear */
	if (form->authgroup_opt) {
		if (!authgroup ||
		    match_choice_label(vpninfo, form->authgroup_opt, authgroup) != 0) {
			if (prompt_opt_select(vpninfo, form->authgroup_opt, &authgroup) < 0)
				goto err;
		}
		if (!authgroup_set) {
			authgroup_set = 1;
			return OC_FORM_RESULT_NEWGROUP;
		}
	}

	for (opt = form->opts; opt; opt = opt->next) {

		if (opt->flags & OC_FORM_OPT_IGNORE)
			continue;

		/* I haven't actually seen a non-authgroup dropdown in the wild, but
		   the Cisco clients do support them */
		if (opt->type == OC_FORM_OPT_SELECT) {
			struct oc_form_opt_select *select_opt = (void *)opt;

			if (select_opt == form->authgroup_opt)
				continue;
			if (prompt_opt_select(vpninfo, select_opt, NULL) < 0)
				goto err;
			empty = 0;

		} else if (opt->type == OC_FORM_OPT_TEXT) {
			if (username &&
			    !strcmp(opt->name, "username")) {
				opt->value = username;
				username = NULL;
			} else {
				opt->value = prompt_for_input(opt->label, vpninfo, 0);
			}

			if (!opt->value)
				goto err;
			empty = 0;

		} else if (opt->type == OC_FORM_OPT_PASSWORD) {
			if (password &&
			    !strcmp(opt->name, "password")) {
				opt->value = password;
				password = NULL;
			} else {
				opt->value = prompt_for_input(opt->label, vpninfo, 1);
			}

			if (!opt->value)
				goto err;
			empty = 0;
		}
	}

	/* prevent infinite loops if the authgroup requires certificate auth only */
	if (last_form_empty && empty)
		return OC_FORM_RESULT_CANCELLED;
	last_form_empty = empty;

	return OC_FORM_RESULT_OK;

 err:
	return OC_FORM_RESULT_ERR;
}

static void init_token(struct openconnect_info *vpninfo,
		       oc_token_mode_t token_mode, const char *token_str)
{
	int ret;

	ret = openconnect_set_token_mode(vpninfo, token_mode, token_str);

	switch (token_mode) {
	case OC_TOKEN_MODE_STOKEN:
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
			fprintf(stderr, _("OpenConnect was not built with libstoken support\n"));
			exit(1);
		default:
			fprintf(stderr, _("General failure in libstoken\n"));
			exit(1);
		}

		break;

	case OC_TOKEN_MODE_TOTP:
		switch (ret) {
		case 0:
			return;
		case -EINVAL:
			fprintf(stderr, _("Soft token string is invalid\n"));
			exit(1);
		case -EOPNOTSUPP:
			fprintf(stderr, _("OpenConnect was not built with liboath support\n"));
			exit(1);
		default:
			fprintf(stderr, _("General failure in liboath\n"));
			exit(1);
		}

		break;

	case OC_TOKEN_MODE_NONE:
		/* No-op */
		break;

	/* Option parsing already checked for invalid modes. */
	}
}
