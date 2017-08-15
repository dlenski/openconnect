/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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
 */

#include <config.h>

#ifdef HAVE_GETLINE
/* Various BSD systems require this for getline() to be visible */
#define _WITH_GETLINE
#endif

#include <stdio.h>
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
#include <sys/types.h>
#include <getopt.h>
#include <time.h>
#include <locale.h>

#ifdef LIBPROXY_HDR
#include LIBPROXY_HDR
#endif

#include "openconnect-internal.h"

#ifdef _WIN32
#include <shlwapi.h>
#include <wtypes.h>
#include <wincon.h>
#else
#include <sys/utsname.h>
#include <pwd.h>
#include <termios.h>
#endif

#ifdef HAVE_NL_LANGINFO
#include <langinfo.h>

static const char *legacy_charset;
#endif

static int write_new_config(void *_vpninfo,
			    const char *buf, int buflen);
static void __attribute__ ((format(printf, 3, 4)))
    write_progress(void *_vpninfo, int level, const char *fmt, ...);
static int validate_peer_cert(void *_vpninfo, const char *reason);
static int process_auth_form_cb(void *_vpninfo,
				struct oc_auth_form *form);
static void init_token(struct openconnect_info *vpninfo,
		       oc_token_mode_t token_mode, const char *token_str);

/* A sanity check that the openconnect executable is running against a
   library of the same version */
#define openconnect_version_str openconnect_binary_version
#include <version.c>
#undef openconnect_version_str

static int verbose = PRG_INFO;
static int timestamp;
int background;
static int do_passphrase_from_fsid;
static int non_inter;
static int cookieonly;
static int allow_stdin_read;

static char *token_filename;
static char *server_cert = NULL;

static char *username;
static char *password;
static char *authgroup;
static int authgroup_set;
static int last_form_empty;

static int sig_cmd_fd;

#ifdef __ANDROID__
#include <android/log.h>
static void __attribute__ ((format(printf, 3, 4)))
    syslog_progress(void *_vpninfo, int level, const char *fmt, ...)
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
#define openlog(...)  /* */
#elif defined(_WIN32) || defined(__native_client__)
/*
 * FIXME: Perhaps we could implement syslog_progress() using these APIs:
 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa364148%28v=vs.85%29.aspx
 */
#else /* !__ANDROID__ && !_WIN32 && !__native_client__ */
#include <syslog.h>
static void  __attribute__ ((format(printf, 3, 4)))
    syslog_progress(void *_vpninfo, int level, const char *fmt, ...)
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

enum {
	OPT_AUTHENTICATE = 0x100,
	OPT_AUTHGROUP,
	OPT_BASEMTU,
	OPT_CAFILE,
	OPT_COMPRESSION,
	OPT_CONFIGFILE,
	OPT_COOKIEONLY,
	OPT_COOKIE_ON_STDIN,
	OPT_CSD_USER,
	OPT_CSD_WRAPPER,
	OPT_DISABLE_IPV6,
	OPT_DTLS_CIPHERS,
	OPT_DUMP_HTTP,
	OPT_FORCE_DPD,
	OPT_GNUTLS_DEBUG,
	OPT_JUNIPER,
	OPT_KEY_PASSWORD_FROM_FSID,
	OPT_LIBPROXY,
	OPT_NO_CERT_CHECK,
	OPT_NO_DTLS,
	OPT_NO_HTTP_KEEPALIVE,
	OPT_NO_SYSTEM_TRUST,
	OPT_NO_PASSWD,
	OPT_NO_PROXY,
	OPT_NO_XMLPOST,
	OPT_PIDFILE,
	OPT_PASSWORD_ON_STDIN,
	OPT_PRINTCOOKIE,
	OPT_RECONNECT_TIMEOUT,
	OPT_SERVERCERT,
	OPT_RESOLVE,
	OPT_USERAGENT,
	OPT_NON_INTER,
	OPT_DTLS_LOCAL_PORT,
	OPT_TOKEN_MODE,
	OPT_TOKEN_SECRET,
	OPT_OS,
	OPT_TIMESTAMP,
	OPT_PFS,
	OPT_PROXY_AUTH,
	OPT_HTTP_AUTH,
	OPT_LOCAL_HOSTNAME,
	OPT_PROTOCOL,
	OPT_PASSTOS,
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

static const struct option long_options[] = {
#ifndef _WIN32
	OPTION("background", 0, 'b'),
	OPTION("pid-file", 1, OPT_PIDFILE),
	OPTION("setuid", 1, 'U'),
	OPTION("script-tun", 0, 'S'),
	OPTION("syslog", 0, 'l'),
	OPTION("csd-user", 1, OPT_CSD_USER),
	OPTION("csd-wrapper", 1, OPT_CSD_WRAPPER),
#endif
	OPTION("pfs", 0, OPT_PFS),
	OPTION("certificate", 1, 'c'),
	OPTION("sslkey", 1, 'k'),
	OPTION("cookie", 1, 'C'),
	OPTION("compression", 1, OPT_COMPRESSION),
	OPTION("deflate", 0, 'd'),
	OPTION("juniper", 0, OPT_JUNIPER),
	OPTION("no-deflate", 0, 'D'),
	OPTION("cert-expire-warning", 1, 'e'),
	OPTION("usergroup", 1, 'g'),
	OPTION("help", 0, 'h'),
	OPTION("http-auth", 1, OPT_HTTP_AUTH),
	OPTION("interface", 1, 'i'),
	OPTION("mtu", 1, 'm'),
	OPTION("base-mtu", 1, OPT_BASEMTU),
	OPTION("script", 1, 's'),
	OPTION("timestamp", 0, OPT_TIMESTAMP),
	OPTION("passtos", 0, OPT_PASSTOS),
	OPTION("key-password", 1, 'p'),
	OPTION("proxy", 1, 'P'),
	OPTION("proxy-auth", 1, OPT_PROXY_AUTH),
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
	OPTION("resolve", 1, OPT_RESOLVE),
	OPTION("key-password-from-fsid", 0, OPT_KEY_PASSWORD_FROM_FSID),
	OPTION("useragent", 1, OPT_USERAGENT),
	OPTION("local-hostname", 1, OPT_LOCAL_HOSTNAME),
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
	OPTION("no-system-trust", 0, OPT_NO_SYSTEM_TRUST),
	OPTION("protocol", 1, OPT_PROTOCOL),
#ifdef OPENCONNECT_GNUTLS
	OPTION("gnutls-debug", 1, OPT_GNUTLS_DEBUG),
#endif
	OPTION(NULL, 0, 0)
};

#ifdef OPENCONNECT_GNUTLS
static void oc_gnutls_log_func(int level, const char *str)
{
	fputs(str, stderr);
}
#endif

#ifdef _WIN32
static int __attribute__ ((format(printf, 2, 0)))
    vfprintf_utf8(FILE *f, const char *fmt, va_list args)
{
	HANDLE h = GetStdHandle(f == stdout ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
	wchar_t wbuf[1024];
	char buf[1024];
	int chars, wchars;

	buf[sizeof(buf) - 1] = 0;
	chars = _vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	wchars = MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, sizeof(wbuf)/2);
	WriteConsoleW(h, wbuf, wchars, NULL, NULL);

	return chars;
}

static int __attribute__ ((format(printf, 2, 3)))
    fprintf_utf8(FILE *f, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vfprintf_utf8(f, fmt, args);
	va_end(args);

	return ret;
}

static wchar_t **argv_w;

/* This isn't so much "convert" the arg to UTF-8, as go grubbing
 * around in the real UTF-16 command line and find the corresponding
 * argument *there*, and convert *that* to UTF-8. Ick. But the
 * alternative is to implement wgetopt(), and that's even more horrid. */
static char *convert_arg_to_utf8(char **argv, char *arg)
{
	char *utf8;
	int chars;
	int offset;

	if (!argv_w) {
		int argc_w;

		argv_w = CommandLineToArgvW(GetCommandLineW(), &argc_w);
		if (!argv_w) {
			char *errstr = openconnect__win32_strerror(GetLastError());
			fprintf(stderr, _("CommandLineToArgvW() failed: %s\n"),
				errstr);
			free(errstr);
			exit(1);
		}
	}

	offset = arg - argv[optind - 1];

	/* Sanity check */
	if (offset < 0 || offset >= strlen(argv[optind - 1]) ||
	    (offset && (argv[optind - 1][offset-1] != '=' ||
			argv_w[optind - 1][offset - 1] != '='))) {
		fprintf(stderr, _("Fatal error in command line handling\n"));
		exit(1);
	}

	chars = WideCharToMultiByte(CP_UTF8, 0, argv_w[optind-1] + offset, -1,
				    NULL, 0, NULL, NULL);
	utf8 = malloc(chars);
	if (!utf8)
		return arg;

	WideCharToMultiByte(CP_UTF8, 0, argv_w[optind-1] + offset, -1, utf8,
			    chars, NULL, NULL);
	return utf8;
}

#undef fprintf
#undef vfprintf
#define fprintf fprintf_utf8
#define vfprintf vfprintf_utf8
#define is_arg_utf8(str) (0)

static void read_stdin(char **string, int hidden, int allow_fail)
{
	CONSOLE_READCONSOLE_CONTROL rcc = { sizeof(rcc), 0, 13, 0 };
	HANDLE stdinh = GetStdHandle(STD_INPUT_HANDLE);
	DWORD cmode, nr_read;
	wchar_t wbuf[1024];
	char *buf;

	if (GetConsoleMode(stdinh, &cmode)) {
		if (hidden)
			SetConsoleMode(stdinh, cmode & (~ENABLE_ECHO_INPUT));

		if (!ReadConsoleW(stdinh, wbuf, sizeof(wbuf)/2, &nr_read, &rcc)) {
			char *errstr = openconnect__win32_strerror(GetLastError());
			fprintf(stderr, _("ReadConsole() failed: %s\n"), errstr);
			free(errstr);
			*string = NULL;
			if (hidden)
				SetConsoleMode(stdinh, cmode);
			return;
		}
		if (hidden)
			SetConsoleMode(stdinh, cmode);
	} else {
		/* Not a console; maybe reading from a piped stdin? */
		if (!fgetws(wbuf, sizeof(wbuf)/2, stdin)) {
			char *errstr = openconnect__win32_strerror(GetLastError());
			fprintf(stderr, _("fgetws() failed: %s\n"), errstr);
			free(errstr);
			*string = NULL;
			return;
		}
		nr_read = wcslen(wbuf);
	}
	if (nr_read >= 2 && wbuf[nr_read - 1] == 10 && wbuf[nr_read - 2] == 13) {
		wbuf[nr_read - 2] = 0;
		nr_read -= 2;
	}

	nr_read = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
	if (!nr_read) {
		char *errstr = openconnect__win32_strerror(GetLastError());
		fprintf(stderr, _("Error converting console input: %s\n"),
			errstr);
		free(errstr);
		return;
	}
	buf = malloc(nr_read);
	if (!buf) {
		fprintf(stderr, _("Allocation failure for string from stdin\n"));
		exit(1);
	}

	if (!WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, nr_read, NULL, NULL)) {
		char *errstr = openconnect__win32_strerror(GetLastError());
		fprintf(stderr, _("Error converting console input: %s\n"),
			errstr);
		free(errstr);
		free(buf);
		return;
	}

	*string = buf;
}

#elif defined(HAVE_ICONV)
#include <iconv.h>

static int is_ascii(char *str)
{
	while (str && *str) {
		if ((unsigned char)*str > 0x7f)
			return 0;
		str++;
	}

	return 1;
}

static int __attribute__ ((format(printf, 2, 0)))
    vfprintf_utf8(FILE *f, const char *fmt, va_list args)
{
	char *utf8_str;
	iconv_t ic;
	int ret;
	char outbuf[80];
	ICONV_CONST char *ic_in;
	char *ic_out;
	size_t insize, outsize;

	if (!legacy_charset)
		return vfprintf(f, fmt, args);

	ret = vasprintf(&utf8_str, fmt, args);
	if (ret < 0)
		return -1;

	if (is_ascii(utf8_str))
		return fwrite(utf8_str, 1, strlen(utf8_str), f);

	ic = iconv_open(legacy_charset, "UTF-8");
	if (ic == (iconv_t) -1) {
		/* Better than nothing... */
		ret = fprintf(f, "%s", utf8_str);
		free(utf8_str);
		return ret;
	}

	ic_in = utf8_str;
	insize = strlen(utf8_str);
	ret = 0;

	while (insize) {
		ic_out = outbuf;
		outsize = sizeof(outbuf) - 1;

		if (iconv(ic, &ic_in, &insize, &ic_out, &outsize) == (size_t)-1) {
			if (errno == EILSEQ) {
				do {
					ic_in++;
					insize--;
				} while (insize && (ic_in[0] & 0xc0) == 0x80);
				ic_out[0] = '?';
				outsize--;
			} else if (errno != E2BIG)
				break;
		}
		ret += fwrite(outbuf, 1, sizeof(outbuf) - 1 - outsize, f);
	}

	iconv_close(ic);

	return ret;
}

static int __attribute__ ((format(printf, 2, 3)))
    fprintf_utf8(FILE *f, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vfprintf_utf8(f, fmt, args);
	va_end(args);

	return ret;
}

static char *convert_to_utf8(char *legacy, int free_it)
{
	char *utf8_str;
	iconv_t ic;
	ICONV_CONST char *ic_in;
	char *ic_out;
	size_t insize, outsize;

	if (!legacy_charset || is_ascii(legacy))
		return legacy;

	ic = iconv_open("UTF-8", legacy_charset);
	if (ic == (iconv_t) -1)
		return legacy;

	insize = strlen(legacy) + 1;
	ic_in = legacy;

	outsize = insize;
	ic_out = utf8_str = malloc(outsize);
	if (!utf8_str) {
	enomem:
		iconv_close(ic);
		return legacy;
	}

	while (insize) {
		if (iconv(ic, &ic_in, &insize, &ic_out, &outsize) == (size_t)-1) {
			if (errno == E2BIG) {
				int outlen = ic_out - utf8_str;
				realloc_inplace(utf8_str, outlen + 10);
				if (!utf8_str)
					goto enomem;
				ic_out = utf8_str + outlen;
				outsize = 10;
			} else {
				/* Should never happen */
				perror("iconv");
				free(utf8_str);
				goto enomem;
			}
		}
	}

	iconv_close(ic);
	if (free_it)
		free(legacy);
	return utf8_str;
}

#define fprintf fprintf_utf8
#define vfprintf vfprintf_utf8
#define convert_arg_to_utf8(av, l) convert_to_utf8((l), 0)
#define is_arg_utf8(a) (!legacy_charset || is_ascii(a))
#else
#define convert_to_utf8(l,f) (l)
#define convert_arg_to_utf8(av, l) (l)
#define is_arg_utf8(a) (1)
#endif

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
	switch(openconnect_has_oath_support()) {
	case 2:
		printf("%sHOTP software token", sep);
		sep = comma;
	case 1:
		printf("%sTOTP software token", sep);
		sep = comma;
	}
	if (openconnect_has_yubioath_support()) {
		printf("%sYubikey OATH", sep);
		sep = comma;
	}
	if (openconnect_has_system_key_support()) {
		printf("%sSystem keys", sep);
		sep = comma;
	}

#ifdef HAVE_DTLS
	printf("%sDTLS", sep);
#endif
#ifdef HAVE_ESP
	printf("%sESP", sep);
#endif
	printf("\n");

#if !defined(HAVE_DTLS) || !defined(HAVE_ESP)
	printf(_("WARNING: This binary lacks DTLS and/or ESP support. Performance will be impaired.\n"));
#endif
}

static void print_supported_protocols(void)
{
	const char *comma = ", ", *sep = comma + 1;
	struct oc_vpn_proto *protos, *p;

	if (openconnect_get_supported_protocols(&protos)>=0) {
		printf(_("Supported protocols:"));
		for (p=protos; p->name; p++) {
			printf("%s%s%s", sep, p->name, p==protos ? _(" (default)") : "");
			sep = comma;
		}
		printf("\n");
		free(protos);
	}
}

static void print_supported_protocols_usage(void)
{
	struct oc_vpn_proto *protos, *p;

	if (openconnect_get_supported_protocols(&protos)>=0) {
		printf(_("\n    Set VPN protocol:\n"));
		for (p=protos; p->name; p++)
			printf("      --protocol=%-16s %s%s\n",
				   p->name, p->description, p==protos ? _(" (default)") : "");
		openconnect_free_supported_protocols(protos);
	}
}

#ifndef _WIN32
static const char default_vpncscript[] = DEFAULT_VPNCSCRIPT;
static void read_stdin(char **string, int hidden, int allow_fail)
{
	char *c, *buf = malloc(1025);
	int fd = fileno(stdin);
	struct termios t;

	if (!buf) {
		fprintf(stderr, _("Allocation failure for string from stdin\n"));
		exit(1);
	}

	if (hidden) {
		tcgetattr(fd, &t);
		t.c_lflag &= ~ECHO;
		tcsetattr(fd, TCSANOW, &t);
	}

	buf = fgets(buf, 1025, stdin);

	if (hidden) {
		t.c_lflag |= ECHO;
		tcsetattr(fd, TCSANOW, &t);
		fprintf(stderr, "\n");
	}

	if (!buf) {
		if (allow_fail) {
			*string = NULL;
			free(buf);
			return;
		} else {
			perror(_("fgets (stdin)"));
			exit(1);
		}
	}

	c = strchr(buf, '\n');
	if (c)
		*c = 0;

	*string = convert_to_utf8(buf, 1);
}

static void handle_signal(int sig)
{
	char cmd;

	switch (sig) {
	case SIGINT:
		cmd = OC_CMD_CANCEL;
		break;
	case SIGHUP:
		cmd = OC_CMD_DETACH;
		break;
	case SIGUSR2:
	default:
		cmd = OC_CMD_PAUSE;
		break;
	}

	if (write(sig_cmd_fd, &cmd, 1) < 0) {
	/* suppress warn_unused_result */
	}
}
#else /* _WIN32 */
static const char *default_vpncscript;
static void set_default_vpncscript(void)
{
	if (PathIsRelative(DEFAULT_VPNCSCRIPT)) {
		char *c = strrchr(_pgmptr, '\\');
		if (!c) {
			fprintf(stderr, _("Cannot process this executable path \"%s\""),
				_pgmptr);
			exit(1);
		}
		if (asprintf((char **)&default_vpncscript, "%.*s%s",
			     (c - _pgmptr + 1), _pgmptr, DEFAULT_VPNCSCRIPT) < 0) {
			fprintf(stderr, _("Allocation for vpnc-script path failed\n"));
			exit(1);
		}
	} else {
		default_vpncscript = "cscript " DEFAULT_VPNCSCRIPT;
	}
}
#endif

static struct oc_vpn_option *gai_overrides;

static int gai_override_cb(void *cbdata, const char *node,
			    const char *service, const struct addrinfo *hints,
			    struct addrinfo **res)
{
	struct openconnect_info *vpninfo = cbdata;
	struct oc_vpn_option *p = gai_overrides;

	while (p) {
		if (!strcmp(node, p->option)) {
			vpn_progress(vpninfo, PRG_TRACE, _("Override hostname '%s' to '%s'\n"),
				     node, p->value);
			node = p->value;
			break;
		}
		p = p->next;
	}

	return getaddrinfo(node, service, hints, res);
}

static void usage(void)
{
	printf(_("Usage:  openconnect [options] <server>\n"));
	printf(_("Open client for multiple VPN protocols, version %s\n\n"), openconnect_version_str);
	print_build_opts();
	printf("      --config=CONFIGFILE         %s\n", _("Read options from config file"));
#ifndef _WIN32
	printf("  -b, --background                %s\n", _("Continue in background after startup"));
	printf("      --pid-file=PIDFILE          %s\n", _("Write the daemon's PID to this file"));
#endif
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
#ifndef _WIN32
	printf("  -l, --syslog                    %s\n", _("Use syslog for progress messages"));
#endif
	printf("      --timestamp                 %s\n", _("Prepend timestamp to progress messages"));
	printf("      --passtos                   %s\n", _("copy TOS / TCLASS when using DTLS"));
#ifndef _WIN32
	printf("  -U, --setuid=USER               %s\n", _("Drop privileges after connecting"));
	printf("      --csd-user=USER             %s\n", _("Drop privileges during CSD execution"));
	printf("      --csd-wrapper=SCRIPT        %s\n", _("Run SCRIPT instead of CSD binary"));
#endif
	printf("  -m, --mtu=MTU                   %s\n", _("Request MTU from server (legacy servers only)"));
	printf("      --base-mtu=MTU              %s\n", _("Indicate path MTU to/from server"));
	printf("  -p, --key-password=PASS         %s\n", _("Set key passphrase or TPM SRK PIN"));
	printf("      --key-password-from-fsid    %s\n", _("Key passphrase is fsid of file system"));
	printf("  -P, --proxy=URL                 %s\n", _("Set proxy server"));
	printf("      --proxy-auth=METHODS        %s\n", _("Set proxy authentication methods"));
	printf("      --no-proxy                  %s\n", _("Disable proxy"));
	printf("      --libproxy                  %s\n", _("Use libproxy to automatically configure proxy"));
#ifndef LIBPROXY_HDR
	printf("                                  %s\n", _("(NOTE: libproxy disabled in this build)"));
#endif
	printf("      --pfs                       %s\n", _("Require perfect forward secrecy"));
	printf("  -q, --quiet                     %s\n", _("Less output"));
	printf("  -Q, --queue-len=LEN             %s\n", _("Set packet queue limit to LEN pkts"));
	printf("  -s, --script=SCRIPT             %s\n", _("Shell command line for using a vpnc-compatible config script"));
	printf("                                  %s: \"%s\"\n", _("default"), default_vpncscript);
#ifndef _WIN32
	printf("  -S, --script-tun                %s\n", _("Pass traffic to 'script' program, not tun"));
#endif
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
	printf("      --no-system-trust           %s\n", _("Disable default system certificate authorities"));
	printf("      --no-xmlpost                %s\n", _("Do not attempt XML POST authentication"));
	printf("      --non-inter                 %s\n", _("Do not expect user input; exit if it is required"));
	printf("      --passwd-on-stdin           %s\n", _("Read password from standard input"));
	printf("      --token-mode=MODE           %s\n", _("Software token type: rsa, totp or hotp"));
	printf("      --token-secret=STRING       %s\n", _("Software token secret"));
#ifndef HAVE_LIBSTOKEN
	printf("                                  %s\n", _("(NOTE: libstoken (RSA SecurID) disabled in this build)"));
#endif
#ifndef HAVE_LIBPCSCLITE
	printf("                                  %s\n", _("(NOTE: Yubikey OATH disabled in this build)"));
#endif
	printf("      --reconnect-timeout         %s\n", _("Connection retry timeout in seconds"));
	printf("      --servercert=FINGERPRINT    %s\n", _("Server's certificate SHA1 fingerprint"));
	printf("      --useragent=STRING          %s\n", _("HTTP header User-Agent: field"));
	printf("      --local-hostname=STRING     %s\n", _("Local hostname to advertise to server"));
	printf("      --resolve=HOST:IP           %s\n", _("Use IP when connecting to HOST"));
	printf("      --os=STRING                 %s\n", _("OS type (linux,linux-64,win,...) to report"));
	printf("      --dtls-local-port=PORT      %s\n", _("Set local port for DTLS datagrams"));
	print_supported_protocols_usage();

	printf("\n");

	helpmessage();
	exit(1);
}


static FILE *config_file = NULL;
static int config_line_num = 0;

static char *xstrdup(const char *arg)
{
	char *ret;

	if (!arg)
		return NULL;

	ret = strdup(arg);

	if (!ret) {
		fprintf(stderr, _("Failed to allocate string\n"));
		exit(1);
	}
	return ret;
}

/* There are three ways to handle config_arg:
 *
 * 1. We only care about it transiently and it can be lost entirely
 *    (e.g. vpninfo->reconnect_timeout = atoi(config_arg);
 * 2. We need to keep it, but it's a static string and will never be freed
 *    so when it's part of argv[] we can use it in place (unless it needs
 *    converting to UTF-8), but when it comes from a file we have to strdup()
 *    because otherwise it'll be overwritten.
 *    For this we use the keep_config_arg() macro below.
 * 3. It may be freed during normal operation, so we have to use strdup()
 *    or convert_arg_to_utf8() even when it's an option from argv[].
 *    (e.g. vpninfo->cert_password).
 *    For this we use the dup_config_arg() macro below.
 */

#define keep_config_arg() \
	(config_file ? xstrdup(config_arg) : convert_arg_to_utf8(argv, config_arg))

#define dup_config_arg() __dup_config_arg(argv, config_arg)

static inline char *__dup_config_arg(char **argv, char *config_arg)
{
	char *res;

	if (config_file || is_arg_utf8(config_arg))
	    return xstrdup(config_arg);

	res = convert_arg_to_utf8(argv, config_arg);
	/* Force a copy, even if conversion failed */
	if (res == config_arg)
		res = xstrdup(res);
	return res;
}

static int next_option(int argc, char **argv, char **config_arg)
{
	/* These get re-used */
	static char *line_buf = NULL;
	static size_t line_size = 0;

	ssize_t llen;
	int opt, optlen = 0;
	const struct option *this;
	char *line;
	int ate_equals = 0;

 next:
	if (!config_file) {
		opt = getopt_long(argc, argv,
#ifdef _WIN32
				  "C:c:Dde:g:hi:k:m:P:p:Q:qs:u:Vvx:",
#else
				  "bC:c:Dde:g:hi:k:lm:P:p:Q:qSs:U:u:Vvx:",
#endif
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

#ifndef _WIN32
static void get_uids(const char *config_arg, uid_t *uid, gid_t *gid)
{
	char *strend;
	struct passwd *pw;
	int e;

	*uid = strtol(config_arg, &strend, 0);
	if (strend[0]) {
		pw = getpwnam(config_arg);
		if (!pw) {
			e = errno;
			fprintf(stderr, _("Invalid user \"%s\": %s\n"),
				config_arg, strerror(e));
			exit(1);
		}
		*uid = pw->pw_uid;
		*gid = pw->pw_gid;
	} else {
		pw = getpwuid(*uid);
		if (!pw) {
			e = errno;
			fprintf(stderr, _("Invalid user ID \"%d\": %s\n"),
				(int)*uid, strerror(e));
			exit(1);
		}
		*gid = pw->pw_gid;
	}
}
#endif

int main(int argc, char **argv)
{
	struct openconnect_info *vpninfo;
	char *urlpath = NULL;
	struct oc_vpn_option *gai;
	char *ip;
	const char *compr = "";
	char *proxy = getenv("https_proxy");
	char *vpnc_script = NULL;
	const struct oc_ip_info *ip_info;
	int autoproxy = 0;
	int opt;
	char *pidfile = NULL;
	FILE *fp = NULL;
	char *config_arg;
	char *config_filename;
	char *token_str = NULL;
	oc_token_mode_t token_mode = OC_TOKEN_MODE_NONE;
	int reconnect_timeout = 300;
	int ret;
#ifdef HAVE_NL_LANGINFO
	char *charset;
#endif
#ifndef _WIN32
	struct sigaction sa;
	struct utsname utsbuf;
	int use_syslog = 0;
#endif

#ifdef ENABLE_NLS
	bindtextdomain("openconnect", LOCALEDIR);
#endif

	if (!setlocale(LC_ALL, ""))
		fprintf(stderr,
			_("WARNING: Cannot set locale: %s\n"), strerror(errno));

#ifdef HAVE_NL_LANGINFO
	charset = nl_langinfo(CODESET);
	if (charset && strcmp(charset, "UTF-8"))
		legacy_charset = strdup(charset);

#ifndef HAVE_ICONV
	if (legacy_charset)
		fprintf(stderr,
			_("WARNING: This version of openconnect was built without iconv\n"
			  "         support but you appear to be using the legacy character\n"
			  "         set \"%s\". Expect strangeness.\n"), legacy_charset);
#endif /* !HAVE_ICONV */
#endif /* HAVE_NL_LANGINFO */

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
#ifdef _WIN32
	set_default_vpncscript();
#else
	vpninfo->use_tun_script = 0;
	vpninfo->uid = getuid();
	vpninfo->gid = getgid();

	if (!uname(&utsbuf)) {
		openconnect_set_localname(vpninfo, utsbuf.nodename);
	}
#endif

	while ((opt = next_option(argc, argv, &config_arg))) {

		if (opt < 0)
			break;

		switch (opt) {
#ifndef _WIN32
		case 'b':
			background = 1;
			break;
		case 'l':
			use_syslog = 1;
			break;
		case 'S':
			vpninfo->use_tun_script = 1;
			break;
		case 'U':
			get_uids(config_arg, &vpninfo->uid, &vpninfo->gid);
			break;
		case OPT_CSD_USER:
			get_uids(config_arg, &vpninfo->uid_csd, &vpninfo->gid_csd);
			vpninfo->uid_csd_given = 1;
			break;
		case OPT_CSD_WRAPPER:
			vpninfo->csd_wrapper = keep_config_arg();
			break;
#endif /* !_WIN32 */
		case OPT_PROTOCOL:
			if (openconnect_set_protocol(vpninfo, config_arg))
				exit(1);
			break;
		case OPT_JUNIPER:
			fprintf(stderr, "WARNING: Juniper Network Connect support is experimental.\n");
			fprintf(stderr, "It will probably be superseded by Junos Pulse support.\n");
			openconnect_set_protocol(vpninfo, "nc");
			break;
		case OPT_CONFIGFILE:
			if (config_file) {
				fprintf(stderr, _("Cannot use 'config' option inside config file\n"));
				exit(1);
			}
			config_filename = keep_config_arg(); /* Convert to UTF-8 */
			config_file = openconnect_fopen_utf8(vpninfo, config_filename, "r");
			if (config_filename != config_arg)
				free(config_filename);
			if (!config_file) {
				fprintf(stderr, _("Cannot open config file '%s': %s\n"),
					config_arg, strerror(errno));
				exit(1);
			}
			config_line_num = 1;
			/* The next option will come from the file... */
			break;
		case OPT_COMPRESSION:
			if (!strcmp(config_arg, "none") ||
			    !strcmp(config_arg, "off"))
				openconnect_set_compression_mode(vpninfo, OC_COMPRESSION_MODE_NONE);
			else if (!strcmp(config_arg, "all"))
				openconnect_set_compression_mode(vpninfo, OC_COMPRESSION_MODE_ALL);
			else if (!strcmp(config_arg, "stateless"))
				openconnect_set_compression_mode(vpninfo, OC_COMPRESSION_MODE_STATELESS);
			else {
				fprintf(stderr, _("Invalid compression mode '%s'\n"),
					config_arg);
				exit(1);
			}
			break;
		case OPT_CAFILE:
			openconnect_set_cafile(vpninfo, dup_config_arg());
			break;
		case OPT_PIDFILE:
			pidfile = keep_config_arg();
			break;
		case OPT_PFS:
			openconnect_set_pfs(vpninfo, 1);
			break;
		case OPT_SERVERCERT:
			server_cert = keep_config_arg();
			openconnect_set_system_trust(vpninfo, 0);
			break;
		case OPT_RESOLVE:
			ip = strchr(config_arg, ':');
			if (!ip) {
				fprintf(stderr, _("Missing colon in resolve option\n"));
				exit(1);
			}
			gai = malloc(sizeof(*gai) + strlen(config_arg) + 1);
			if (!gai) {
				fprintf(stderr, _("Failed to allocate memory\n"));
				exit(1);
			}
			gai->next = gai_overrides;
			gai_overrides = gai;
			gai->option = (void *)(gai + 1);
			memcpy(gai->option, config_arg, strlen(config_arg) + 1);
			gai->option[ip - config_arg] = 0;
			gai->value = gai->option + (ip - config_arg) + 1;
			break;
		case OPT_NO_DTLS:
			vpninfo->dtls_state = DTLS_DISABLED;
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
			read_stdin(&vpninfo->cookie, 0, 0);
			/* If the cookie is empty, ignore it */
			if (!*vpninfo->cookie)
				vpninfo->cookie = NULL;
			break;
		case OPT_PASSWORD_ON_STDIN:
			read_stdin(&password, 0, 0);
			allow_stdin_read = 1;
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
		case 'C':
			vpninfo->cookie = dup_config_arg();
			break;
		case 'c':
			vpninfo->cert = dup_config_arg();
			break;
		case 'e':
			vpninfo->cert_expire_warning = 86400 * atoi(config_arg);
			break;
		case 'k':
			vpninfo->sslkey = dup_config_arg();
			break;
		case 'd':
			vpninfo->req_compr = COMPR_ALL;
			break;
		case 'D':
			vpninfo->req_compr = 0;
			break;
		case 'g':
			free(urlpath);
			urlpath = dup_config_arg();
			break;
		case 'h':
			usage();
		case 'i':
			vpninfo->ifname = dup_config_arg();
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
			vpninfo->cert_password = dup_config_arg();
			break;
		case 'P':
			proxy = keep_config_arg();
			autoproxy = 0;
			break;
		case OPT_PROXY_AUTH:
			openconnect_set_proxy_auth(vpninfo, config_arg);
			break;
		case OPT_HTTP_AUTH:
			openconnect_set_http_auth(vpninfo, config_arg);
			break;
		case OPT_NO_PROXY:
			autoproxy = 0;
			proxy = NULL;
			break;
		case OPT_NO_SYSTEM_TRUST:
			openconnect_set_system_trust(vpninfo, 0);
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
			fprintf(stderr,
				_("The --no-cert-check option was insecure and has been removed.\n"
				  "Fix your server's certificate or use --servercert to trust it.\n"));
			exit(1);
			break;
		case 's':
			vpnc_script = dup_config_arg();
			break;
		case 'u':
			free(username);
			username = dup_config_arg();
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
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			printf(_("OpenConnect version %s\n"), openconnect_version_str);
			print_build_opts();
			print_supported_protocols();
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
			vpninfo->useragent = dup_config_arg();
			break;
		case OPT_LOCAL_HOSTNAME:
			openconnect_set_localname(vpninfo, config_arg);
			break;
		case OPT_FORCE_DPD:
			openconnect_set_dpd(vpninfo, atoi(config_arg));
			break;
		case OPT_DTLS_LOCAL_PORT:
			vpninfo->dtls_local_port = atoi(config_arg);
			break;
		case OPT_TOKEN_MODE:
			if (strcasecmp(config_arg, "rsa") == 0) {
				token_mode = OC_TOKEN_MODE_STOKEN;
			} else if (strcasecmp(config_arg, "totp") == 0) {
				token_mode = OC_TOKEN_MODE_TOTP;
			} else if (strcasecmp(config_arg, "hotp") == 0) {
				token_mode = OC_TOKEN_MODE_HOTP;
			} else if (strcasecmp(config_arg, "yubioath") == 0) {
				token_mode = OC_TOKEN_MODE_YUBIOATH;
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
					dup_config_arg(),
					xstrdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
			}
			break;
		case OPT_PASSTOS:
			openconnect_set_pass_tos(vpninfo, 1);
			break;
		case OPT_TIMESTAMP:
			timestamp = 1;
			break;
#ifdef OPENCONNECT_GNUTLS
		case OPT_GNUTLS_DEBUG:
			gnutls_global_set_log_level(atoi(config_arg));
			gnutls_global_set_log_function(oc_gnutls_log_func);
			break;
#endif
		default:
			usage();
		}
	}

	if (gai_overrides)
		openconnect_override_getaddrinfo(vpninfo, gai_override_cb);

	if (optind < argc - 1) {
		fprintf(stderr, _("Too many arguments on command line\n"));
		usage();
	} else if (optind > argc - 1) {
		fprintf(stderr, _("No server specified\n"));
		usage();
	}

	if (!vpninfo->sslkey)
		vpninfo->sslkey = vpninfo->cert;

	if (vpninfo->dump_http_traffic && verbose < PRG_DEBUG)
		verbose = PRG_DEBUG;

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

#if !defined(_WIN32) && !defined(__native_client__)
	if (use_syslog) {
		openlog("openconnect", LOG_PID, LOG_DAEMON);
		vpninfo->progress = syslog_progress;
	}
#endif /* !_WIN32 && !__native_client__ */

#ifndef _WIN32
	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
#endif /* !_WIN32 */

	sig_cmd_fd = openconnect_setup_cmd_pipe(vpninfo);
	if (sig_cmd_fd < 0) {
		fprintf(stderr, _("Error opening cmd pipe\n"));
		exit(1);
	}

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
		printf("FINGERPRINT='%s'\n",
		       openconnect_get_peer_cert_hash(vpninfo));
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
		vpnc_script = xstrdup(default_vpncscript);

	STRDUP(vpninfo->vpnc_script, vpnc_script);

	if (vpninfo->dtls_state != DTLS_DISABLED &&
	    openconnect_setup_dtls(vpninfo, 60)) {
		/* Disable DTLS if we cannot set it up, otherwise
		 * reconnects end up in infinite loop trying to connect
		 * to non existing DTLS */
		vpninfo->dtls_state = DTLS_DISABLED;
		fprintf(stderr, _("Set up DTLS failed; using SSL instead\n"));
	}

	openconnect_get_ip_info(vpninfo, &ip_info, NULL, NULL);

	if (vpninfo->dtls_state != DTLS_CONNECTED) {
		if (vpninfo->cstp_compr == COMPR_DEFLATE)
			compr = " + deflate";
		else if (vpninfo->cstp_compr == COMPR_LZS)
			compr = " + lzs";
		else if (vpninfo->cstp_compr == COMPR_LZ4)
			compr = " + lz4";
	} else {
		if (vpninfo->dtls_compr == COMPR_DEFLATE)
			compr = " + deflate";
		else if (vpninfo->dtls_compr == COMPR_LZS)
			compr = " + lzs";
		else if (vpninfo->dtls_compr == COMPR_LZ4)
			compr = " + lz4";
	}
	vpn_progress(vpninfo, PRG_INFO,
		     _("Connected as %s%s%s, using %s%s\n"),
		     ip_info->addr?:"",
		     (ip_info->netmask6 && ip_info->addr) ? " + " : "",
		     ip_info->netmask6 ? : "",
		     (vpninfo->dtls_state != DTLS_CONNECTED) ? "SSL"
		     : "DTLS", compr);

	if (!vpninfo->vpnc_script) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("No --script argument provided; DNS and routing are not configured\n"));
		vpn_progress(vpninfo, PRG_INFO,
			     _("See http://www.infradead.org/openconnect/vpnc-script.html\n"));
	}

#ifndef _WIN32
	if (background) {
		int pid;

		/* Open the pidfile before forking, so we can report errors
		   more sanely. It's *possible* that we'll fail to write to
		   it, but very unlikely. */
		if (pidfile != NULL) {
			fp = openconnect_fopen_utf8(vpninfo, pidfile, "w");
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
#endif

	openconnect_set_loglevel(vpninfo, verbose);

	while (1) {
		ret = openconnect_mainloop(vpninfo, reconnect_timeout, RECONNECT_INTERVAL_MIN);
		if (ret)
			break;

		vpn_progress(vpninfo, PRG_INFO, _("User requested reconnect\n"));
	}

	if (fp)
		unlink(pidfile);

	switch (ret) {
	case -EPERM:
		vpn_progress(vpninfo, PRG_ERR, _("Cookie was rejected on reconnection; exiting.\n"));
		ret = 2;
		break;
	case -EPIPE:
		vpn_progress(vpninfo, PRG_ERR, _("Session terminated by server; exiting.\n"));
		ret = 1;
		break;
	case -EINTR:
		vpn_progress(vpninfo, PRG_INFO, _("User cancelled (SIGINT); exiting.\n"));
		ret = 0;
		break;
	case -ECONNABORTED:
		vpn_progress(vpninfo, PRG_INFO, _("User detached from session (SIGHUP); exiting.\n"));
		ret = 0;
		break;
	default:
		vpn_progress(vpninfo, PRG_ERR, _("Unknown error; exiting.\n"));
		ret = 1;
		break;
	}

	openconnect_vpninfo_free(vpninfo);
	exit(ret);
}

static int write_new_config(void *_vpninfo, const char *buf, int buflen)
{
	struct openconnect_info *vpninfo = _vpninfo;
	int config_fd;
	int err;

	config_fd = openconnect_open_utf8(vpninfo, vpninfo->xmlconfig,
					  O_WRONLY|O_TRUNC|O_CREAT|O_BINARY);
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

static void __attribute__ ((format(printf, 3, 4)))
    write_progress(void *_vpninfo, int level, const char *fmt, ...)
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

struct accepted_cert {
	struct accepted_cert *next;
	char *fingerprint;
	char *host;
	int port;
} *accepted_certs;

static int validate_peer_cert(void *_vpninfo, const char *reason)
{
	struct openconnect_info *vpninfo = _vpninfo;
	const char *fingerprint;
	struct accepted_cert *this;

	if (server_cert) {
		int err = openconnect_check_peer_cert_hash(vpninfo, server_cert);

		if (!err)
			return 0;

		if (err < 0)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Could not calculate hash of server's certificate\n"));
		else
			vpn_progress(vpninfo, PRG_ERR,
				     _("Server SSL certificate didn't match: %s\n"),
				     openconnect_get_peer_cert_hash(vpninfo));

		return -EINVAL;
	}

	fingerprint = openconnect_get_peer_cert_hash(vpninfo);

	for (this = accepted_certs; this; this = this->next) {
		if (!strcasecmp(this->host, vpninfo->hostname) &&
		    this->port == vpninfo->port &&
		    !openconnect_check_peer_cert_hash(vpninfo, this->fingerprint))
			return 0;
	}

	while (1) {
		char *details;
		char *response = NULL;

		fprintf(stderr, _("\nCertificate from VPN server \"%s\" failed verification.\n"
			 "Reason: %s\n"), vpninfo->hostname, reason);

		fprintf(stderr, _("To trust this server in future, perhaps add this to your command line:\n"));
		fprintf(stderr, _("    --servercert %s\n"), fingerprint);

		if (non_inter)
			return -EINVAL;

		fprintf(stderr, _("Enter '%s' to accept, '%s' to abort; anything else to view: "),
		       _("yes"), _("no"));

		read_stdin(&response, 0, 0);
		if (!response)
			return -EINVAL;

		if (!strcasecmp(response, _("yes"))) {
			struct accepted_cert *newcert = malloc(sizeof(*newcert));
			if (newcert) {
				newcert->next = accepted_certs;
				accepted_certs = newcert;
				newcert->fingerprint = strdup(fingerprint);
				newcert->host = strdup(vpninfo->hostname);
				newcert->port = vpninfo->port;
			}
			free(response);
			return 0;
		}
		if (!strcasecmp(response, _("no"))) {
			free(response);
			return -EINVAL;
		}
		free(response);

		details = openconnect_get_peer_cert_details(vpninfo);
		fputs(details, stderr);
		openconnect_free_cert_info(vpninfo, details);
		fprintf(stderr, _("Server key hash: %s\n"), fingerprint);
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
				select_opt->form._value = choice->name;
				return 0;
			} else {
				match = choice->name;
				partial_matches++;
			}
		}
	}

	if (partial_matches == 1) {
		select_opt->form._value = match;
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
	char *response = NULL;

	fprintf(stderr, "%s", prompt);
	fflush(stderr);

	if (non_inter) {
		if (allow_stdin_read) {
			read_stdin(&response, hidden, 1);
		}
		if (response == NULL) {
			fprintf(stderr, "***\n");
			vpn_progress(vpninfo, PRG_ERR,
			     _("User input required in non-interactive mode\n"));
		}
		return response;
	}

	read_stdin(&response, hidden, 0);
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
			    !strncmp(opt->name, "user", 4)) {
				opt->_value = username;
				username = NULL;
			} else {
				opt->_value = prompt_for_input(opt->label, vpninfo, 0);
			}

			if (!opt->_value)
				goto err;
			empty = 0;

		} else if (opt->type == OC_FORM_OPT_PASSWORD) {
			if (password &&
			    !strncmp(opt->name, "pass", 4)) {
				opt->_value = password;
				password = NULL;
			} else {
				opt->_value = prompt_for_input(opt->label, vpninfo, 1);
			}

			if (!opt->_value)
				goto err;
			empty = 0;
		} else if (opt->type == OC_FORM_OPT_TOKEN) {
			/* Nothing to do here, but if the tokencode is being
			 * automatically generated then don't treat it as an
			 * empty form for the purpose of loop avoidance. */
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

static int lock_token(void *tokdata)
{
	struct openconnect_info *vpninfo = tokdata;
	char *file_token;
	int err;

	/* FIXME: Actually lock the file */
	err = read_file_into_string(vpninfo, token_filename, &file_token);
	if (err < 0)
	    return err;

	err = openconnect_set_token_mode(vpninfo, vpninfo->token_mode, file_token);
	free(file_token);

	return 0;
}

static int unlock_token(void *tokdata, const char *new_tok)
{
	struct openconnect_info *vpninfo = tokdata;
	int tok_fd;
	int err;

	if (!new_tok)
		return 0;

	tok_fd = openconnect_open_utf8(vpninfo, token_filename,
				       O_WRONLY|O_TRUNC|O_CREAT|O_BINARY);
	if (tok_fd < 0) {
		err = errno;
		fprintf(stderr, _("Failed to open token file for write: %s\n"),
			strerror(err));
		return -err;
	}

	/* FIXME: We should actually write to a new tempfile, then rename */
	if (write(tok_fd, new_tok, strlen(new_tok)) != strlen(new_tok)) {
		err = errno;
		fprintf(stderr, _("Failed to write token: %s\n"),
			strerror(err));
		close(tok_fd);
		return -err;
	}

	close(tok_fd);
	return 0;
}

static void init_token(struct openconnect_info *vpninfo,
		       oc_token_mode_t token_mode, const char *token_str)
{
	int ret;
	char *file_token = NULL;

	if (token_str) {
		switch(token_str[0]) {
		case '@':
			token_str++;
			/* fall through... */
		case '/':
			if (read_file_into_string(vpninfo, token_str,
						  &file_token) < 0)
				exit(1);
			break;
		default:
			/* Use token_str as raw data */
			break;
		}
	}

	ret = openconnect_set_token_mode(vpninfo, token_mode,
					 file_token ? : token_str);
	if (file_token) {
		token_filename = strdup(token_str);
		openconnect_set_token_callbacks(vpninfo, vpninfo,
						lock_token, unlock_token);
		free(file_token);
	}
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
	case OC_TOKEN_MODE_HOTP:
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

	case OC_TOKEN_MODE_YUBIOATH:
		switch(ret) {
		case 0:
			return;
		case -ENOENT:
			fprintf(stderr, _("Yubikey token not found\n"));
			exit(1);
		case -EOPNOTSUPP:
			fprintf(stderr, _("OpenConnect was not built with Yubikey support\n"));
			exit(1);
		default:
			fprintf(stderr, _("General Yubikey failure: %s\n"), strerror(-ret));
			exit(1);
		}

	case OC_TOKEN_MODE_NONE:
		/* No-op */
		break;

	/* Option parsing already checked for invalid modes. */
	}
}
