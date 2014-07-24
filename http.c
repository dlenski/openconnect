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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#ifndef _WIN32
#include <pwd.h>
#endif

#include "openconnect-internal.h"

static int proxy_write(struct openconnect_info *vpninfo, char *buf, size_t len);
static int proxy_read(struct openconnect_info *vpninfo, char *buf, size_t len);

#define MAX_BUF_LEN 131072
#define BUF_CHUNK_SIZE 4096

struct oc_text_buf *buf_alloc(void)
{
	return calloc(1, sizeof(struct oc_text_buf));
}

void buf_append_urlencoded(struct oc_text_buf *buf, char *str)
{
	while (str && *str) {
		if (isalnum((int)(unsigned char)*str))
			buf_append_bytes(buf, str, 1);
		else
			buf_append(buf, "%%%02x", (unsigned char)*str);
		str++;
	}
}

void buf_truncate(struct oc_text_buf *buf)
{
	if (!buf)
		return;

	buf->pos = 0;
	if (buf->data)
		buf->data[0] = 0;
}

int buf_ensure_space(struct oc_text_buf *buf, int len)
{
	int new_buf_len;

	new_buf_len = (buf->pos + len + BUF_CHUNK_SIZE - 1) & ~(BUF_CHUNK_SIZE - 1);

	if (new_buf_len <= buf->buf_len)
		return 0;

	if (new_buf_len > MAX_BUF_LEN) {
		buf->error = -E2BIG;
		return buf->error;
	} else {
		realloc_inplace(buf->data, new_buf_len);
		if (!buf->data)
			buf->error = -ENOMEM;
		else
			buf->buf_len = new_buf_len;
	}
	return buf->error;
}

void  __attribute__ ((format (printf, 2, 3)))
	buf_append(struct oc_text_buf *buf, const char *fmt, ...)
{
	va_list ap;

	if (!buf || buf->error)
		return;

	if (buf_ensure_space(buf, 1))
		return;

	while (1) {
		int max_len = buf->buf_len - buf->pos, ret;

		va_start(ap, fmt);
		ret = vsnprintf(buf->data + buf->pos, max_len, fmt, ap);
		va_end(ap);
		if (ret < 0) {
			buf->error = -EIO;
			break;
		} else if (ret < max_len) {
			buf->pos += ret;
			break;
		} else if (buf_ensure_space(buf, ret))
			break;
	}
}

void buf_append_bytes(struct oc_text_buf *buf, const void *bytes, int len)
{
	if (!buf || buf->error)
		return;

	if (buf_ensure_space(buf, len + 1))
		return;

	memcpy(buf->data + buf->pos, bytes, len);
	buf->pos += len;
	buf->data[buf->pos] = 0;
}

int buf_error(struct oc_text_buf *buf)
{
	return buf ? buf->error : -ENOMEM;
}

int buf_free(struct oc_text_buf *buf)
{
	int error = buf_error(buf);

	if (buf) {
		if (buf->data)
			free(buf->data);
		free(buf);
	}

	return error;
}

/*
 * We didn't really want to have to do this for ourselves -- one might have
 * thought that it would be available in a library somewhere. But neither
 * cURL nor Neon have reliable cross-platform ways of either using a cert
 * from the TPM, or just reading from / writing to a transport which is
 * provided by their caller.
 */

static int http_add_cookie(struct openconnect_info *vpninfo,
			   const char *option, const char *value)
{
	struct oc_vpn_option *new, **this;

	if (*value) {
		new = malloc(sizeof(*new));
		if (!new) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("No memory for allocating cookies\n"));
			return -ENOMEM;
		}
		new->next = NULL;
		new->option = strdup(option);
		new->value = strdup(value);
		if (!new->option || !new->value) {
			free(new->option);
			free(new->value);
			free(new);
			return -ENOMEM;
		}
	} else {
		/* Kill cookie; don't replace it */
		new = NULL;
	}
	for (this = &vpninfo->cookies; *this; this = &(*this)->next) {
		if (!strcmp(option, (*this)->option)) {
			/* Replace existing cookie */
			if (new)
				new->next = (*this)->next;
			else
				new = (*this)->next;

			free((*this)->option);
			free((*this)->value);
			free(*this);
			*this = new;
			break;
		}
	}
	if (new && !*this) {
		*this = new;
		new->next = NULL;
	}
	return 0;
}

#define BODY_HTTP10 -1
#define BODY_CHUNKED -2

static int process_http_response(struct openconnect_info *vpninfo, int *result, int connect,
				 int (*header_cb)(struct openconnect_info *, char *, char *),
				 char **body_ret)
{
	char buf[MAX_BUF_LEN];
	char *body = NULL;
	int bodylen = BODY_HTTP10;
	int done = 0;
	int closeconn = 0;
	int i;

 cont:
	if (vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error fetching HTTPS response\n"));
		openconnect_close_https(vpninfo, 0);
		return -EINVAL;
	}

	if (!strncmp(buf, "HTTP/1.0 ", 9))
		closeconn = 1;

	if ((!closeconn && strncmp(buf, "HTTP/1.1 ", 9)) || !(*result = atoi(buf+9))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse HTTP response '%s'\n"), buf);
		openconnect_close_https(vpninfo, 0);
		return -EINVAL;
	}

	vpn_progress(vpninfo, (*result == 200 || *result == 407) ? PRG_DEBUG : PRG_INFO,
		     _("Got HTTP response: %s\n"), buf);

	/* Eat headers... */
	while ((i = vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)))) {
		char *colon;

		if (i < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error processing HTTP response\n"));
			openconnect_close_https(vpninfo, 0);
			return -EINVAL;
		}
		colon = strchr(buf, ':');
		if (!colon) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Ignoring unknown HTTP response line '%s'\n"), buf);
			continue;
		}
		*(colon++) = 0;
		if (*colon == ' ')
			colon++;

		/* Handle Set-Cookie first so that we can avoid printing the
		   webvpn cookie in the verbose debug output */
		if (!strcasecmp(buf, "Set-Cookie")) {
			char *semicolon = strchr(colon, ';');
			const char *print_equals;
			char *equals = strchr(colon, '=');
			int ret;

			if (semicolon)
				*semicolon = 0;

			if (!equals) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Invalid cookie offered: %s\n"), buf);
				return -EINVAL;
			}
			*(equals++) = 0;

			print_equals = equals;
			/* Don't print the webvpn cookie unless it's empty; we don't
			   want people posting it in public with debugging output */
			if (!strcmp(colon, "webvpn") && *equals)
				print_equals = _("<elided>");
			vpn_progress(vpninfo, PRG_DEBUG, "%s: %s=%s%s%s\n",
				     buf, colon, print_equals, semicolon ? ";" : "",
				     semicolon ? (semicolon+1) : "");

			/* The server tends to ask for the username and password as
			   usual, even if we've already failed because it didn't like
			   our cert. Thankfully it does give us this hint... */
			if (!strcmp(colon, "ClientCertAuthFailed"))
				vpn_progress(vpninfo, PRG_ERR,
					     _("SSL certificate authentication failed\n"));

			ret = http_add_cookie(vpninfo, colon, equals);
			if (ret)
				return ret;
		} else {
			vpn_progress(vpninfo, PRG_DEBUG, "%s: %s\n", buf, colon);
		}

		if (!strcasecmp(buf, "Connection")) {
			if (!strcasecmp(colon, "Close"))
				closeconn = 1;
#if 0
			/* This might seem reasonable, but in fact it breaks
			   certificate authentication with some servers. If
			   they give an HTTP/1.0 response, even if they
			   explicitly give a Connection: Keep-Alive header,
			   just close the connection. */
			else if (!strcasecmp(colon, "Keep-Alive"))
				closeconn = 0;
#endif
		}
		if (!strcasecmp(buf, "Location")) {
			vpninfo->redirect_url = strdup(colon);
			if (!vpninfo->redirect_url)
				return -ENOMEM;
		}
		if (!strcasecmp(buf, "Content-Length")) {
			bodylen = atoi(colon);
			if (bodylen < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Response body has negative size (%d)\n"),
					     bodylen);
				openconnect_close_https(vpninfo, 0);
				return -EINVAL;
			}
		}
		if (!strcasecmp(buf, "Transfer-Encoding")) {
			if (!strcasecmp(colon, "chunked"))
				bodylen = BODY_CHUNKED;
			else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unknown Transfer-Encoding: %s\n"),
					     colon);
				openconnect_close_https(vpninfo, 0);
				return -EINVAL;
			}
		}
		if (header_cb)
			header_cb(vpninfo, buf, colon);
	}

	/* Handle 'HTTP/1.1 100 Continue'. Not that we should ever see it */
	if (*result == 100)
		goto cont;

	/* On successful CONNECT, there is no body. Return success */
	if (connect && *result == 200)
		return 0;

	/* Now the body, if there is one */
	vpn_progress(vpninfo, PRG_DEBUG, _("HTTP body %s (%d)\n"),
		     bodylen == BODY_HTTP10 ? "http 1.0" :
		     bodylen == BODY_CHUNKED ? "chunked" : "length: ",
		     bodylen);

	/* If we were given Content-Length, it's nice and easy... */
	if (bodylen > 0) {
		body = malloc(bodylen + 1);
		if (!body)
			return -ENOMEM;
		while (done < bodylen) {
			i = vpninfo->ssl_read(vpninfo, body + done, bodylen - done);
			if (i < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error reading HTTP response body\n"));
				openconnect_close_https(vpninfo, 0);
				free(body);
				return -EINVAL;
			}
			done += i;
		}
	} else if (bodylen == BODY_CHUNKED) {
		/* ... else, chunked */
		while ((i = vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)))) {
			int chunklen, lastchunk = 0;

			if (i < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error fetching chunk header\n"));
				return i;
			}
			chunklen = strtol(buf, NULL, 16);
			if (!chunklen) {
				lastchunk = 1;
				goto skip;
			}
			realloc_inplace(body, done + chunklen + 1);
			if (!body)
				return -ENOMEM;
			while (chunklen) {
				i = vpninfo->ssl_read(vpninfo, body + done, chunklen);
				if (i < 0) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error reading HTTP response body\n"));
					free(body);
					return -EINVAL;
				}
				chunklen -= i;
				done += i;
			}
		skip:
			if ((i = vpninfo->ssl_gets(vpninfo, buf, sizeof(buf)))) {
				if (i < 0) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error fetching HTTP response body\n"));
				} else {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Error in chunked decoding. Expected '', got: '%s'"),
						     buf);
				}
				free(body);
				return -EINVAL;
			}

			if (lastchunk)
				break;
		}
	} else if (bodylen == BODY_HTTP10) {
		if (!closeconn) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Cannot receive HTTP 1.0 body without closing connection\n"));
			openconnect_close_https(vpninfo, 0);
			return -EINVAL;
		}

		/* HTTP 1.0 response. Just eat all we can in 16KiB chunks */
		while (1) {
			realloc_inplace(body, done + 16384);
			if (!body)
				return -ENOMEM;
			i = vpninfo->ssl_read(vpninfo, body + done, 16384);
			if (i > 0) {
				/* Got more data */
				done += i;
			} else if (i < 0) {
				/* Error */
				free(body);
				openconnect_close_https(vpninfo, 0);
				return i;
			} else {
				/* Connection closed. Reduce allocation to just what we need */
				realloc_inplace(body, done + 1);
				if (!body)
					return -ENOMEM;
				break;
			}
		}
	}

	if (closeconn || vpninfo->no_http_keepalive)
		openconnect_close_https(vpninfo, 0);

	if (body)
		body[done] = 0;
	*body_ret = body;
	return done;
}

static void add_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	struct oc_vpn_option *opt;

	buf_append(buf, "Host: %s\r\n", vpninfo->hostname);
	buf_append(buf, "User-Agent: %s\r\n", vpninfo->useragent);
	buf_append(buf, "Accept: */*\r\n");
	buf_append(buf, "Accept-Encoding: identity\r\n");

	if (vpninfo->cookies) {
		buf_append(buf, "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			buf_append(buf, "%s=%s%s", opt->option,
				      opt->value, opt->next ? "; " : "\r\n");
	}
	buf_append(buf, "X-Transcend-Version: 1\r\n");
	if (vpninfo->xmlpost) {
		buf_append(buf, "X-Aggregate-Auth: 1\r\n");
		buf_append(buf, "X-AnyConnect-Platform: %s\r\n",
			   vpninfo->platname);
	}
	if (vpninfo->mobile_platform_version) {
		buf_append(buf, "X-AnyConnect-Identifier-ClientVersion: %s\r\n",
			   openconnect_version_str);
		buf_append(buf, "X-AnyConnect-Identifier-Platform: %s\r\n",
			   vpninfo->platname);
		buf_append(buf, "X-AnyConnect-Identifier-PlatformVersion: %s\r\n",
			   vpninfo->mobile_platform_version);
		buf_append(buf, "X-AnyConnect-Identifier-DeviceType: %s\r\n",
			   vpninfo->mobile_device_type);
		buf_append(buf, "X-AnyConnect-Identifier-Device-UniqueID: %s\r\n",
			   vpninfo->mobile_device_uniqueid);
	}
}

static int fetch_config(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *buf;
	char *config_buf = NULL;
	int result, buflen;
	unsigned char local_sha1_bin[SHA1_SIZE];
	char local_sha1_ascii[(SHA1_SIZE * 2)+1];
	int i;

	if (!vpninfo->profile_url || !vpninfo->profile_sha1 || !vpninfo->write_new_config)
		return -ENOENT;

	if (!strncasecmp(vpninfo->xmlsha1, vpninfo->profile_sha1, SHA1_SIZE * 2)) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Not downloading XML profile because SHA1 already matches\n"));
		return 0;
	}

	if ((result = openconnect_open_https(vpninfo))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open HTTPS connection to %s\n"),
			     vpninfo->hostname);
		return result;
	}

	buf = buf_alloc();
	buf_append(buf, "GET %s HTTP/1.1\r\n", vpninfo->profile_url);
	add_common_headers(vpninfo, buf);
	if (vpninfo->xmlpost)
		buf_append(buf, "Cookie: webvpn=%s\r\n", vpninfo->cookie);
	buf_append(buf, "\r\n");

	if (buf_error(buf))
		return buf_free(buf);

	if (vpninfo->ssl_write(vpninfo, buf->data, buf->pos) != buf->pos) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to send GET request for new config\n"));
		buf_free(buf);
		return -EIO;
	}
	buf_free(buf);

	buflen = process_http_response(vpninfo, &result, 0, NULL, &config_buf);
	if (buflen < 0) {
		/* We'll already have complained about whatever offended us */
		return -EINVAL;
	}

	if (result != 200) {
		free(config_buf);
		return -EINVAL;
	}

	openconnect_sha1(local_sha1_bin, config_buf, buflen);

	for (i = 0; i < SHA1_SIZE; i++)
		sprintf(&local_sha1_ascii[i*2], "%02x", local_sha1_bin[i]);

	if (strcasecmp(vpninfo->profile_sha1, local_sha1_ascii)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Downloaded config file did not match intended SHA1\n"));
		free(config_buf);
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_DEBUG, _("Downloaded new XML profile\n"));

	result = vpninfo->write_new_config(vpninfo->cbdata, config_buf, buflen);
	free(config_buf);
	return result;
}

static int run_csd_script(struct openconnect_info *vpninfo, char *buf, int buflen)
{
#ifdef _WIN32
	vpn_progress(vpninfo, PRG_ERR,
		     _("Error: Running the 'Cisco Secure Desktop' trojan on Windows is not yet implemented.\n"));
	return -EPERM;
#else
	char fname[64];
	int fd, ret;

	if (!vpninfo->csd_wrapper && !buflen) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: Server asked us to run CSD hostscan.\n"
			       "You need to provide a suitable --csd-wrapper argument.\n"));
		return -EINVAL;
	}

	if (!vpninfo->uid_csd_given && !vpninfo->csd_wrapper) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: Server asked us to download and run a 'Cisco Secure Desktop' trojan.\n"
			       "This facility is disabled by default for security reasons, so you may wish to enable it.\n"));
		return -EPERM;
	}

#ifndef __linux__
	vpn_progress(vpninfo, PRG_INFO,
		     _("Trying to run Linux CSD trojan script.\n"));
#endif

	fname[0] = 0;
	if (buflen) {
		char *tmpdir = getenv("TMPDIR");
		snprintf(fname, 64, "%s/csdXXXXXX", tmpdir ? tmpdir : "/tmp");
		fd = mkstemp(fname);
		if (fd < 0) {
			int err = -errno;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open temporary CSD script file: %s\n"),
				     strerror(errno));
			return err;
		}

		ret = write(fd, (void *)buf, buflen);
		if (ret != buflen) {
			int err = -errno;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to write temporary CSD script file: %s\n"),
				     strerror(errno));
			return err;
		}
		fchmod(fd, 0755);
		close(fd);
	}

	if (!fork()) {
		char scertbuf[MD5_SIZE * 2 + 1];
		char ccertbuf[MD5_SIZE * 2 + 1];
		char *csd_argv[32];
		int i = 0;

		if (vpninfo->uid_csd_given && vpninfo->uid_csd != getuid()) {
			struct passwd *pw;

			if (setuid(vpninfo->uid_csd)) {
				fprintf(stderr, _("Failed to set uid %ld\n"),
					(long)vpninfo->uid_csd);
				exit(1);
			}
			if (!(pw = getpwuid(vpninfo->uid_csd))) {
				fprintf(stderr, _("Invalid user uid=%ld\n"),
					(long)vpninfo->uid_csd);
				exit(1);
			}
			setenv("HOME", pw->pw_dir, 1);
			if (chdir(pw->pw_dir)) {
				fprintf(stderr, _("Failed to change to CSD home directory '%s': %s\n"),
					pw->pw_dir, strerror(errno));
				exit(1);
			}
		}
		if (getuid() == 0 && !vpninfo->csd_wrapper) {
			fprintf(stderr, _("Warning: you are running insecure "
					  "CSD code with root privileges\n"
					  "\t Use command line option \"--csd-user\"\n"));
		}
		/* Spurious stdout output from the CSD trojan will break both
		   the NM tool and the various cookieonly modes. */
		dup2(2, 1);
		if (vpninfo->csd_wrapper)
			csd_argv[i++] = vpninfo->csd_wrapper;
		csd_argv[i++] = fname;
		csd_argv[i++] = (char *)"-ticket";
		if (asprintf(&csd_argv[i++], "\"%s\"", vpninfo->csd_ticket) == -1)
			goto out;
		csd_argv[i++] = (char *)"-stub";
		csd_argv[i++] = (char *)"\"0\"";
		csd_argv[i++] = (char *)"-group";
		if (asprintf(&csd_argv[i++], "\"%s\"", vpninfo->authgroup?:"") == -1)
			goto out;

		openconnect_local_cert_md5(vpninfo, ccertbuf);
		scertbuf[0] = 0;
		get_cert_md5_fingerprint(vpninfo, vpninfo->peer_cert, scertbuf);
		csd_argv[i++] = (char *)"-certhash";
		if (asprintf(&csd_argv[i++], "\"%s:%s\"", scertbuf, ccertbuf) == -1)
			goto out;

		csd_argv[i++] = (char *)"-url";
		if (asprintf(&csd_argv[i++], "\"https://%s%s\"", vpninfo->hostname, vpninfo->csd_starturl) == -1)
			goto out;

		csd_argv[i++] = (char *)"-langselen";
		csd_argv[i++] = NULL;

		if (setenv("CSD_TOKEN", vpninfo->csd_token, 1))
			goto out;
		if (setenv("CSD_HOSTNAME", vpninfo->hostname, 1))
			goto out;

		execv(csd_argv[0], csd_argv);

out:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to exec CSD script %s\n"), csd_argv[0]);
		exit(1);
	}

	free(vpninfo->csd_stuburl);
	vpninfo->csd_stuburl = NULL;
	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup(vpninfo->csd_waiturl +
				  (vpninfo->csd_waiturl[0] == '/' ? 1 : 0));
	free(vpninfo->csd_waiturl);
	vpninfo->csd_waiturl = NULL;
	vpninfo->csd_scriptname = strdup(fname);

	http_add_cookie(vpninfo, "sdesktop", vpninfo->csd_token);
	return 0;
#endif /* !_WIN32 */
}

int internal_parse_url(char *url, char **res_proto, char **res_host,
		       int *res_port, char **res_path, int default_port)
{
	char *proto = url;
	char *host, *path, *port_str;
	int port;

	host = strstr(url, "://");
	if (host) {
		*host = 0;
		host += 3;

		if (!strcasecmp(proto, "https"))
			port = 443;
		else if (!strcasecmp(proto, "http"))
			port = 80;
		else if (!strcasecmp(proto, "socks") ||
			 !strcasecmp(proto, "socks4") ||
			 !strcasecmp(proto, "socks5"))
			port = 1080;
		else
			return -EPROTONOSUPPORT;
	} else {
		if (default_port) {
			proto = NULL;
			port = default_port;
			host = url;
		} else
			return -EINVAL;
	}

	path = strchr(host, '/');
	if (path)
		*(path++) = 0;

	port_str = strrchr(host, ':');
	if (port_str) {
		char *end;
		int new_port = strtol(port_str + 1, &end, 10);

		if (!*end) {
			*port_str = 0;
			port = new_port;
		}
	}

	if (res_proto)
		*res_proto = proto ? strdup(proto) : NULL;
	if (res_host)
		*res_host = strdup(host);
	if (res_port)
		*res_port = port;
	if (res_path)
		*res_path = (path && *path) ? strdup(path) : NULL;

	/* Undo the damage we did to the original string */
	if (port_str)
		*(port_str) = ':';
	if (path)
		*(path - 1) = '/';
	if (proto)
		*(host - 3) = ':';
	return 0;
}

static void clear_cookies(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *opt, *next;

	for (opt = vpninfo->cookies; opt; opt = next) {
		next = opt->next;

		free(opt->option);
		free(opt->value);
		free(opt);
	}
	vpninfo->cookies = NULL;
}

/* Return value:
 *  < 0, on error
 *  = 0, on success (go ahead and retry with the latest vpninfo->{hostname,urlpath,port,...})
 */
static int handle_redirect(struct openconnect_info *vpninfo)
{
	vpninfo->redirect_type = REDIR_TYPE_LOCAL;

	if (!strncmp(vpninfo->redirect_url, "https://", 8)) {
		/* New host. Tear down the existing connection and make a new one */
		char *host;
		int port;
		int ret;

		free(vpninfo->urlpath);
		vpninfo->urlpath = NULL;

		ret = internal_parse_url(vpninfo->redirect_url, NULL, &host, &port, &vpninfo->urlpath, 0);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse redirected URL '%s': %s\n"),
				     vpninfo->redirect_url, strerror(-ret));
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
			return ret;
		}

		if (strcasecmp(vpninfo->hostname, host) || port != vpninfo->port) {
			openconnect_set_hostname(vpninfo, host);
			vpninfo->port = port;

			/* Kill the existing connection, and a new one will happen */
			openconnect_close_https(vpninfo, 0);
			clear_cookies(vpninfo);
			vpninfo->redirect_type = REDIR_TYPE_NEWHOST;
		} else
			free(host);

		free(vpninfo->redirect_url);
		vpninfo->redirect_url = NULL;

		return 0;
	} else if (strstr(vpninfo->redirect_url, "://")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Cannot follow redirection to non-https URL '%s'\n"),
			     vpninfo->redirect_url);
		free(vpninfo->redirect_url);
		vpninfo->redirect_url = NULL;
		return -EINVAL;
	} else if (vpninfo->redirect_url[0] == '/') {
		/* Absolute redirect within same host */
		free(vpninfo->urlpath);
		vpninfo->urlpath = strdup(vpninfo->redirect_url + 1);
		free(vpninfo->redirect_url);
		vpninfo->redirect_url = NULL;
		return 0;
	} else {
		char *lastslash = NULL;
		if (vpninfo->urlpath)
			lastslash = strrchr(vpninfo->urlpath, '/');
		if (!lastslash) {
			free(vpninfo->urlpath);
			vpninfo->urlpath = vpninfo->redirect_url;
			vpninfo->redirect_url = NULL;
		} else {
			char *oldurl = vpninfo->urlpath;
			*lastslash = 0;
			vpninfo->urlpath = NULL;
			if (asprintf(&vpninfo->urlpath, "%s/%s",
				     oldurl, vpninfo->redirect_url) == -1) {
				int err = -errno;
				vpn_progress(vpninfo, PRG_ERR,
					     _("Allocating new path for relative redirect failed: %s\n"),
					     strerror(-err));
				return err;
			}
			free(oldurl);
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
		}
		return 0;
	}
}

static void dump_buf(struct openconnect_info *vpninfo, char prefix, char *buf)
{
	while (*buf) {
		char *eol = buf;
		char eol_char = 0;

		while (*eol) {
			if (*eol == '\r' || *eol == '\n') {
				eol_char = *eol;
				*eol = 0;
				break;
			}
			eol++;
		}

		vpn_progress(vpninfo, PRG_DEBUG, "%c %s\n", prefix, buf);
		if (!eol_char)
			break;

		*eol = eol_char;
		buf = eol + 1;
		if (eol_char == '\r' && *buf == '\n')
			buf++;
	}
}

/* Inputs:
 *  method:             GET or POST
 *  vpninfo->hostname:  Host DNS name
 *  vpninfo->port:      TCP port, typically 443
 *  vpninfo->urlpath:   Relative path, e.g. /+webvpn+/foo.html
 *  request_body_type:  Content type for a POST (e.g. text/html).  Can be NULL.
 *  request_body:       POST content
 *  form_buf:           Callee-allocated buffer for server content
 *
 * Return value:
 *  < 0, on error
 *  >=0, on success, indicating the length of the data in *form_buf
 */
static int do_https_request(struct openconnect_info *vpninfo, const char *method,
			    const char *request_body_type, struct oc_text_buf *request_body,
			    char **form_buf, int fetch_redirect)
{
	struct oc_text_buf *buf;
	int result, buflen;
	int rq_retry;
	int rlen, pad;

	if (buf_error(request_body))
		return buf_error(request_body);

 redirected:
	vpninfo->redirect_type = REDIR_TYPE_NONE;

	if (*form_buf) {
		free(*form_buf);
		*form_buf = NULL;
	}

	/*
	 * It would be nice to use cURL for this, but we really need to guarantee
	 * that we'll be using OpenSSL (for the TPM stuff), and it doesn't seem
	 * to have any way to let us provide our own socket read/write functions.
	 * We can only provide a socket _open_ function. Which would require having
	 * a socketpair() and servicing the "other" end of it.
	 *
	 * So we process the HTTP for ourselves...
	 */
	buf = buf_alloc();
	buf_append(buf, "%s /%s HTTP/1.1\r\n", method, vpninfo->urlpath ?: "");
	add_common_headers(vpninfo, buf);

	if (request_body_type) {
		rlen = request_body->pos;

		/* force body length to be a multiple of 64, to avoid leaking
		 * password length. */
		pad = 64*(1+rlen/64) - rlen;
		buf_append(buf, "X-Pad: %0*d\r\n", pad, 0);

		buf_append(buf, "Content-Type: %s\r\n", request_body_type);
		buf_append(buf, "Content-Length: %d\r\n", (int)rlen);
	}
	buf_append(buf, "\r\n");

	if (request_body_type)
		buf_append_bytes(buf, request_body->data, request_body->pos);

	if (vpninfo->port == 443)
		vpn_progress(vpninfo, PRG_INFO, "%s https://%s/%s\n",
			     method, vpninfo->hostname,
			     vpninfo->urlpath ?: "");
	else
		vpn_progress(vpninfo, PRG_INFO, "%s https://%s:%d/%s\n",
			     method, vpninfo->hostname, vpninfo->port,
			     vpninfo->urlpath ?: "");

	if (buf_error(buf))
		return buf_free(buf);

 retry:
	if (openconnect_https_connected(vpninfo)) {
		/* The session is already connected. If we get a failure on
		* *sending* the request, try it again immediately with a new
		* connection. */
		rq_retry = 1;
	} else {
		rq_retry = 0;
		if ((result = openconnect_open_https(vpninfo))) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open HTTPS connection to %s\n"),
				     vpninfo->hostname);
			buf_free(buf);
			/* We really don't want to return -EINVAL if we have
			   failed to even connect to the server, because if
			   we do that openconnect_obtain_cookie() might try
			   again without XMLPOST... with the same result. */
			return -EIO;
		}
	}

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', buf->data);

	result = vpninfo->ssl_write(vpninfo, buf->data, buf->pos);
	if (rq_retry && result < 0) {
		openconnect_close_https(vpninfo, 0);
		goto retry;
	}
	buf_free(buf);
	if (result < 0)
		return result;

	buflen = process_http_response(vpninfo, &result, 0, NULL, form_buf);
	if (buflen < 0) {
		/* We'll already have complained about whatever offended us */
		return buflen;
	}
	if (vpninfo->dump_http_traffic && *form_buf)
		dump_buf(vpninfo, '<', *form_buf);

	if (result != 200 && vpninfo->redirect_url) {
		result = handle_redirect(vpninfo);
		if (result == 0) {
			if (!fetch_redirect)
				return 0;
			goto redirected;
		}
		goto out;
	}
	if (!*form_buf || result != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     result);
		result = -EINVAL;
		goto out;
	}

	return buflen;

 out:
	free(*form_buf);
	*form_buf = NULL;
	return result;
}

/* Return value:
 *  < 0, if the data is unrecognized
 *  = 0, if the page contains an XML document
 *  = 1, if the page is a wait/refresh HTML page
 */
static int check_response_type(struct openconnect_info *vpninfo, char *form_buf)
{
	if (strncmp(form_buf, "<?xml", 5)) {
		/* Not XML? Perhaps it's HTML with a refresh... */
		if (strcasestr(form_buf, "http-equiv=\"refresh\""))
			return 1;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown response from server\n"));
		return -EINVAL;
	}
	return 0;
}

/* Return value:
 *  < 0, on error
 *  > 0, no cookie (user cancel)
 *  = 0, obtained cookie
 */
int openconnect_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *opt;
	char *form_buf = NULL;
	struct oc_auth_form *form = NULL;
	int result, buflen, tries;
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *orig_host = NULL, *orig_path = NULL, *form_path = NULL;
	int orig_port = 0;
	int cert_rq, cert_sent = !vpninfo->cert;

	/* Step 1: Unlock software token (if applicable) */
	if (vpninfo->token_mode == OC_TOKEN_MODE_STOKEN) {
		result = prepare_stoken(vpninfo);
		if (result)
			return result;
	}

	if (!vpninfo->xmlpost)
		goto no_xmlpost;

	/*
	 * Step 2: Probe for XML POST compatibility
	 *
	 * This can get stuck in a redirect loop, so give up after any of:
	 *
	 * a) HTTP error (e.g. 400 Bad Request)
	 * b) Same-host redirect (e.g. Location: /foo/bar)
	 * c) Three redirects without seeing a plausible login form
	 */
newgroup:
	result = xmlpost_initial_req(vpninfo, request_body, 0);
	if (result < 0)
		goto out;

	orig_host = strdup(vpninfo->hostname);
	orig_path = vpninfo->urlpath ? strdup(vpninfo->urlpath) : NULL;
	orig_port = vpninfo->port;

	for (tries = 0; ; tries++) {
		if (tries == 3) {
		fail:
			if (vpninfo->xmlpost) {
			no_xmlpost:
				/* Try without XML POST this time... */
				tries = 0;
				vpninfo->xmlpost = 0;
				request_body_type = NULL;
				buf_truncate(request_body);
				method = "GET";
				if (orig_host) {
					openconnect_set_hostname(vpninfo, orig_host);
					orig_host = NULL;
					free(vpninfo->urlpath);
					vpninfo->urlpath = orig_path;
					orig_path = NULL;
					vpninfo->port = orig_port;
				}
				openconnect_close_https(vpninfo, 0);
			} else {
				result = -EIO;
				goto out;
			}
		}

		result = do_https_request(vpninfo, method, request_body_type, request_body,
					  &form_buf, 0);
		if (vpninfo->got_cancel_cmd) {
			result = 1;
			goto out;
		}
		if (result == -EINVAL)
			goto fail;
		if (result < 0)
			goto out;

		/* Some ASAs forget to send the TLS cert request on the initial connection.
		 * If we have a client cert, disable HTTP keepalive until we get a real
		 * login form (not a redirect). */
		if (!cert_sent)
			openconnect_close_https(vpninfo, 0);

		/* XML POST does not allow local redirects, but GET does. */
		if (vpninfo->xmlpost &&
		    vpninfo->redirect_type == REDIR_TYPE_LOCAL)
			goto fail;
		else if (vpninfo->redirect_type != REDIR_TYPE_NONE)
			continue;

		result = parse_xml_response(vpninfo, form_buf, &form, &cert_rq);
		if (result < 0)
			goto fail;

		if (cert_rq) {
			int cert_failed = 0;

			free_auth_form(form);
			form = NULL;

			if (!cert_sent && vpninfo->cert) {
				/* Try again on a fresh connection. */
				cert_sent = 1;
			} else if (cert_sent && vpninfo->cert) {
				/* Try again with <client-cert-fail/> in the request */
				vpn_progress(vpninfo, PRG_ERR,
					     _("Server requested SSL client certificate after one was provided\n"));
				cert_failed = 1;
			} else {
				vpn_progress(vpninfo, PRG_INFO,
					     _("Server requested SSL client certificate; none was configured\n"));
				cert_failed = 1;
			}
			result = xmlpost_initial_req(vpninfo, request_body, cert_failed);
			if (result < 0)
				goto fail;
			continue;
		}
		if (form && form->action) {
			vpninfo->redirect_url = strdup(form->action);
			handle_redirect(vpninfo);
		}
		break;
	}
	if (vpninfo->xmlpost)
		vpn_progress(vpninfo, PRG_INFO, _("XML POST enabled\n"));

	/* Step 4: Run the CSD trojan, if applicable */
	if (vpninfo->csd_starturl && vpninfo->csd_waiturl) {
		buflen = 0;

		if (vpninfo->urlpath) {
			form_path = strdup(vpninfo->urlpath);
			if (!form_path) {
				result = -ENOMEM;
				goto out;
			}
		}

		/* fetch the CSD program, if available */
		if (vpninfo->csd_stuburl) {
			vpninfo->redirect_url = vpninfo->csd_stuburl;
			vpninfo->csd_stuburl = NULL;
			handle_redirect(vpninfo);

			buflen = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, 0);
			if (buflen <= 0) {
				result = -EINVAL;
				goto out;
			}
		}

		/* This is the CSD stub script, which we now need to run */
		result = run_csd_script(vpninfo, form_buf, buflen);
		if (result)
			goto out;

		/* vpninfo->urlpath now points to the wait page */
		while (1) {
			result = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, 0);
			if (result <= 0)
				break;

			result = check_response_type(vpninfo, form_buf);
			if (result <= 0)
				break;

			vpn_progress(vpninfo, PRG_INFO,
				     _("Refreshing %s after 1 second...\n"),
				     vpninfo->urlpath);
			sleep(1);
		}
		if (result < 0)
			goto out;

		/* refresh the form page, to see if we're authorized now */
		free(vpninfo->urlpath);
		vpninfo->urlpath = form_path;
		form_path = NULL;

		result = do_https_request(vpninfo,
					  vpninfo->xmlpost ? "POST" : "GET",
					  request_body_type, request_body, &form_buf, 1);
		if (result < 0)
			goto out;

		result = parse_xml_response(vpninfo, form_buf, &form, NULL);
		if (result < 0)
			goto out;
	}

	/* Step 5: Ask the user to fill in the auth form; repeat as necessary */
	while (1) {
		buf_truncate(request_body);
		result = handle_auth_form(vpninfo, form, request_body,
					  &method, &request_body_type);
		if (result < 0 || result == OC_FORM_RESULT_CANCELLED)
			goto out;
		if (result == OC_FORM_RESULT_LOGGEDIN)
			break;
		if (result == OC_FORM_RESULT_NEWGROUP) {
			free(form_buf);
			form_buf = NULL;
			free_auth_form(form);
			form = NULL;
			goto newgroup;
		}

		result = do_https_request(vpninfo, method, request_body_type, request_body,
					  &form_buf, 1);
		if (result < 0)
			goto out;

		result = parse_xml_response(vpninfo, form_buf, &form, NULL);
		if (result < 0)
			goto out;
		if (form->action) {
			vpninfo->redirect_url = strdup(form->action);
			handle_redirect(vpninfo);
		}
	}

	/* A return value of 2 means the XML form indicated
	   success. We _should_ have a cookie... */

	for (opt = vpninfo->cookies; opt; opt = opt->next) {

		if (!strcmp(opt->option, "webvpn")) {
			free(vpninfo->cookie);
			vpninfo->cookie = strdup(opt->value);
		} else if (vpninfo->write_new_config && !strcmp(opt->option, "webvpnc")) {
			char *tok = opt->value;
			char *bu = NULL, *fu = NULL, *sha = NULL;

			do {
				if (tok != opt->value)
					*(tok++) = 0;

				if (!strncmp(tok, "bu:", 3))
					bu = tok + 3;
				else if (!strncmp(tok, "fu:", 3))
					fu = tok + 3;
				else if (!strncmp(tok, "fh:", 3))
					sha = tok + 3;
			} while ((tok = strchr(tok, '&')));

			if (bu && fu && sha) {
				if (asprintf(&vpninfo->profile_url, "%s%s", bu, fu) == -1) {
					result = -ENOMEM;
					goto out;
				}
				vpninfo->profile_sha1 = strdup(sha);
			}
		}
	}
	result = 0;

	fetch_config(vpninfo);

out:
	buf_free(request_body);

	free (orig_host);
	free (orig_path);

	free(form_path);
	free(form_buf);
	free_auth_form(form);

	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
		vpninfo->csd_scriptname = NULL;
	}

	return result;
}

char *openconnect_create_useragent(const char *base)
{
	char *uagent;

	if (asprintf(&uagent, "%s %s", base, openconnect_version_str) < 0)
		return NULL;

	return uagent;
}

static int proxy_gets(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while ((ret = proxy_read(vpninfo, (void *)(buf + i), 1)) == 1) {
		if (buf[i] == '\n') {
			buf[i] = 0;
			if (i && buf[i-1] == '\r') {
				buf[i-1] = 0;
				i--;
			}
			return i;
		}
		i++;

		if (i >= len - 1) {
			buf[i] = 0;
			return i;
		}
	}
	buf[i] = 0;
	return i ?: ret;
}

static int proxy_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	size_t count;
	int fd = vpninfo->proxy_fd;

	if (fd == -1)
		return -EINVAL;

	for (count = 0; count < len; ) {
		fd_set rd_set, wr_set;
		int maxfd = fd;
		int i;

		FD_ZERO(&wr_set);
		FD_ZERO(&rd_set);
		FD_SET(fd, &wr_set);
		cmd_fd_set(vpninfo, &rd_set, &maxfd);

		select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
		if (is_cancel_pending(vpninfo, &rd_set))
			return -EINTR;

		/* Not that this should ever be able to happen... */
		if (!FD_ISSET(fd, &wr_set))
			continue;

		i = send(fd, (void *)&buf[count], len - count, 0);
		if (i < 0)
			return -errno;

		count += i;
	}
	return count;
}

static int proxy_read(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	size_t count;
	int fd = vpninfo->proxy_fd;

	if (fd == -1)
		return -EINVAL;

	for (count = 0; count < len; ) {
		fd_set rd_set;
		int maxfd = fd;
		int i;

		FD_ZERO(&rd_set);
		FD_SET(fd, &rd_set);
		cmd_fd_set(vpninfo, &rd_set, &maxfd);

		select(maxfd + 1, &rd_set, NULL, NULL, NULL);
		if (is_cancel_pending(vpninfo, &rd_set))
			return -EINTR;

		/* Not that this should ever be able to happen... */
		if (!FD_ISSET(fd, &rd_set))
			continue;

		i = recv(fd, (void *)&buf[count], len - count, 0);
		if (i < 0)
			return -errno;
		else if (i == 0)
			return -ECONNRESET;

		count += i;
	}
	return count;
}

static const char *socks_errors[] = {
	N_("request granted"),
	N_("general failure"),
	N_("connection not allowed by ruleset"),
	N_("network unreachable"),
	N_("host unreachable"),
	N_("connection refused by destination host"),
	N_("TTL expired"),
	N_("command not supported / protocol error"),
	N_("address type not supported")
};

static int socks_password_auth(struct openconnect_info *vpninfo)
{
	int ul, pl, i;
	char buf[1024];

	if (!vpninfo->proxy_user || !vpninfo->proxy_pass) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("SOCKS server requested username/password but we have none\n"));
		return -EIO;
	}
	ul = strlen(vpninfo->proxy_user);
	pl = strlen(vpninfo->proxy_pass);

	if (ul > 255 || pl > 255) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Username and password for SOCKS authentication must be < 255 bytes\n"));
		return -EINVAL;
	}

	buf[0] = 1;
	buf[1] = ul;
	memcpy(buf + 2, vpninfo->proxy_user, ul);
	buf[2 + ul] = pl;
	memcpy(buf + 3 + ul, vpninfo->proxy_pass, pl);

	i = proxy_write(vpninfo, buf, 3 + ul + pl);
	/* Don't leave passwords lying around if we can easily avoid it... */
	memset(buf, 0, sizeof(buf));
	if (i < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error writing auth request to SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}


	if ((i = proxy_read(vpninfo, buf, 2)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading auth response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}

	if (buf[0] != 1) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected auth response from SOCKS proxy: %02x %02x\n"),
			     buf[0], buf[1]);
		return -EIO;
	}
	if (buf[1] == 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Authenticated to SOCKS server using password\n"));
		return 0;
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Password authentication to SOCKS server failed\n"));
		return -EIO;
	}
}

#define SOCKS_AUTH_NONE			0	/* RFC1928 */
#define SOCKS_AUTH_GSSAPI		1	/* RFC1961 */
#define SOCKS_AUTH_PASSWORD		2	/* RFC1929 */
#define SOCKS_AUTH_NO_ACCEPTABLE	0xff	/* RFC1928 */

static int process_socks_proxy(struct openconnect_info *vpninfo)
{
	char buf[1024];
	int i, nr_auth_methods = 0;

	buf[0] = 5; /* SOCKS version */

	buf[2 + nr_auth_methods++] = SOCKS_AUTH_NONE;
#if defined(HAVE_GSSAPI) || defined(_WIN32)
	if (vpninfo->auth[AUTH_TYPE_GSSAPI].state != AUTH_DISABLED &&
	    !vpninfo->proxy_user && !vpninfo->proxy_pass)
		buf[2 + nr_auth_methods++] = SOCKS_AUTH_GSSAPI;
#endif
	if (vpninfo->auth[AUTH_TYPE_BASIC].state != AUTH_DISABLED &&
	    vpninfo->proxy_user && vpninfo->proxy_pass)
		buf[2 + nr_auth_methods++] = SOCKS_AUTH_PASSWORD;

	buf[1] = nr_auth_methods;

	if ((i = proxy_write(vpninfo, buf, 2 + nr_auth_methods)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error writing auth request to SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}

	if ((i = proxy_read(vpninfo, buf, 2)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading auth response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	if (buf[0] != 5) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected auth response from SOCKS proxy: %02x %02x\n"),
			     buf[0], buf[1]);
		return -EIO;
	}
	switch ((unsigned char)buf[1]) {
	case SOCKS_AUTH_NONE:
		/* No authentication */
		break;

	case SOCKS_AUTH_GSSAPI:
#if defined(HAVE_GSSAPI) || defined(_WIN32)
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("SOCKS server requested GSSAPI authentication\n"));
		if (socks_gssapi_auth(vpninfo))
			return -EIO;
		break;
#else
		/* This should never happen since we didn't ask for it! */
		vpn_progress(vpninfo, PRG_ERR,
			     _("SOCKS server requested GSSAPI authentication\n"));
		return -EIO;
#endif

	case SOCKS_AUTH_PASSWORD:
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("SOCKS server requested password authentication\n"));
		if (socks_password_auth(vpninfo))
			return -EIO;
		break;

	case SOCKS_AUTH_NO_ACCEPTABLE:
		vpn_progress(vpninfo, PRG_ERR,
			     _("SOCKS server requires authentication\n"));
		vpn_progress(vpninfo, PRG_INFO,
			     _("This version of OpenConnect was built without GSSAPI support\n"));
		return -EIO;

	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("SOCKS server requested unknown authentication type %02x\n"),
			     (unsigned char)buf[1]);
		return -EIO;
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Requesting SOCKS proxy connection to %s:%d\n"),
		     vpninfo->hostname, vpninfo->port);

	buf[0] = 5; /* SOCKS version */
	buf[1] = 1; /* CONNECT */
	buf[2] = 0; /* Reserved */
	buf[3] = 3; /* Address type is domain name */
	buf[4] = strlen(vpninfo->hostname);
	strcpy((char *)buf + 5, vpninfo->hostname);
	i = strlen(vpninfo->hostname) + 5;
	buf[i++] = vpninfo->port >> 8;
	buf[i++] = vpninfo->port & 0xff;

	if ((i = proxy_write(vpninfo, buf, i)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error writing connect request to SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	/* Read 5 bytes -- up to and including the first byte of the returned
	   address (which might be the length byte of a domain name) */
	if ((i = proxy_read(vpninfo, buf, 5)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading connect response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	if (i != 5 || buf[0] != 5) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected connect response from SOCKS proxy: %02x %02x...\n"),
			     buf[0], buf[1]);
		return -EIO;
	}
	if (buf[1]) {
		unsigned char err = buf[1];
		if (err < sizeof(socks_errors) / sizeof(socks_errors[0]))
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy error %02x: %s\n"),
				     err, _(socks_errors[err]));
		else
			vpn_progress(vpninfo, PRG_ERR,
				     _("SOCKS proxy error %02x\n"), err);
		return -EIO;
	}

	/* Connect responses contain an address */
	switch (buf[3]) {
	case 1: /* Legacy IP */
		i = 5;
		break;
	case 3: /* Domain name */
		i = buf[4] + 2;
		break;
	case 4: /* IPv6 */
		i = 17;
		break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected address type %02x in SOCKS connect response\n"),
			     buf[3]);
		return -EIO;
	}

	if ((i = proxy_read(vpninfo, buf, i)) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error reading connect response from SOCKS proxy: %s\n"),
			     strerror(-i));
		return i;
	}
	return 0;
}

/* Ick. Yet another wheel to reinvent. But although we could pull it
   in from OpenSSL, we can't from GnuTLS */

static inline int b64_char(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

void *openconnect_base64_decode(int *ret_len, const char *in)
{
	unsigned char *buf;
	int b[4];
	int len = strlen(in);

	if (len & 3) {
		*ret_len = -EINVAL;
		return NULL;
	}
	len = (len * 3) / 4;
	buf = malloc(len);
	if (!buf) {
		*ret_len = -ENOMEM;
		return NULL;
	}

	len = 0;
	while (*in) {
		if (!in[1] || !in[2] || !in[3])
			goto err;
	        b[0] = b64_char(in[0]);
		b[1] = b64_char(in[1]);
		if (b[0] < 0 || b[1] < 0)
			goto err;
		buf[len++] = (b[0] << 2) | (b[1] >> 4);

		if (in[2] == '=') {
			if (in[3] != '=' || in[4] != 0)
				goto err;
			break;
		}
		b[2] = b64_char(in[2]);
		if (b[2] < 0)
			goto err;
		buf[len++] = (b[1] << 4) | (b[2] >> 2);
		if (in[3] == '=') {
			if (in[4] != 0)
				goto err;
			break;
		}
		b[3] = b64_char(in[3]);
		if (b[3] < 0)
			goto err;
		buf[len++] = (b[2] << 6) | b[3];
		in += 4;
	}
	*ret_len = len;
	return buf;

 err:
	free(buf);
	*ret_len = EINVAL;
	return NULL;
}

static const char b64_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

void buf_append_base64(struct oc_text_buf *buf, const void *bytes, int len)
{
	const unsigned char *in = bytes;
	int hibits;

	if (!buf || buf->error)
		return;

	if (buf_ensure_space(buf, (4 * (len + 2) / 3) + 1))
		return;

	while (len > 0) {
		buf->data[buf->pos++] = b64_table[in[0] >> 2];
		hibits = (in[0] << 4) & 0x30;
		if (len == 1) {
			buf->data[buf->pos++] = b64_table[hibits];
			buf->data[buf->pos++] = '=';
			buf->data[buf->pos++] = '=';
			break;
		}
		buf->data[buf->pos++] = b64_table[hibits | (in[1] >> 4)];
		hibits = (in[1] << 2) & 0x3c;
		if (len == 2) {
			buf->data[buf->pos++] = b64_table[hibits];
			buf->data[buf->pos++] = '=';
			break;
		}
		buf->data[buf->pos++] = b64_table[hibits | (in[2] >> 6)];
		buf->data[buf->pos++] = b64_table[in[2] & 0x3f];
		in += 3;
		len -= 3;
	}
	buf->data[buf->pos] = 0;
}

static int basic_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *hdrbuf)
{
	struct oc_text_buf *text;

	if (!vpninfo->proxy_user || !vpninfo->proxy_pass)
		return -EINVAL;

	if (!vpninfo->authmethods_set) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Proxy requested Basic authentication which is disabled by default\n"));
		vpninfo->auth[AUTH_TYPE_BASIC].state = AUTH_FAILED;
		return -EINVAL;
	}

	if (vpninfo->auth[AUTH_TYPE_BASIC].state == AUTH_IN_PROGRESS) {
		vpninfo->auth[AUTH_TYPE_BASIC].state = AUTH_FAILED;
		return -EAGAIN;
	}

	text = buf_alloc();
	buf_append(text, "%s:%s", vpninfo->proxy_user, vpninfo->proxy_pass);
	if (buf_error(text))
		return buf_free(text);

	buf_append(hdrbuf, "Proxy-Authorization: Basic ");
	buf_append_base64(hdrbuf, text->data, text->pos);
	buf_append(hdrbuf, "\r\n");

	memset(text->data, 0, text->pos);
	buf_free(text);

	vpn_progress(vpninfo, PRG_INFO, _("Attempting HTTP Basic authentication to proxy\n"));
	vpninfo->auth[AUTH_TYPE_BASIC].state = AUTH_IN_PROGRESS;
	return 0;
}

#if !defined(HAVE_GSSAPI) && !defined(_WIN32)
static int no_gssapi_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *hdrbuf)
{
	/* This comes last so just complain. We're about to bail. */
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without GSSAPI support\n"));
	vpninfo->auth[AUTH_TYPE_GSSAPI].state = AUTH_FAILED;
	return -ENOENT;
}
#endif

struct auth_method {
	int state_index;
	const char *name;
	int (*authorization)(struct openconnect_info *, struct oc_text_buf *);
	void (*cleanup)(struct openconnect_info *);
} auth_methods[] = {
#if defined(HAVE_GSSAPI) || defined(_WIN32)
	{ AUTH_TYPE_GSSAPI, "Negotiate", gssapi_authorization, cleanup_gssapi_auth },
#endif
	{ AUTH_TYPE_NTLM, "NTLM", ntlm_authorization, cleanup_ntlm_auth },
	{ AUTH_TYPE_DIGEST, "Digest", digest_authorization, NULL },
	{ AUTH_TYPE_BASIC, "Basic", basic_authorization, NULL },
#if !defined(HAVE_GSSAPI) && !defined(_WIN32)
	{ AUTH_TYPE_GSSAPI, "Negotiate", no_gssapi_authorization, NULL }
#endif
};

/* Generate Proxy-Authorization: header for request if appropriate */
static int proxy_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	int ret;
	int i;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++) {
		int index = auth_methods[i].state_index;
		if (vpninfo->auth[index].state > AUTH_UNSEEN) {
			ret = auth_methods[i].authorization(vpninfo, buf);
			if (ret == -EAGAIN || !ret)
				return ret;
		}
	}
	vpn_progress(vpninfo, PRG_INFO, _("No more authentication methods to try\n"));
	return -ENOENT;
}

/* Returns non-zero if it matched */
static int handle_auth_proto(struct openconnect_info *vpninfo,
			      struct auth_method *method, char *hdr)
{
	struct proxy_auth_state *auth = &vpninfo->auth[method->state_index];
	int l = strlen(method->name);

	if (auth->state <= AUTH_FAILED)
		return 0;

	if (strncmp(method->name, hdr, l))
		return 0;
	if (hdr[l] != ' ' && hdr[l] != 0)
		return 0;

	if (auth->state == AUTH_UNSEEN)
		auth->state = AUTH_AVAILABLE;

	free(auth->challenge);
	if (hdr[l])
		auth->challenge = strdup(hdr + l + 1);
	else
		auth->challenge = NULL;

	return 1;
}

static int proxy_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val)
{
	int i;

	if (!strcasecmp(hdr, "Proxy-Connection")) {
		if (!strcasecmp(val, "close"))
			vpninfo->proxy_close_during_auth = 1;
		return 0;
	}

	if (strcasecmp(hdr, "Proxy-Authenticate"))
		return 0;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++) {
		/* Return once we've found a match */
		if (handle_auth_proto(vpninfo, &auth_methods[i], val))
			return 0;
	}

	return 0;
}

static void clear_auth_state(struct openconnect_info *vpninfo,
			     struct auth_method *method, int reset)
{
	struct proxy_auth_state *auth = &vpninfo->auth[method->state_index];

	/* The 'reset' argument is set when we're connected successfully,
	   to fully reset the state to allow another connection to start
	   again. Otherwise, we need to remember which auth methods have
	   been tried and should not be attempted again. */
	if (reset && method->cleanup)
		method->cleanup(vpninfo);

	free(auth->challenge);
	auth->challenge = NULL;
	/* If it *failed* don't try it again even next time */
	if (auth->state <= AUTH_FAILED)
		return;
	if (reset || auth->state == AUTH_AVAILABLE)
		auth->state = AUTH_UNSEEN;
}


static int process_http_proxy(struct openconnect_info *vpninfo)
{
	char *resp = NULL;
	int resplen;
	struct oc_text_buf *reqbuf;
	int result;
	int auth = vpninfo->proxy_close_during_auth;

	vpninfo->proxy_close_during_auth = 0;

	vpn_progress(vpninfo, PRG_INFO,
		     _("Requesting HTTP proxy connection to %s:%d\n"),
		     vpninfo->hostname, vpninfo->port);

 retry:
	reqbuf = buf_alloc();
	buf_append(reqbuf, "CONNECT %s:%d HTTP/1.1\r\n", vpninfo->hostname, vpninfo->port);
	buf_append(reqbuf, "Host: %s\r\n", vpninfo->hostname);
	buf_append(reqbuf, "User-Agent: %s\r\n", vpninfo->useragent);
	buf_append(reqbuf, "Proxy-Connection: keep-alive\r\n");
	buf_append(reqbuf, "Connection: keep-alive\r\n");
	buf_append(reqbuf, "Accept-Encoding: identity\r\n");
	if (auth) {
		int i;

		result = proxy_authorization(vpninfo, reqbuf);
		if (result) {
			buf_free(reqbuf);
			return result;
		}
		/* Forget existing challenges */
		for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++)
			clear_auth_state(vpninfo, &auth_methods[i], 0);
	}
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf))
		return buf_free(reqbuf);

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	result = proxy_write(vpninfo, reqbuf->data, reqbuf->pos);
	buf_free(reqbuf);

	if (result < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Sending proxy request failed: %s\n"),
			     strerror(-result));
		return result;
	}

	resplen = process_http_response(vpninfo, &result, 1, proxy_hdrs, &resp);
	if (resplen < 0)
		return -EINVAL;

	if (resp) {
		free(resp);
		resp = NULL;
	}

	if (result == 407) {
		/* If the proxy asked us to close the connection, do so */
		if (vpninfo->proxy_close_during_auth)
			return -EAGAIN;

		auth = 1;
		goto retry;
	}

	if (result == 200)
		return 0;

	vpn_progress(vpninfo, PRG_ERR,
		     _("Proxy CONNECT request failed: %d\n"), result);
	return -EIO;
}

void cleanup_proxy_auth(struct openconnect_info *vpninfo)
{
	int i;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++)
		clear_auth_state(vpninfo, &auth_methods[i], 1);
}

int process_proxy(struct openconnect_info *vpninfo, int ssl_sock)
{
	int ret;

	vpninfo->proxy_fd = ssl_sock;
	vpninfo->ssl_read = proxy_read;
	vpninfo->ssl_write = proxy_write;
	vpninfo->ssl_gets = proxy_gets;

	if (!vpninfo->proxy_type || !strcmp(vpninfo->proxy_type, "http"))
		ret = process_http_proxy(vpninfo);
	else if (!strcmp(vpninfo->proxy_type, "socks") ||
		 !strcmp(vpninfo->proxy_type, "socks5"))
		ret = process_socks_proxy(vpninfo);
	else {
		vpn_progress(vpninfo, PRG_ERR, _("Unknown proxy type '%s'\n"),
			     vpninfo->proxy_type);
		ret = -EIO;
	}

	vpninfo->proxy_fd = -1;
	if (!vpninfo->proxy_close_during_auth)
		cleanup_proxy_auth(vpninfo);

	return ret;
}

int openconnect_set_proxy_auth(struct openconnect_info *vpninfo, char *methods)
{
	int i;
	char *p, *start = methods;

	for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++)
		vpninfo->auth[auth_methods[i].state_index].state = AUTH_DISABLED;

	while (methods) {
		p = strchr(methods, ',');
		if (p)
			*(p++) = 0;

		for (i = 0; i < sizeof(auth_methods) / sizeof(auth_methods[0]); i++) {
			if (!strcasecmp(methods, auth_methods[i].name) ||
			    (auth_methods[i].state_index == AUTH_TYPE_GSSAPI &&
			     !strcasecmp(methods, "gssapi"))) {
				vpninfo->auth[auth_methods[i].state_index].state = AUTH_UNSEEN;
				break;
			}
		}
		methods = p;
	}
	vpninfo->authmethods_set = 1;
	free(start);
	return 0;
}

int openconnect_set_http_proxy(struct openconnect_info *vpninfo, char *proxy)
{
	char *url = proxy, *p;
	int ret;

	if (!url)
		return -ENOMEM;

	free(vpninfo->proxy_type);
	vpninfo->proxy_type = NULL;
	free(vpninfo->proxy);
	vpninfo->proxy = NULL;

	ret = internal_parse_url(url, &vpninfo->proxy_type, &vpninfo->proxy,
				 &vpninfo->proxy_port, NULL, 80);
	if (ret)
		goto out;

	p = strchr(vpninfo->proxy, '@');
	if (p) {
		/* Proxy username/password */
		*p = 0;
		vpninfo->proxy_user = vpninfo->proxy;
		vpninfo->proxy = strdup(p + 1);
		p = strchr(vpninfo->proxy_user, ':');
		if (p) {
			*p = 0;
			vpninfo->proxy_pass = strdup(p + 1);
		}
	}

	if (vpninfo->proxy_type &&
	    strcmp(vpninfo->proxy_type, "http") &&
	    strcmp(vpninfo->proxy_type, "socks") &&
	    strcmp(vpninfo->proxy_type, "socks5")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Only http or socks(5) proxies supported\n"));
		free(vpninfo->proxy_type);
		vpninfo->proxy_type = NULL;
		free(vpninfo->proxy);
		vpninfo->proxy = NULL;
		return -EINVAL;
	}
 out:
	free(url);
	return ret;
}
