/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008 Intel Corporation.
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

#define _GNU_SOURCE
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "openconnect.h"

#define MAX_BUF_LEN 131072
/*
 * We didn't really want to have to do this for ourselves -- one might have
 * thought that it would be available in a library somewhere. But neither
 * cURL nor Neon have reliable cross-platform ways of either using a cert
 * from the TPM, or just reading from / writing to a transport which is
 * provided by their caller.
 */

static int process_http_response(struct openconnect_info *vpninfo, int *result,
				 int (*header_cb)(struct openconnect_info *, char *, char *),
				 char *body, int buf_len)
{
	char buf[MAX_BUF_LEN];
	int bodylen = 0;
	int done = 0;
	int http10 = 0, closeconn = 0;
	int i;

	if (openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)) < 0) {
		vpninfo->progress(vpninfo, PRG_ERR, "Error fetching HTTPS response\n");
		return -EINVAL;
	}

 cont:
	if (!strncmp(buf, "HTTP/1.0 ", 9)) {
		http10 = 1;
		closeconn = 1;
	}

	if ((!http10 && strncmp(buf, "HTTP/1.1 ", 9)) || !(*result = atoi(buf+9))) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to parse HTTP response '%s'\n", buf);
		return -EINVAL;
	}

	vpninfo->progress(vpninfo, PRG_TRACE, "Got HTTP response: %s\n", buf);

	/* Eat headers... */
	while ((i = openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		char *colon;

		vpninfo->progress(vpninfo, PRG_TRACE, "%s\n", buf);

		if (i < 0) {
			vpninfo->progress(vpninfo, PRG_ERR, "Error processing HTTP response\n");
			return -EINVAL;
		}
		colon = strchr(buf, ':');
		if (!colon) {
			vpninfo->progress(vpninfo, PRG_ERR, "Ignoring unknown HTTP response line '%s'\n", buf);
			continue;
		}
		*(colon++) = 0;
		if (*colon == ' ')
			colon++;

		if (!strcmp(buf, "Connection") && !strcmp(colon, "Close"))
			closeconn = 1;

		if (!strcmp(buf, "Location")) {
			vpninfo->redirect_url = strdup(colon);
			if (!vpninfo->redirect_url)
				return -ENOMEM;
		}
		if (!strcmp(buf, "Content-Length")) {
			bodylen = atoi(colon);
			if (bodylen < 0 || bodylen > buf_len) {
				vpninfo->progress(vpninfo, PRG_ERR, "Response body too large for buffer (%d > %d)\n",
					bodylen, buf_len);
				return -EINVAL;
			}
		}
		if (!strcmp(buf, "Set-Cookie")) {
			struct vpn_option *new, **this;
			char *semicolon = strchr(colon, ';');
			char *equals = strchr(colon, '=');

			if (semicolon)
				*semicolon = 0;

			if (!equals) {
				vpninfo->progress(vpninfo, PRG_ERR, "Invalid cookie offered: %s\n", buf);
				return -EINVAL;
			}
			*(equals++) = 0;

			if (*equals) {
				new = malloc(sizeof(*new));
				if (!new) {
					vpninfo->progress(vpninfo, PRG_ERR, "No memory for allocating cookies\n");
					return -ENOMEM;
				}
				new->next = NULL;
				new->option = strdup(colon);
				new->value = strdup(equals);
			} else {
				/* Kill cookie; don't replace it */
				new = NULL;
			}
			for (this = &vpninfo->cookies; *this; this = &(*this)->next) {
				if (!strcmp(colon, (*this)->option)) {
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
		}
		if (!strcmp(buf, "Transfer-Encoding")) {
			if (!strcmp(colon, "chunked"))
				bodylen = -1;
			else {
				vpninfo->progress(vpninfo, PRG_ERR, "Unknown Transfer-Encoding: %s\n", colon);
				return -EINVAL;
			}
		}
		if (header_cb && !strncmp(buf, "X-", 2))
			header_cb(vpninfo, buf, colon);
	}

	/* Handle 'HTTP/1.1 100 Continue'. Not that we should ever see it */
	if (*result == 100)
		goto cont;

	/* Now the body, if there is one */
	if (!bodylen)
		goto fin;

	if (http10) {
		/* HTTP 1.0 response. Just eat all we can. */
		while (1) {
			i = SSL_read(vpninfo->https_ssl, body + done, bodylen - done);
			if (i < 0)
				goto fin;
			done += i;
		}
	}
	/* If we were given Content-Length, it's nice and easy... */
	if (bodylen > 0) {
		while (done < bodylen) {
			i = SSL_read(vpninfo->https_ssl, body + done, bodylen - done);
			if (i < 0) {
				vpninfo->progress(vpninfo, PRG_ERR, "Error reading HTTP response body\n");
				return -EINVAL;
			}
			done += i;
		}
		goto fin;
	}

	/* ... else, chunked */
	while ((i = openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		int chunklen, lastchunk = 0;

		if (i < 0) {
			vpninfo->progress(vpninfo, PRG_ERR, "Error fetching chunk header\n");
			exit(1);
		}
		chunklen = strtol(buf, NULL, 16);
		if (!chunklen) {
			lastchunk = 1;
			goto skip;
		}
		if (chunklen + done > buf_len) {
			vpninfo->progress(vpninfo, PRG_ERR, "Response body too large for buffer (%d > %d)\n",
				chunklen + done, buf_len);
			return -EINVAL;
		}
		while (chunklen) {
			i = SSL_read(vpninfo->https_ssl, body + done, chunklen);
			if (i < 0) {
				vpninfo->progress(vpninfo, PRG_ERR, "Error reading HTTP response body\n");
				return -EINVAL;
			}
			chunklen -= i;
			done += i;
		}
	skip:
		if ((i = openconnect_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
			if (i < 0) {
				vpninfo->progress(vpninfo, PRG_ERR, "Error fetching HTTP response body\n");
			} else {
				vpninfo->progress(vpninfo, PRG_ERR, "Error in chunked decoding. Expected '', got: '%s'",
					buf);
			}
			return -EINVAL;
		}

		if (lastchunk)
			break;
	}
 fin:
	if (closeconn) {
		SSL_free(vpninfo->https_ssl);
		vpninfo->https_ssl = NULL;
		close(vpninfo->ssl_fd);
		vpninfo->ssl_fd = -1;
	}
	body[done] = 0;
	return done;
}

static int fetch_config(struct openconnect_info *vpninfo, char *fu, char *bu,
			char *server_sha1)
{
	struct vpn_option *opt;
	char buf[MAX_BUF_LEN];
	int result, buflen;
	unsigned char local_sha1_bin[SHA_DIGEST_LENGTH];
	char local_sha1_ascii[(SHA_DIGEST_LENGTH * 2)+1];
	EVP_MD_CTX c;
	int i;

	sprintf(buf, "GET %s%s HTTP/1.1\r\n", fu, bu);
	sprintf(buf + strlen(buf), "Host: %s\r\n", vpninfo->hostname);
	sprintf(buf + strlen(buf),  "User-Agent: %s\r\n", vpninfo->useragent);
	sprintf(buf + strlen(buf),  "Accept: */*\r\n");
	sprintf(buf + strlen(buf),  "Accept-Encoding: identity\r\n");

	if (vpninfo->cookies) {
		sprintf(buf + strlen(buf),  "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			sprintf(buf + strlen(buf),  "%s=%s%s", opt->option,
				      opt->value, opt->next ? "; " : "\r\n");
	}
	sprintf(buf + strlen(buf),  "X-Transcend-Version: 1\r\n\r\n");

	SSL_write(vpninfo->https_ssl, buf, strlen(buf));

	buflen = process_http_response(vpninfo, &result, NULL, buf, MAX_BUF_LEN);
	if (buflen < 0) {
		/* We'll already have complained about whatever offended us */
		return -EINVAL;
	}

	if (result != 200)
		return -EINVAL;


	EVP_MD_CTX_init(&c);
	EVP_Digest(buf, buflen, local_sha1_bin, NULL, EVP_sha1(), NULL);
	EVP_MD_CTX_cleanup(&c);

	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(&local_sha1_ascii[i*2], "%02x", local_sha1_bin[i]);

	if (strcasecmp(server_sha1, local_sha1_ascii)) {
		vpninfo->progress(vpninfo, PRG_ERR, "Downloaded config file did not match intended SHA1\n");
		return -EINVAL;
	}

	return vpninfo->write_new_config(vpninfo, buf, buflen);
}

static int run_csd_script(struct openconnect_info *vpninfo, char *buf, int buflen)
{
	char fname[16];
	int fd;

	if (!vpninfo->uid_csd_given) {
		vpninfo->progress(vpninfo, PRG_ERR, "Error: You are trying to "
				  "run insecure CSD code without specifying the CSD user.\n"
				  "       Use command line option \"--csd-user\"\n");
		exit(1);
	}

#ifndef __linux__
	vpninfo->progress(vpninfo, PRG_INFO,
			  "Trying to run Linux CSD trojan script.");
#endif

	sprintf(fname, "/tmp/csdXXXXXX");
	fd = mkstemp(fname);
	if (fd < 0) {
		int err = -errno;
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to open temporary CSD script file: %s\n",
				  strerror(errno));
		return err;
	}
	write(fd, buf, buflen);
	fchmod(fd, 0755);
	close(fd);

	if (!fork()) {
		X509 *cert = SSL_get_peer_certificate(vpninfo->https_ssl);
		char certbuf[EVP_MAX_MD_SIZE * 2 + 1];
		char *csd_argv[32];
		int i = 0;

		if (vpninfo->uid_csd != getuid()) {
			struct passwd *pw;

			if (setuid(vpninfo->uid_csd)) {
				fprintf(stderr, "Failed to set uid %d\n",
					vpninfo->uid_csd);
				exit(1);
			}
			if (!(pw = getpwuid(vpninfo->uid_csd))) {
				fprintf(stderr, "Invalid user uid=%d\n",
					vpninfo->uid_csd);
				exit(1);
			}
			setenv("HOME", pw->pw_dir, 1);
			chdir(pw->pw_dir);
		}
		if (vpninfo->uid_csd == 0) {
			fprintf(stderr, "Warning: you are running insecure "
				"CSD code with root privileges\n"
				"\t Use command line option \"--csd-user\"\n");
		}

		csd_argv[i++] = fname;
		csd_argv[i++] = "-ticket";
		asprintf(&csd_argv[i++], "\"%s\"", vpninfo->csd_ticket);
		csd_argv[i++] = "-stub";
		csd_argv[i++] = "\"0\"";
		csd_argv[i++] = "-group";
		asprintf(&csd_argv[i++], "\"%s\"", vpninfo->authgroup?:"");
		get_cert_md5_fingerprint(vpninfo, cert, certbuf);
		csd_argv[i++] = "-certhash";
		asprintf(&csd_argv[i++], "\"%s:%s\"", certbuf, vpninfo->cert_md5_fingerprint ?: "");
		csd_argv[i++] = "-url";
		asprintf(&csd_argv[i++], "\"https://%s%s\"", vpninfo->hostname, vpninfo->csd_starturl);
		/* WTF would it want to know this for? */
		csd_argv[i++] = "-vpnclient";
		csd_argv[i++] = "\"/opt/cisco/vpn/bin/vpnui";
		csd_argv[i++] = "-connect";
		asprintf(&csd_argv[i++], "https://%s/%s", vpninfo->hostname, vpninfo->csd_preurl);
		csd_argv[i++] = "-connectparam";
		asprintf(&csd_argv[i++], "#csdtoken=%s\"", vpninfo->csd_token);
		csd_argv[i++] = "-langselen";
		csd_argv[i++] = NULL;

		execv(fname, csd_argv);
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to exec CSD script %s\n", fname);
		exit(1);
	}

	free(vpninfo->csd_stuburl);
	vpninfo->csd_stuburl = NULL;
	vpninfo->urlpath = strdup(vpninfo->csd_waiturl +
				  (vpninfo->csd_waiturl[0] == '/' ? 1 : 0));
	vpninfo->csd_waiturl = NULL;
	vpninfo->csd_scriptname = strdup(fname);

	/* AB: add cookie "sdesktop=__TOKEN__" */
	{
		struct vpn_option *new, **this;
		new = malloc(sizeof(*new));
		if (!new) {
			vpninfo->progress(vpninfo, PRG_ERR, "No memory for allocating cookies\n");
			return -ENOMEM;
		}
		new->next = NULL;
		new->option = strdup("sdesktop");
		new->value = strdup(vpninfo->csd_token);

		for (this = &vpninfo->cookies; *this; this = &(*this)->next) {
			if (!strcmp(new->option, (*this)->option)) {
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
	}
	return 0;
}

#ifdef __sun__
char *local_strcasestr(const char *haystack, const char *needle)
{
	int hlen = strlen(haystack);
	int nlen = strlen(needle);
	int i, j;

	for (i = 0; i < hlen - nlen + 1; i++) {
		for (j = 0; j < nlen; j++) {
			if (tolower(haystack[i + j]) != 
			    tolower(needle[j]))
				break;
		}
		if (j == nlen)
			return (char *)haystack + i;
	}
	return NULL;
}
#define strcasestr local_strcasestr
#endif

/* Return value:
 *  < 0, on error
 *  = 0, no cookie (user cancel)
 *  = 1, obtained cookie
 */
int openconnect_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct vpn_option *opt, *next;
	char buf[MAX_BUF_LEN];
	int result, buflen;
	char request_body[2048];
	char *request_body_type = NULL;
	char *method = "GET";

 retry:
	if (!vpninfo->https_ssl && openconnect_open_https(vpninfo)) {
		vpninfo->progress(vpninfo, PRG_ERR, "Failed to open HTTPS connection to %s\n",
			vpninfo->hostname);
		return -EINVAL;
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
	sprintf(buf, "%s /%s HTTP/1.1\r\n", method, vpninfo->urlpath ?: "");
	sprintf(buf + strlen(buf), "Host: %s\r\n", vpninfo->hostname);
	sprintf(buf + strlen(buf),  "User-Agent: %s\r\n", vpninfo->useragent);
	sprintf(buf + strlen(buf),  "Accept: */*\r\n");
	sprintf(buf + strlen(buf),  "Accept-Encoding: identity\r\n");

	if (vpninfo->cookies) {
		sprintf(buf + strlen(buf),  "Cookie: ");
		for (opt = vpninfo->cookies; opt; opt = opt->next)
			sprintf(buf + strlen(buf),  "%s=%s%s", opt->option,
				      opt->value, opt->next ? "; " : "\r\n");
	}
	if (request_body_type) {
		sprintf(buf + strlen(buf),  "Content-Type: %s\r\n",
			      request_body_type);
		sprintf(buf + strlen(buf),  "Content-Length: %zd\r\n",
			      strlen(request_body));
	}
	sprintf(buf + strlen(buf),  "X-Transcend-Version: 1\r\n\r\n");
	if (request_body_type)
		sprintf(buf + strlen(buf), "%s", request_body);

	vpninfo->progress(vpninfo, PRG_INFO, "%s %s/%s\n", method,
			  vpninfo->hostname, vpninfo->urlpath ?: "");

	SSL_write(vpninfo->https_ssl, buf, strlen(buf));

	buflen = process_http_response(vpninfo, &result, NULL, buf, MAX_BUF_LEN);
	if (buflen < 0) {
		/* We'll already have complained about whatever offended us */
		exit(1);
	}

	if (result != 200 && vpninfo->redirect_url) {
	redirect:
		if (!strncmp(vpninfo->redirect_url, "https://", 8)) {
			/* New host. Tear down the existing connection and make a new one */
			char *host = vpninfo->redirect_url + 8;
			char *path = strchr(host, '/');

			free(vpninfo->urlpath);
			if (path) {
				*(path++) = 0;
				vpninfo->urlpath = strdup(path);
			} else
				vpninfo->urlpath = NULL;

			if (strcmp(vpninfo->hostname, host)) {
				free(vpninfo->hostname);
				vpninfo->hostname = strdup(host);

				/* Kill the existing connection, and a new one will happen */
				SSL_free(vpninfo->https_ssl);
				vpninfo->https_ssl = NULL;
				close(vpninfo->ssl_fd);
				vpninfo->ssl_fd = -1;

				for (opt = vpninfo->cookies; opt; opt = next) {
					next = opt->next;

					free(opt->option);
					free(opt->value);
					free(opt);
				}
				vpninfo->cookies = NULL;
			}
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;

			goto retry;
		} else if (vpninfo->redirect_url[0] == '/') {
			/* Absolute redirect within same host */
			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup(vpninfo->redirect_url + 1);
			free(vpninfo->redirect_url);
			vpninfo->redirect_url = NULL;
			goto retry;
		} else {
			vpninfo->progress(vpninfo, PRG_ERR, "Relative redirect (to '%s') not supported\n",
				vpninfo->redirect_url);
			return -EINVAL;
		}
	}

	if (vpninfo->csd_stuburl) {
		/* This is the CSD stub script, which we now need to run */
		result = run_csd_script(vpninfo, buf, buflen);
		if (result)
			return result;

		/* Now we'll be redirected to the waiturl */
		goto retry;
	}
	if (strncmp(buf, "<?xml", 5)) {
		/* Not XML? Perhaps it's HTML with a refresh... */
		if (strcasestr(buf, "http-equiv=\"refresh\"")) {
			vpninfo->progress(vpninfo, PRG_INFO, "Refreshing %s after 1 second...\n",
					  vpninfo->urlpath);
			sleep(1);
			goto retry;
		}
		vpninfo->progress(vpninfo, PRG_ERR, "Unknown response from server\n");
		return -EINVAL;
	}
	request_body[0] = 0;
	result = parse_xml_response(vpninfo, buf, request_body, sizeof(request_body),
				    &method, &request_body_type);
	if (!result)
		goto redirect;

	if (result != 2)
		return result;
	/* A return value of 2 means the XML form indicated
	   success. We _should_ have a cookie... */

	for (opt = vpninfo->cookies; opt; opt = opt->next) {

		if (!strcmp(opt->option, "webvpn"))
			vpninfo->cookie = opt->value;
		else if (vpninfo->write_new_config && !strcmp(opt->option, "webvpnc")) {
			char *tok = opt->value;
			char *bu = NULL, *fu = NULL, *sha = NULL;

			do {
				if (tok != opt->value)
					*(tok++) = 0;

				if (!strncmp(tok, "bu:", 3))
					bu = tok + 3;
				else if (!strncmp(tok, "fu:", 3))
					fu = tok + 3;
				else if (!strncmp(tok, "fh:", 3)) {
					if (!strncasecmp(tok+3, vpninfo->xmlsha1,
							 SHA_DIGEST_LENGTH * 2))
						break;
					sha = tok + 3;
				}
			} while ((tok = strchr(tok, '&')));

			if (bu && fu && sha)
				fetch_config(vpninfo, bu, fu, sha);
		}
	}
	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
		vpninfo->csd_scriptname = NULL;
	}
	return 0;
}

char *openconnect_create_useragent(char *base)
{
	char *uagent = malloc(strlen(base) + 1 + strlen(openconnect_version));
	sprintf(uagent, "%s %s", base, openconnect_version);
	return uagent;
}
