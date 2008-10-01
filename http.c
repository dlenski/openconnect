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

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "anyconnect.h"

/*
 * We didn't really want to have to do this for ourselves -- one might have 
 * thought that it would be available in a library somewhere. But neither
 * cURL nor Neon have reliable cross-platform ways of either using a cert
 * from the TPM, or just reading from / writing to a transport which is
 * provided by their caller.
 */

int process_http_response(struct anyconnect_info *vpninfo, int *result,
			  int (*header_cb)(struct anyconnect_info *, char *, char *),
			  char *body, int buf_len)
{
	char buf[65536];
	int bodylen = 0;
	int done = 0;
	int http10 = 0, closeconn = 0;
	int i;

	if (my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)) < 0) {
		fprintf(stderr, "Error fetching HTTPS response\n");
		exit(1);
	}

 cont:
	if (!strncmp(buf, "HTTP/1.0 ", 9)) {
		http10 = 1;
		closeconn = 1;
	}

	if ((!http10 && strncmp(buf, "HTTP/1.1 ", 9)) || !(*result = atoi(buf+9))) {
		fprintf(stderr, "Failed to parse HTTP response '%s'\n", buf);
		return -EINVAL;
	}

	if (verbose || *result == 100)
		printf("Got HTTP response: %s\n", buf);

	/* Eat headers... */
	while ((i=my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		char *colon;

		if (verbose)
			printf("%s\n", buf);
		if (i < 0) {
			fprintf(stderr, "Error processing HTTP response\n");
			return -EINVAL;
		}
		colon = strchr(buf, ':');
		if (!colon) {
			fprintf(stderr, "Ignoring unknown HTTP response line '%s'\n", buf);
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
				fprintf(stderr, "Response body too large for buffer (%d > %d)\n",
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
				fprintf(stderr, "Invalid cookie offered: %s\n", buf);
				return -EINVAL;
			}
			*(equals++) = 0;

			new = malloc(sizeof(*new));
			if (!new) {
				fprintf(stderr, "No memory for allocating cookies\n");
				return -ENOMEM;
			}
			new->next = NULL;
			new->option = strdup(colon);
			new->value = strdup(equals);
			
			for (this = &vpninfo->cookies; *this; this = &(*this)->next) {
				if (!strcmp(new->option, (*this)->option)) {
					/* Replace existing cookie */
					new->next = (*this)->next;
					free((*this)->option);
					free((*this)->value);
					free(*this);
					*this = new;
					break;
				}
			}
			if (!*this) {
				*this = new;
				new->next = NULL;
			}
		}
		if (!strcmp(buf, "Transfer-Encoding")) {
			if (!strcmp(colon, "chunked"))
				bodylen = -1;
			else {
				fprintf(stderr, "Unknown Transfer-Encoding: %s\n", colon);
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
				fprintf(stderr, "Error reading HTTP response body\n");
				return -EINVAL;
			}
			done += i;
		}
		goto fin;
	}

	/* ... else, chunked */
	while ((i=my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
		int chunklen, lastchunk = 0;

		if (i < 0) {
			fprintf(stderr, "Error fetching chunk header\n");
			exit(1);
		}
		chunklen = strtol(buf, NULL, 16);
		if (!chunklen) {
			lastchunk = 1;
			goto skip;
		}
		if (chunklen + done > buf_len) {
			fprintf(stderr, "Response body too large for buffer (%d > %d)\n",
				chunklen + done, buf_len);
			return -EINVAL;
		}
		while (chunklen) {
			i = SSL_read(vpninfo->https_ssl, body + done, chunklen);
			if (i < 0) {
				fprintf(stderr, "Error reading HTTP response body\n");
				return -EINVAL;
			}
			chunklen -= i;
			done += i;
		}
	skip:
		if ((i=my_SSL_gets(vpninfo->https_ssl, buf, sizeof(buf)))) {
			if (i < 0) {
				fprintf(stderr, "Error fetching HTTP response body\n");
			} else {
				fprintf(stderr, "Error in chunked decoding. Expected '', got: '%s'",
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

	return done;
}

