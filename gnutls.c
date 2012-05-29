/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>

#include "openconnect-internal.h"

/* OSX < 1.6 doesn't have AI_NUMERICSERV */
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

/* Helper functions for reading/writing lines over SSL.
   We could use cURL for the HTTP stuff, but it's overkill */

int openconnect_SSL_write(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	size_t orig_len = len;

	while (len) {
		int done = gnutls_record_send(vpninfo->https_sess, buf, len);
		if (done > 0)
			len -= done;
		else if (done != GNUTLS_E_AGAIN) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to write to SSL socket: %s"),
				     gnutls_strerror(done));
			return -EIO;
		} else {
			fd_set wr_set, rd_set;
			int maxfd = vpninfo->ssl_fd;

			FD_ZERO(&wr_set);
			FD_ZERO(&rd_set);
			
			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			if (vpninfo->cancel_fd != -1) {
				FD_SET(vpninfo->cancel_fd, &rd_set);
				if (vpninfo->cancel_fd > vpninfo->ssl_fd)
					maxfd = vpninfo->cancel_fd;
			}
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (vpninfo->cancel_fd != -1 &&
			    FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL write cancelled\n"));
				return -EINTR;
			}
		}
	}
	return orig_len;
}

int openconnect_SSL_read(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int done;

	while ((done = gnutls_record_recv(vpninfo->https_sess, buf, len)) < 0) {
		fd_set wr_set, rd_set;
		int maxfd = vpninfo->ssl_fd;

		if (done != GNUTLS_E_AGAIN) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to read from SSL socket: %s"),
				     gnutls_strerror(done));
			return -EIO;
		} else {
			FD_ZERO(&wr_set);
			FD_ZERO(&rd_set);
			
			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			if (vpninfo->cancel_fd != -1) {
				FD_SET(vpninfo->cancel_fd, &rd_set);
				if (vpninfo->cancel_fd > vpninfo->ssl_fd)
					maxfd = vpninfo->cancel_fd;
			}
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (vpninfo->cancel_fd != -1 &&
			    FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL read cancelled\n"));
				return -EINTR;
			}
		}
	}
	return done;
}

int  __attribute__ ((format (printf, 2, 3)))
    openconnect_SSL_printf(struct openconnect_info *vpninfo, const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	buf[1023] = 0;

	va_start(args, fmt);
	vsnprintf(buf, 1023, fmt, args);
	va_end(args);
	return openconnect_SSL_write(vpninfo, buf, strlen(buf));

}

int openconnect_SSL_gets(struct openconnect_info *vpninfo, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while (1) {
		ret = gnutls_record_recv(vpninfo->https_sess, buf + i, 1);
		if (ret == 1) {
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
		} else if (ret != GNUTLS_E_AGAIN) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to read from SSL socket: %s\n"),
				     gnutls_strerror(ret));
			ret = -EIO;
			break;
		} else {
			fd_set rd_set, wr_set;
			int maxfd = vpninfo->ssl_fd;
			
			FD_ZERO(&rd_set);
			FD_ZERO(&wr_set);
			
			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(vpninfo->ssl_fd, &wr_set);
			else
				FD_SET(vpninfo->ssl_fd, &rd_set);

			if (vpninfo->cancel_fd != -1) {
				FD_SET(vpninfo->cancel_fd, &rd_set);
				if (vpninfo->cancel_fd > vpninfo->ssl_fd)
					maxfd = vpninfo->cancel_fd;
			}
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (vpninfo->cancel_fd != -1 &&
			    FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL read cancelled\n"));
				ret = -EINTR;
				break;
			}
		}
	}
	buf[i] = 0;
	return i ?: ret;
}

static int load_certificate(struct openconnect_info *vpninfo)
{
	int err;

	vpn_progress(vpninfo, PRG_TRACE,
		     _("Using certificate file %s\n"), vpninfo->cert);
	
	err = gnutls_certificate_set_x509_key_file(vpninfo->https_cred, vpninfo->cert, vpninfo->sslkey,
						   GNUTLS_X509_FMT_PEM);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load certificate: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}
	return 0;
}

static int get_cert_fingerprint(struct openconnect_info *vpninfo,
				gnutls_x509_crt_t cert,
				gnutls_digest_algorithm_t algo,
				char *buf)
{
	unsigned char md[256];
	size_t md_size = sizeof(md);
	unsigned int i;

	if (gnutls_x509_crt_get_fingerprint(cert, algo, md, &md_size))
		return -EIO;

	for (i=0; i < md_size; i++)
		sprintf(&buf[i*2], "%02X", md[i]);

	return 0;
}

int get_cert_md5_fingerprint(struct openconnect_info *vpninfo,
			     OPENCONNECT_X509 *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, GNUTLS_DIG_MD5, buf);
}

int openconnect_get_cert_sha1(struct openconnect_info *vpninfo,
			      OPENCONNECT_X509 *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, GNUTLS_DIG_SHA1, buf);
}

static int check_server_cert(struct openconnect_info *vpninfo, OPENCONNECT_X509 *cert)
{
	char fingerprint[41];
	int ret;

	ret = openconnect_get_cert_sha1(vpninfo, cert, fingerprint);
	if (ret)
		return ret;

	if (strcasecmp(vpninfo->servercert, fingerprint)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Server SSL certificate didn't match: %s\n"), fingerprint);
		return -EINVAL;
	}
	return 0;
}

char *openconnect_get_cert_details(struct openconnect_info *vpninfo,
				   OPENCONNECT_X509 *cert)
{
	gnutls_datum_t buf;
	char *ret;

	if (gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_FULL, &buf))
		return NULL;
	
	/* Just in case gnutls_free() isn't free(), we can't steal it. */
	ret = strdup((char *)buf.data);
	gnutls_free(buf.data);
	
	return ret;
}

int openconnect_get_cert_DER(struct openconnect_info *vpninfo,
			     OPENCONNECT_X509 *cert, unsigned char **buf)
{
	size_t l = 0;
	unsigned char *ret = NULL;

	if (gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, ret, &l) != 
	    GNUTLS_E_SHORT_MEMORY_BUFFER)
		return -EIO;

	ret = malloc(l);
	if (!ret)
		return -ENOMEM;

	if (gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, ret, &l)) {
		free(ret);
 		return -EIO;
	}
	*buf = ret;
	return l;
}
#if 0
static int verify_peer(struct openconnect_info *vpninfo, SSL *https_ssl)
{
	X509 *peer_cert;
	int ret;

	peer_cert = SSL_get_peer_certificate(https_ssl);

	if (vpninfo->servercert) {
		/* If given a cert fingerprint on the command line, that's
		   all we look for */
		ret = check_server_cert(vpninfo, peer_cert);
	} else {
		int vfy = SSL_get_verify_result(https_ssl);
		const char *err_string = NULL;

		if (vfy != X509_V_OK)
			err_string = X509_verify_cert_error_string(vfy);
		else if (match_cert_hostname(vpninfo, peer_cert))
			err_string = _("certificate does not match hostname");

		if (err_string) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Server certificate verify failed: %s\n"),
				     err_string);

			if (vpninfo->validate_peer_cert)
				ret = vpninfo->validate_peer_cert(vpninfo->cbdata,
								  peer_cert,
								  err_string);
			else
				ret = -EINVAL;
		} else {
			ret = 0;
		}
	}
	X509_free(peer_cert);

	return ret;
}
#endif
static void workaround_openssl_certchain_bug(struct openconnect_info *vpninfo)
{
	/* OpenSSL has problems with certificate chains -- if there are
	   multiple certs with the same name, it doesn't necessarily
	   choose the _right_ one. (RT#1942)
	   Pick the right ones for ourselves and add them manually. */
	
	/* FIXME: Of course we still have to do this with GnuTLS, to work
	   around the issue on the server side */
}

static int check_certificate_expiry(struct openconnect_info *vpninfo)
{
	/* FIXME */
	return 0;
#if 0
	ASN1_TIME *notAfter;
	const char *reason = NULL;
	time_t t;
	int i;

	if (!vpninfo->cert_x509)
		return 0;

	t = time(NULL);
	notAfter = X509_get_notAfter(vpninfo->cert_x509);
	i = X509_cmp_time(notAfter, &t);
	if (!i) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error in client cert notAfter field\n"));
		return -EINVAL;
	} else if (i < 0) {
		reason = _("Client certificate has expired at");
	} else {
		t += vpninfo->cert_expire_warning;
		i = X509_cmp_time(notAfter, &t);
		if (i < 0) {
			reason = _("Client certificate expires soon at");
		}
	}
	if (reason) {
		BIO *bp = BIO_new(BIO_s_mem());
		BUF_MEM *bm;
		const char *expiry = _("<error>");
		char zero = 0;

		if (bp) {
			ASN1_TIME_print(bp, notAfter);
			BIO_write(bp, &zero, 1);
			BIO_get_mem_ptr(bp, &bm);
			expiry = bm->data;
		}
		vpn_progress(vpninfo, PRG_ERR, "%s: %s\n", reason, expiry);
		if (bp)
			BIO_free(bp);
	}
	return 0;
#endif
}

static int cancellable_connect(struct openconnect_info *vpninfo, int sockfd,
			       const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_storage peer;
	socklen_t peerlen = sizeof(peer);
	fd_set wr_set, rd_set;
	int maxfd = sockfd;

	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

	if (connect(sockfd, addr, addrlen) < 0 && errno != EINPROGRESS)
		return -1;

	FD_ZERO(&wr_set);
	FD_ZERO(&rd_set);
	FD_SET(sockfd, &wr_set);
	if (vpninfo->cancel_fd != -1) {
		FD_SET(vpninfo->cancel_fd, &rd_set);
		if (vpninfo->cancel_fd > sockfd)
			maxfd = vpninfo->cancel_fd;
	}
	
	/* Later we'll render this whole exercise non-pointless by
	   including a 'cancelfd' here too. */
	select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
	if (vpninfo->cancel_fd != -1 && FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
		vpn_progress(vpninfo, PRG_ERR, _("Socket connect cancelled\n"));
		errno = EINTR;
		return -1;
	}
		
	/* Check whether connect() succeeded or failed by using
	   getpeername(). See http://cr.yp.to/docs/connect.html */
	return getpeername(sockfd, (void *)&peer, &peerlen);
}

int openconnect_open_https(struct openconnect_info *vpninfo)
{
	int ssl_sock = -1;
	int err;

	if (vpninfo->https_sess)
		return 0;

	if (!vpninfo->port)
		vpninfo->port = 443;

	if (vpninfo->peer_addr) {
#ifdef SOCK_CLOEXEC
		ssl_sock = socket(vpninfo->peer_addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_IP);
		if (ssl_sock < 0)
#endif
		{
			ssl_sock = socket(vpninfo->peer_addr->sa_family, SOCK_STREAM, IPPROTO_IP);
			if (ssl_sock < 0)
				goto reconn_err;
			fcntl(ssl_sock, F_SETFD, fcntl(ssl_sock, F_GETFD) | FD_CLOEXEC);
		}
		if (cancellable_connect(vpninfo, ssl_sock, vpninfo->peer_addr, vpninfo->peer_addrlen)) {
		reconn_err:
			if (vpninfo->proxy) {
				vpn_progress(vpninfo, PRG_ERR, 
					     _("Failed to reconnect to proxy %s\n"),
					     vpninfo->proxy);
			} else {
				vpn_progress(vpninfo, PRG_ERR, 
					     _("Failed to reconnect to host %s\n"),
					     vpninfo->hostname);
			}
			return -EINVAL;
		}
		
	} else {
		struct addrinfo hints, *result, *rp;
		char *hostname;
		char port[6];

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
		hints.ai_protocol = 0;
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		/* The 'port' variable is a string because it's easier
		   this way than if we pass NULL to getaddrinfo() and
		   then try to fill in the numeric value into
		   different types of returned sockaddr_in{6,}. */
#ifdef LIBPROXY_HDR
		if (vpninfo->proxy_factory) {
			char *url;
			char **proxies;
			int i = 0;

			free(vpninfo->proxy_type);
			vpninfo->proxy_type = NULL;
			free(vpninfo->proxy);
			vpninfo->proxy = NULL;

			if (vpninfo->port == 443)
				i = asprintf(&url, "https://%s/%s", vpninfo->hostname,
					     vpninfo->urlpath?:"");
			else
				i = asprintf(&url, "https://%s:%d/%s", vpninfo->hostname,
					     vpninfo->port, vpninfo->urlpath?:"");
			if (i == -1)
				return -ENOMEM;

			proxies = px_proxy_factory_get_proxies(vpninfo->proxy_factory,
							       url);

			i = 0;
			while (proxies && proxies[i]) {
				if (!vpninfo->proxy &&
				    (!strncmp(proxies[i], "http://", 7) ||
				     !strncmp(proxies[i], "socks://", 8) ||
				     !strncmp(proxies[i], "socks5://", 9)))
					internal_parse_url(proxies[i], &vpninfo->proxy_type,
						  &vpninfo->proxy, &vpninfo->proxy_port,
						  NULL, 0);
				i++;
			}
			free(url);
			free(proxies);
			if (vpninfo->proxy)
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Proxy from libproxy: %s://%s:%d/\n"),
					     vpninfo->proxy_type, vpninfo->proxy, vpninfo->port);
		}
#endif
		if (vpninfo->proxy) {
			hostname = vpninfo->proxy;
			snprintf(port, 6, "%d", vpninfo->proxy_port);
		} else {
			hostname = vpninfo->hostname;
			snprintf(port, 6, "%d", vpninfo->port);
		}

		if (hostname[0] == '[' && hostname[strlen(hostname)-1] == ']') {
			/* Solaris has no strndup(). */
			int len = strlen(hostname) - 2;
			char *new_hostname = malloc(len + 1);
			if (!new_hostname)
				return -ENOMEM;
			memcpy(new_hostname, hostname + 1, len);
			new_hostname[len] = 0;

			hostname = new_hostname;
			hints.ai_flags |= AI_NUMERICHOST;
		}

		err = getaddrinfo(hostname, port, &hints, &result);
		if (hints.ai_flags & AI_NUMERICHOST)
			free(hostname);

		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("getaddrinfo failed for host '%s': %s\n"),
				     hostname, gai_strerror(err));
			return -EINVAL;
		}

		for (rp = result; rp ; rp = rp->ai_next) {
			char host[80];

			if (!getnameinfo(rp->ai_addr, rp->ai_addrlen, host,
					 sizeof(host), NULL, 0, NI_NUMERICHOST))
				vpn_progress(vpninfo, PRG_INFO,
					     _("Attempting to connect to %s%s%s:%s\n"),
					     rp->ai_family == AF_INET6?"[":"",
					     host,
					     rp->ai_family == AF_INET6?"]":"",
					     port);
			
			ssl_sock = socket(rp->ai_family, rp->ai_socktype,
					  rp->ai_protocol);
			if (ssl_sock < 0)
				continue;
			if (cancellable_connect(vpninfo, ssl_sock, rp->ai_addr, rp->ai_addrlen) >= 0) {
				/* Store the peer address we actually used, so that DTLS can
				   use it again later */
				vpninfo->peer_addr = malloc(rp->ai_addrlen);
				if (!vpninfo->peer_addr) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Failed to allocate sockaddr storage\n"));
					close(ssl_sock);
					return -ENOMEM;
				}
				vpninfo->peer_addrlen = rp->ai_addrlen;
				memcpy(vpninfo->peer_addr, rp->ai_addr, rp->ai_addrlen);
				break;
			}
			close(ssl_sock);
			ssl_sock = -1;
		}
		freeaddrinfo(result);
		
		if (ssl_sock < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to connect to host %s\n"),
				     vpninfo->proxy?:vpninfo->hostname);
			return -EINVAL;
		}
	}

	if (vpninfo->proxy) {
		err = process_proxy(vpninfo, ssl_sock);
		if (err) {
			close(ssl_sock);
			return err;
		}
	}

	if (!vpninfo->https_cred) {
		gnutls_certificate_allocate_credentials(&vpninfo->https_cred);
		gnutls_certificate_set_x509_trust_file(vpninfo->https_cred,
						       "/etc/pki/tls/certs/ca-bundle.crt",
						       GNUTLS_X509_FMT_PEM);

		/* FIXME: Ensure TLSv1.0, no options */

		if (vpninfo->cert) {
			err = load_certificate(vpninfo);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Loading certificate failed. Aborting.\n"));
				return err;
			}
			check_certificate_expiry(vpninfo);
		}

		/* We just want to do:
		   SSL_CTX_set_purpose(vpninfo->https_ctx, X509_PURPOSE_ANY); 
		   ... but it doesn't work with OpenSSL < 0.9.8k because of 
		   problems with inheritance (fixed in v1.1.4.6 of
		   crypto/x509/x509_vpm.c) so we have to play silly buggers
		   instead. This trick doesn't work _either_ in < 0.9.7 but
		   I don't know of _any_ workaround which will, and can't
		   be bothered to find out either. */

		if (vpninfo->cafile) {
			err = gnutls_certificate_set_x509_trust_file(vpninfo->https_cred,
								     vpninfo->cafile,
								     GNUTLS_X509_FMT_PEM);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to open CA file '%s': %s\n"),
					     vpninfo->cafile, gnutls_strerror(err));
				close(ssl_sock);
				return -EINVAL;
			}
		}

	}
	gnutls_init (&vpninfo->https_sess, GNUTLS_CLIENT);
	gnutls_priority_set_direct (vpninfo->https_sess, "NORMAL", NULL);

	workaround_openssl_certchain_bug(vpninfo);
	gnutls_credentials_set (vpninfo->https_sess, GNUTLS_CRD_CERTIFICATE, vpninfo->https_cred);
	gnutls_transport_set_ptr(vpninfo->https_sess, /* really? */(gnutls_transport_ptr_t)(long) ssl_sock);

	vpn_progress(vpninfo, PRG_INFO, _("SSL negotiation with %s\n"),
		     vpninfo->hostname);

	while ((err = gnutls_handshake (vpninfo->https_sess))) {
		if (err == GNUTLS_E_AGAIN) {
			fd_set rd_set, wr_set;
			int maxfd = ssl_sock;
			
			FD_ZERO(&rd_set);
			FD_ZERO(&wr_set);
			
			if (gnutls_record_get_direction(vpninfo->https_sess))
				FD_SET(ssl_sock, &wr_set);
			else
				FD_SET(ssl_sock, &rd_set);

			if (vpninfo->cancel_fd != -1) {
				FD_SET(vpninfo->cancel_fd, &rd_set);
				if (vpninfo->cancel_fd > vpninfo->ssl_fd)
					maxfd = vpninfo->cancel_fd;
			}
			select(maxfd + 1, &rd_set, &wr_set, NULL, NULL);
			if (vpninfo->cancel_fd != -1 &&
			    FD_ISSET(vpninfo->cancel_fd, &rd_set)) {
				vpn_progress(vpninfo, PRG_ERR, _("SSL connection cancelled\n"));
				gnutls_deinit(vpninfo->https_sess);
				vpninfo->https_sess = NULL;
				close(ssl_sock);
				return -EINTR;
			}
		} else if (err == GNUTLS_E_INTERRUPTED || gnutls_error_is_fatal(err)) {
			vpn_progress(vpninfo, PRG_ERR, _("SSL connection failure: %s\n"),
							 gnutls_strerror(err));
			gnutls_deinit(vpninfo->https_sess);
			vpninfo->https_sess = NULL;
			close(ssl_sock);
			return -EIO;
		} else {
			/* non-fatal error or warning. Ignore it and continue */
			vpn_progress(vpninfo, PRG_TRACE,
				     _("GnuTLS non-fatal return during handshake: %s\n"),
				     gnutls_strerror(err));
		}
	}
#if 0
	if (verify_peer(vpninfo, https_ssl)) {
		SSL_free(https_ssl);
		close(ssl_sock);
		return -EINVAL;
	}
#endif
	vpninfo->ssl_fd = ssl_sock;

	vpn_progress(vpninfo, PRG_INFO, _("Connected to HTTPS on %s\n"),
		     vpninfo->hostname);

	return 0;
}

void openconnect_close_https(struct openconnect_info *vpninfo)
{
#if 0
	if (vpninfo->peer_cert) {
		X509_free(vpninfo->peer_cert);
		vpninfo->peer_cert = NULL;
	}
#endif
	if (vpninfo->https_sess) {
		gnutls_deinit(vpninfo->https_sess);
		vpninfo->https_sess = NULL;
	}
	if (vpninfo->ssl_fd != -1) {
		close(vpninfo->ssl_fd);
		FD_CLR(vpninfo->ssl_fd, &vpninfo->select_rfds);
		FD_CLR(vpninfo->ssl_fd, &vpninfo->select_wfds);
		FD_CLR(vpninfo->ssl_fd, &vpninfo->select_efds);
		vpninfo->ssl_fd = -1;
	}
}

void openconnect_init_openssl(void)
{
	gnutls_global_init();
}

int openconnect_sha1(unsigned char *result, void *data, int datalen)
{
	gnutls_datum_t d;
	size_t shalen = SHA1_SIZE;

	d.data = data;
	d.size = datalen;
	if (gnutls_fingerprint(GNUTLS_DIG_SHA1, &d, result, &shalen))
		return -1;

	return 0;
}

int openconnect_random(void *bytes, int len)
{
	if (gnutls_rnd(GNUTLS_RND_RANDOM, bytes, len))
		return -EIO;
	return 0;
}

int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf)
{
	const gnutls_datum_t *d;
	size_t md5len = 16;

	buf[0] = 0;

	d = gnutls_certificate_get_ours(vpninfo->https_sess);
	if (!d)
		return -EIO;

	if (gnutls_fingerprint(GNUTLS_DIG_MD5, d, buf, &md5len))
		return -EIO;

	return 0;
}

