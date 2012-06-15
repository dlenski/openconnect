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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#if defined(__linux__) || defined(ANDROID)
#include <sys/vfs.h>
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <sys/param.h>
#include <sys/mount.h>
#elif defined (__sun__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/statvfs.h>
#elif defined (__GNU__)
#include <sys/statfs.h>
#endif

#include "openconnect-internal.h"

/* OSX < 1.6 doesn't have AI_NUMERICSERV */
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

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

int connect_https_socket(struct openconnect_info *vpninfo)
{
	int ssl_sock = -1;
	int err;

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

	return ssl_sock;
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

int request_passphrase(struct openconnect_info *vpninfo, const char *label,
		       char **response, const char *fmt, ...)
{
	struct oc_auth_form f;
	struct oc_form_opt o;
	char buf[1024];
	va_list args;
	int ret;

	if (!vpninfo->process_auth_form)
		return -EINVAL;

	buf[1023] = 0;
	memset(&f, 0, sizeof(f));
	va_start(args, fmt);
	vsnprintf(buf, 1023, fmt, args);
	va_end(args);

	f.auth_id = (char *)label;
	f.opts = &o;

	o.next = NULL;
	o.type = OC_FORM_OPT_PASSWORD;
	o.name = (char *)label;
	o.label = buf;
	o.value = NULL;

	ret = vpninfo->process_auth_form(vpninfo->cbdata, &f);
	if (!ret) {
		*response = o.value;
		return 0;
	}

	return -EIO;
}

#if defined(__sun__) || defined(__NetBSD__) || defined(__DragonFly__)
int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	struct statvfs buf;

	if (statvfs(vpninfo->sslkey, &buf)) {
		int err = errno;
		vpn_progress(vpninfo, PRG_ERR, _("statvfs: %s\n"),
			     strerror(errno));
		return -err;
	}
	if (asprintf(&vpninfo->cert_password, "%lx", buf.f_fsid))
		return -ENOMEM;
	return 0;
}
#else
int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	struct statfs buf;
	unsigned *fsid = (unsigned *)&buf.f_fsid;
	unsigned long long fsid64;

	if (statfs(vpninfo->sslkey, &buf)) {
		int err = errno;
		vpn_progress(vpninfo, PRG_ERR, _("statfs: %s\n"),
			     strerror(errno));
		return -err;
	}
	fsid64 = ((unsigned long long)fsid[0] << 32) | fsid[1];

	if (asprintf(&vpninfo->cert_password, "%llx", fsid64))
		return -ENOMEM;
	return 0;
}
#endif

#if defined(OPENCONNECT_OPENSSL) || defined (DTLS_OPENSSL)
/* We put this here rather than in openssl.c because it might be needed
   for OpenSSL DTLS support even when GnuTLS is being used for HTTPS */
int openconnect_print_err_cb(const char *str, size_t len, void *ptr)
{
	struct openconnect_info *vpninfo = ptr;

	vpn_progress(vpninfo, PRG_ERR, "%s", str);
	return 0;
}
#endif
