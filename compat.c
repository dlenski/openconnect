/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>
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

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "openconnect-internal.h"

#ifdef HAVE_SUNOS_BROKEN_TIME
/*
 * On SunOS, time() goes backwards. Thankfully, gethrtime() doesn't.
 * https://www.illumos.org/issues/1871 and, for Solaris 11, CR7121035.
 */
#include <sys/time.h>

time_t openconnect__time(time_t *t)
{
	time_t s = gethrtime() / 1000000000LL;
	if (t)
		*t = s;

	return s;
}
#endif

#ifndef HAVE_ASPRINTF

static int oc_vasprintf(char **strp, const char *fmt, va_list ap)
{
	va_list ap2;
	char *res = NULL;
	int len = 160, len2;
	int ret = 0;
	int errno_save = -ENOMEM;

	res = malloc(160);
	if (!res)
		goto err;

	/* Use a copy of 'ap', preserving it in case we need to retry into
	   a larger buffer. 160 characters should be sufficient for most
	   strings in openconnect. */
#ifdef HAVE_VA_COPY
	va_copy(ap2, ap);
#elif defined(HAVE___VA_COPY)
	__va_copy(ap2, ap);
#else
#error No va_copy()!
	/* You could try this. */
	ap2 = ap;
	/* Or this */
	*ap2 = *ap;
#endif
	len = vsnprintf(res, 160, fmt, ap2);
	va_end(ap2);

	if (len < 0) {
	printf_err:
		errno_save = errno;
		free(res);
		res = NULL;
		goto err;
	}
	if (len >= 0 && len < 160)
		goto out;

	free(res);
	res = malloc(len+1);
	if (!res)
		goto err;

	len2 = vsnprintf(res, len+1, fmt, ap);
	if (len2 < 0 || len2 > len)
		goto printf_err;

	ret = 0;
	goto out;

 err:
	errno = errno_save;
	ret = -1;
 out:
	*strp = res;
	return ret;
}

int openconnect__asprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = oc_vasprintf(strp, fmt, ap);
	va_end(ap);
	return ret;
}
#endif

#ifndef HAVE_GETLINE
ssize_t openconnect__getline(char **lineptr, size_t *n, FILE *stream)
{
	int len = 0;

	if (!*lineptr) {
		*n = 2;
		*lineptr = malloc(*n);
		if (!*lineptr)
			return -1;
	}

	while (fgets((*lineptr) + len, (*n) - len, stream)) {

		len += strlen((*lineptr) + len);
		if ((*lineptr)[len-1] == '\n')
			break;

		*n *= 2;
		realloc_inplace(*lineptr, *n);
		if (!*lineptr)
			return -1;
	}
	if (len)
		return len;
	return -1;
}
#endif

#ifndef HAVE_STRCASESTR

char *openconnect__strcasestr(const char *haystack, const char *needle)
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
#endif

#ifndef HAVE_SETENV
int openconnect__setenv(const char *name, const char *value, int overwrite)
{
	char *buf = alloca(strlen(name) + strlen(value) + 2);

	sprintf(buf, "%s=%s", name, value);
	putenv(buf);
	return 0;
}
#endif

#ifndef HAVE_UNSETENV
void openconnect__unsetenv(const char *name)
{
	char *buf = alloca(strlen(name) + 2);

	sprintf(buf, "%s=", name);
	putenv(buf);
}
#endif

#ifndef HAVE_INET_ATON
int openconnect__inet_aton(const char *cp, struct in_addr *addr)
{
  addr->s_addr = inet_addr(cp);
  return (addr->s_addr == 0xffffffff) ? 0 : 1;
}
#endif

#ifdef _WIN32
void openconnect__win32_sock_init()
{
	WSADATA data;
	if (WSAStartup (MAKEWORD(1, 1), &data) != 0) {
		fprintf(stderr, _("ERROR: Cannot initialize sockets\n"));
		exit(1);
	}
}

#ifdef OPENCONNECT_GNUTLS
int openconnect__win32_neterrno()
{
	switch (WSAGetLastError()) {
	case WSAEINTR:		return EINTR;
	case WSAEWOULDBLOCK:	return EAGAIN;
	case WSAEINPROGRESS:	return EINPROGRESS;
	case WSAEALREADY:	return EALREADY;
	case WSAENOTSOCK:	return ENOTSOCK;
	case WSAEDESTADDRREQ:	return EDESTADDRREQ;
	case WSAEMSGSIZE:	return EMSGSIZE;
	case WSAEPROTOTYPE:	return EPROTOTYPE;
	case WSAENOPROTOOPT:	return ENOPROTOOPT;
	case WSAEPROTONOSUPPORT:return EPROTONOSUPPORT;
	case WSAEOPNOTSUPP:	return EOPNOTSUPP;
	case WSAEPFNOSUPPORT:	return EAFNOSUPPORT;
	case WSAEAFNOSUPPORT:	return EAFNOSUPPORT;
	case WSAEADDRINUSE:	return EADDRINUSE;
	case WSAEADDRNOTAVAIL:	return EADDRNOTAVAIL;
	case WSAENETDOWN:	return ENETDOWN;
	case WSAENETUNREACH:	return ENETUNREACH;
	case WSAENETRESET:	return ENETRESET;
	case WSAECONNABORTED:	return ECONNABORTED;
	case WSAECONNRESET:	return ECONNRESET;
	case WSAENOBUFS:	return ENOBUFS;
	case WSAEISCONN:	return EISCONN;
	case WSAENOTCONN:	return ENOTCONN;
	case WSAETIMEDOUT:	return ETIMEDOUT;
	case WSAECONNREFUSED:	return ECONNREFUSED;
	case WSAELOOP:		return ELOOP;
	case WSAENAMETOOLONG:	return ENAMETOOLONG;
	case WSAEHOSTUNREACH:	return EHOSTUNREACH;
	case WSAENOTEMPTY:	return ENOTEMPTY;
	case WSAEINVAL:		return EINVAL;
	case WSAEFAULT:		return EFAULT;
	case 0:			return 0;
	default:		return EIO;
	}
}

int openconnect__win32_sock_poll(gnutls_transport_ptr_t ptr, unsigned int ms)
{
	fd_set rfds;
	struct timeval tv;
	int fd = (int)(long)ptr;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = ms * 1000;

	while(tv.tv_usec >= 1000000) {
		tv.tv_usec -= 1000000;
		tv.tv_sec++;
	}

	return select(fd+1, &rfds, NULL, NULL, &tv);
}

ssize_t openconnect__win32_sock_read(gnutls_transport_ptr_t ptr, void *data, size_t size)
{
	return recv((long)ptr, data, size, 0);
}

ssize_t openconnect__win32_sock_write(gnutls_transport_ptr_t ptr, const void *data, size_t size)
{
	return send((long)ptr, data, size, 0);
}
#endif /* OPENCONNECT_GNUTLS */


/* https://github.com/ncm/selectable-socketpair

Copyright 2007, 2010 by Nathan C. Myers <ncm@cantrip.org>
Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.
    
    Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    The name of the author must not be used to endorse or promote products derived 
    from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Changes:
 * 2013-07-18: Change to BSD 3-clause license
 * 2010-03-31:
 *   set addr to 127.0.0.1 because win32 getsockname does not always set it.
 * 2010-02-25:
 *   set SO_REUSEADDR option to avoid leaking some windows resource.
 *   Windows System Error 10049, "Event ID 4226 TCP/IP has reached 
 *   the security limit imposed on the number of concurrent TCP connect 
 *   attempts."  Bleah.
 * 2007-04-25:
 *   preserve value of WSAGetLastError() on all error returns.
 * 2007-04-22:  (Thanks to Matthew Gregan <kinetik@flim.org>)
 *   s/EINVAL/WSAEINVAL/ fix trivial compile failure
 *   s/socket/WSASocket/ enable creation of sockets suitable as stdin/stdout
 *     of a child process.
 *   add argument make_overlapped
 */

#include <string.h>

# include <winsock2.h>
# include <windows.h>
# include <io.h>

/* dumb_socketpair:
 *   If make_overlapped is nonzero, both sockets created will be usable for
 *   "overlapped" operations via WSASend etc.  If make_overlapped is zero,
 *   socks[0] (only) will be usable with regular ReadFile etc., and thus 
 *   suitable for use as stdin or stdout of a child process.  Note that the
 *   sockets must be closed with closesocket() regardless.
 */

int dumb_socketpair(int socks[2], int make_overlapped)
{
    union {
       struct sockaddr_in inaddr;
       struct sockaddr addr;
    } a;
    SOCKET listener;
    int e;
    socklen_t addrlen = sizeof(a.inaddr);
    DWORD flags = (make_overlapped ? WSA_FLAG_OVERLAPPED : 0);
    int reuse = 1;

    if (socks == 0) {
      WSASetLastError(WSAEINVAL);
      return SOCKET_ERROR;
    }

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) 
        return SOCKET_ERROR;

    memset(&a, 0, sizeof(a));
    a.inaddr.sin_family = AF_INET;
    a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.inaddr.sin_port = 0; 

    socks[0] = socks[1] = INVALID_SOCKET;
    do {
        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, 
               (char*) &reuse, (socklen_t) sizeof(reuse)) == -1)
            break;
        if  (bind(listener, &a.addr, sizeof(a.inaddr)) == SOCKET_ERROR)
            break;

        memset(&a, 0, sizeof(a));
        if  (getsockname(listener, &a.addr, &addrlen) == SOCKET_ERROR)
            break;
        // win32 getsockname may only set the port number, p=0.0005.
        // ( http://msdn.microsoft.com/library/ms738543.aspx ):
        a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.inaddr.sin_family = AF_INET;

        if (listen(listener, 1) == SOCKET_ERROR)
            break;

        socks[0] = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, flags);
        if (socks[0] == INVALID_SOCKET)
            break;
        if (connect(socks[0], &a.addr, sizeof(a.inaddr)) == SOCKET_ERROR)
            break;

        socks[1] = accept(listener, NULL, NULL);
        if (socks[1] == INVALID_SOCKET)
            break;

        closesocket(listener);
        return 0;

    } while (0);

    e = WSAGetLastError();
    closesocket(listener);
    closesocket(socks[0]);
    closesocket(socks[1]);
    WSASetLastError(e);
    return SOCKET_ERROR;
}
#endif /* _WIN32 */
