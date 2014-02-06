/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
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
int openconnect__win32_neterrno()
{
	switch (WSAGetLastError()) {
	case WSAEINTR:		return EINTR;
	case WSAEWOULDBLOCK:	return EWOULDBLOCK;
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

#ifdef OPENCONNECT_GNUTLS
ssize_t openconnect__win32_sock_read(gnutls_transport_ptr_t ptr, void *data, size_t size)
{
	return recv((long)ptr, data, size, 0);
}

ssize_t openconnect__win32_sock_write(gnutls_transport_ptr_t ptr, const void *data, size_t size)
{
	return send((long)ptr, data, size, 0);
}
#endif /* OPENCONNECT_GNUTLS */
#endif /* _WIN32 */
