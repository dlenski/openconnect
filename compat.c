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

#include "openconnect-internal.h"

#ifdef __sun__
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
#include <stdarg.h>
#include <errno.h>

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
#elif defined (HAVE___VA_COPY)
	__va_copy(ap2, ap);
#else
#error No va_copy()!
	// You could try this.
	ap2 = ap;
	// Or this
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
	if (len >=0 && len < 160)
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
