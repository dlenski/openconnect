/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "openconnect-internal.h"

int script_setenv(struct openconnect_info *vpninfo,
		  const char *opt, const char *val, int append)
{
	struct oc_vpn_option *p;
	char *str;

	for (p = vpninfo->script_env; p; p = p->next) {
		if (!strcmp(opt, p->option)) {
			if (append) {
				if (asprintf(&str, "%s %s", p->value, val) == -1)
					return -ENOMEM;
			} else
				str = val ? strdup(val) : NULL;

			free (p->value);
			p->value = str;
			return 0;
		}
	}
	p = malloc(sizeof(*p));
	if (!p)
		return -ENOMEM;
	p->next = vpninfo->script_env;
	p->option = strdup(opt);
	p->value = val ? strdup(val) : NULL;
	vpninfo->script_env = p;
	return 0;
}

int script_setenv_int(struct openconnect_info *vpninfo, const char *opt, int value)
{
	char buf[16];
	sprintf(buf, "%d", value);
	return script_setenv(vpninfo, opt, buf, 0);
}

static int netmasklen(struct in_addr addr)
{
	int masklen;

	for (masklen = 0; masklen < 32; masklen++) {
		if (ntohl(addr.s_addr) >= (0xffffffff << masklen))
			break;
	}
	return 32 - masklen;
}

static int process_split_xxclude(struct openconnect_info *vpninfo,
				 int include, const char *route, int *v4_incs,
				 int *v6_incs)
{
	struct in_addr addr;
	const char *in_ex = include ? "IN" : "EX";
	char envname[80];
	char *slash;

	slash = strchr(route, '/');
	if (!slash) {
	badinc:
		if (include)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Discard bad split include: \"%s\"\n"),
				     route);
		else
			vpn_progress(vpninfo, PRG_ERR,
				     _("Discard bad split exclude: \"%s\"\n"),
				     route);
		return -EINVAL;
	}

	*slash = 0;

	if (strchr(route, ':')) {
		snprintf(envname, 79, "CISCO_IPV6_SPLIT_%sC_%d_ADDR", in_ex,
			 *v6_incs);
		script_setenv(vpninfo, envname, route, 0);

		snprintf(envname, 79, "CISCO_IPV6_SPLIT_%sC_%d_MASKLEN", in_ex,
			 *v6_incs);
		script_setenv(vpninfo, envname, slash+1, 0);

		(*v6_incs)++;
		return 0;
	}

	if (!inet_aton(route, &addr)) {
		*slash = '/';
		goto badinc;
	}

	envname[79] = 0;
	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_ADDR", in_ex, *v4_incs);
	script_setenv(vpninfo, envname, route, 0);

	/* Put it back how we found it */
	*slash = '/';

	if (!inet_aton(slash+1, &addr))
		goto badinc;

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_MASK", in_ex, *v4_incs);
	script_setenv(vpninfo, envname, slash+1, 0);

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_MASKLEN", in_ex, *v4_incs);
	script_setenv_int(vpninfo, envname, netmasklen(addr));

	(*v4_incs)++;
	return 0;
}

static void setenv_cstp_opts(struct openconnect_info *vpninfo)
{
	char *env_buf;
	int buflen = 0;
	int bufofs = 0;
	struct oc_vpn_option *opt;

	for (opt = vpninfo->cstp_options; opt; opt = opt->next)
		buflen += 2 + strlen(opt->option) + strlen(opt->value);

	env_buf = malloc(buflen + 1);
	if (!env_buf)
		return;

	env_buf[buflen] = 0;

	for (opt = vpninfo->cstp_options; opt; opt = opt->next)
		bufofs += snprintf(env_buf + bufofs, buflen - bufofs,
				   "%s=%s\n", opt->option, opt->value);

	script_setenv(vpninfo, "CISCO_CSTP_OPTIONS", env_buf, 0);
	free(env_buf);
}

static void set_banner(struct openconnect_info *vpninfo)
{
	char *banner, *legacy_banner, *q;
	const char *p;

	if (!vpninfo->banner || !(banner = malloc(strlen(vpninfo->banner)+1))) {
		script_setenv(vpninfo, "CISCO_BANNER", NULL, 0);
		return;
	}
	p = vpninfo->banner;
	q = banner;

	while (*p) {
		if (*p == '%' && isxdigit((int)(unsigned char)p[1]) &&
		    isxdigit((int)(unsigned char)p[2])) {
			*(q++) = unhex(p + 1);
			p += 3;
		} else
			*(q++) = *(p++);
	}
	*q = 0;
	legacy_banner = openconnect_utf8_to_legacy(vpninfo, banner);
	script_setenv(vpninfo, "CISCO_BANNER", legacy_banner, 0);
	if (legacy_banner != banner)
		free(legacy_banner);

	free(banner);
}

void prepare_script_env(struct openconnect_info *vpninfo)
{
	char host[80];
	int ret = getnameinfo(vpninfo->peer_addr, vpninfo->peer_addrlen, host,
			      sizeof(host), NULL, 0, NI_NUMERICHOST);
	if (!ret)
		script_setenv(vpninfo, "VPNGATEWAY", host, 0);

	set_banner(vpninfo);
	script_setenv(vpninfo, "CISCO_SPLIT_INC", NULL, 0);
	script_setenv(vpninfo, "CISCO_SPLIT_EXC", NULL, 0);

	script_setenv_int(vpninfo, "INTERNAL_IP4_MTU", vpninfo->ip_info.mtu);

	if (vpninfo->ip_info.addr) {
		script_setenv(vpninfo, "INTERNAL_IP4_ADDRESS", vpninfo->ip_info.addr, 0);
		if (vpninfo->ip_info.netmask) {
			struct in_addr addr;
			struct in_addr mask;

			if (inet_aton(vpninfo->ip_info.addr, &addr) &&
			    inet_aton(vpninfo->ip_info.netmask, &mask)) {
				char *netaddr;

				addr.s_addr &= mask.s_addr;
				netaddr = inet_ntoa(addr);

				script_setenv(vpninfo, "INTERNAL_IP4_NETADDR", netaddr, 0);
				script_setenv(vpninfo, "INTERNAL_IP4_NETMASK", vpninfo->ip_info.netmask, 0);
				script_setenv_int(vpninfo, "INTERNAL_IP4_NETMASKLEN", netmasklen(mask));
			}
		}
	}
	if (vpninfo->ip_info.addr6) {
		script_setenv(vpninfo, "INTERNAL_IP6_ADDRESS", vpninfo->ip_info.addr6, 0);
		script_setenv(vpninfo, "INTERNAL_IP6_NETMASK", vpninfo->ip_info.netmask6, 0);
	} else if (vpninfo->ip_info.netmask6) {
               char *slash = strchr(vpninfo->ip_info.netmask6, '/');
               script_setenv(vpninfo, "INTERNAL_IP6_NETMASK", vpninfo->ip_info.netmask6, 0);
               if (slash) {
                       *slash = 0;
                       script_setenv(vpninfo, "INTERNAL_IP6_ADDRESS", vpninfo->ip_info.netmask6, 0);
                       *slash = '/';
               }
	}

	if (vpninfo->ip_info.dns[0])
		script_setenv(vpninfo, "INTERNAL_IP4_DNS", vpninfo->ip_info.dns[0], 0);
	else
		script_setenv(vpninfo, "INTERNAL_IP4_DNS", NULL, 0);
	if (vpninfo->ip_info.dns[1])
		script_setenv(vpninfo, "INTERNAL_IP4_DNS", vpninfo->ip_info.dns[1], 1);
	if (vpninfo->ip_info.dns[2])
		script_setenv(vpninfo, "INTERNAL_IP4_DNS", vpninfo->ip_info.dns[2], 1);

	if (vpninfo->ip_info.nbns[0])
		script_setenv(vpninfo, "INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[0], 0);
	else
		script_setenv(vpninfo, "INTERNAL_IP4_NBNS", NULL, 0);
	if (vpninfo->ip_info.nbns[1])
		script_setenv(vpninfo, "INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[1], 1);
	if (vpninfo->ip_info.nbns[2])
		script_setenv(vpninfo, "INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[2], 1);

	if (vpninfo->ip_info.domain)
		script_setenv(vpninfo, "CISCO_DEF_DOMAIN", vpninfo->ip_info.domain, 0);
	else
		script_setenv(vpninfo, "CISCO_DEF_DOMAIN", NULL, 0);

	if (vpninfo->ip_info.proxy_pac)
		script_setenv(vpninfo, "CISCO_PROXY_PAC", vpninfo->ip_info.proxy_pac, 0);

	if (vpninfo->ip_info.split_dns) {
		char *list;
		int len = 0;
		struct oc_split_include *dns = vpninfo->ip_info.split_dns;

		while (dns) {
			len += strlen(dns->route) + 1;
			dns = dns->next;
		}
		list = malloc(len);
		if (list) {
			char *p = list;

			dns = vpninfo->ip_info.split_dns;
			while (1) {
				strcpy(p, dns->route);
				p += strlen(p);
				dns = dns->next;
				if (!dns)
					break;
				*(p++) = ',';
			}
			script_setenv(vpninfo, "CISCO_SPLIT_DNS", list, 0);
			free(list);
		}
	}
	if (vpninfo->ip_info.split_includes) {
		struct oc_split_include *this = vpninfo->ip_info.split_includes;
		int nr_split_includes = 0;
		int nr_v6_split_includes = 0;

		while (this) {
			process_split_xxclude(vpninfo, 1, this->route,
					      &nr_split_includes,
					      &nr_v6_split_includes);
			this = this->next;
		}
		if (nr_split_includes)
			script_setenv_int(vpninfo, "CISCO_SPLIT_INC", nr_split_includes);
		if (nr_v6_split_includes)
			script_setenv_int(vpninfo, "CISCO_IPV6_SPLIT_INC", nr_v6_split_includes);
	}
	if (vpninfo->ip_info.split_excludes) {
		struct oc_split_include *this = vpninfo->ip_info.split_excludes;
		int nr_split_excludes = 0;
		int nr_v6_split_excludes = 0;

		while (this) {
			process_split_xxclude(vpninfo, 0, this->route,
					      &nr_split_excludes,
					      &nr_v6_split_excludes);
			this = this->next;
		}
		if (nr_split_excludes)
			script_setenv_int(vpninfo, "CISCO_SPLIT_EXC", nr_split_excludes);
		if (nr_v6_split_excludes)
			script_setenv_int(vpninfo, "CISCO_IPV6_SPLIT_EXC", nr_v6_split_excludes);
	}
	setenv_cstp_opts(vpninfo);
}

#ifdef _WIN32
static wchar_t *create_script_env(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *opt;
	struct oc_text_buf *envbuf;
	wchar_t **oldenv, **p, *newenv = NULL;
	int nr_envs = 0, i;

	/* _wenviron is NULL until we call _wgetenv() */
	(void)_wgetenv(L"PATH");

	/* Take a copy of _wenviron (but not of its strings) */
	for (p = _wenviron; *p; p++)
		nr_envs++;

	oldenv = malloc(nr_envs * sizeof(*oldenv));
	if (!oldenv)
		return NULL;
	memcpy(oldenv, _wenviron, nr_envs * sizeof(*oldenv));

	envbuf = buf_alloc();

	/* Add the script environment variables, prodding out any members of
	   oldenv which are obsoleted by them. */
	for (opt = vpninfo->script_env; opt && !buf_error(envbuf); opt = opt->next) {
		struct oc_text_buf *buf;

		buf = buf_alloc();
		buf_append_utf16le(buf, opt->option);
		buf_append_utf16le(buf, "=");

		if (buf_error(buf)) {
			buf_free(buf);
			goto err;
		}

		/* See if we can find it in the existing environment */
		for (i = 0; i < nr_envs; i++) {
			if (!wcsncmp((wchar_t *)buf->data, oldenv[i], buf->pos / 2)) {
				oldenv[i] = NULL;
				break;
			}
		}

		if (opt->value) {
			buf_append_bytes(envbuf, buf->data, buf->pos);
			buf_append_utf16le(envbuf, opt->value);
			buf_append_bytes(envbuf, "\0\0", 2);
		}

		buf_free(buf);
	}

	for (i = 0; i < nr_envs && !buf_error(envbuf); i++) {
		if (oldenv[i])
			buf_append_bytes(envbuf, oldenv[i],
					 (wcslen(oldenv[i]) + 1) * sizeof(wchar_t));
	}

	buf_append_bytes(envbuf, "\0\0", 2);

	if (!buf_error(envbuf)) {
		newenv = (wchar_t *)envbuf->data;
		envbuf->data = NULL;
	}

 err:
	free(oldenv);
	buf_free(envbuf);
	return newenv;
}

int script_config_tun(struct openconnect_info *vpninfo, const char *reason)
{
	wchar_t *script_w;
	wchar_t *script_env;
	int nr_chars;
	int ret;
	char *cmd;
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;

	if (!vpninfo->vpnc_script || vpninfo->script_tun)
		return 0;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	/* probably superfluous */
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	script_setenv(vpninfo, "reason", reason, 0);

	if (asprintf(&cmd, "cscript.exe \"%s\"", vpninfo->vpnc_script) == -1)
		return 0;

	nr_chars = MultiByteToWideChar(CP_UTF8, 0, cmd, -1, NULL, 0);
	script_w = malloc(nr_chars * sizeof(wchar_t));

	if (!script_w) {
		free(cmd);
		return -ENOMEM;
	}

	MultiByteToWideChar(CP_UTF8, 0, cmd, -1, script_w, nr_chars);

	free(cmd);

	script_env = create_script_env(vpninfo);

	if (CreateProcessW(NULL, script_w, NULL, NULL, FALSE,
			   CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
			   script_env, NULL, &si, &pi)) {
		ret = WaitForSingleObject(pi.hProcess,10000);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		if (ret == WAIT_TIMEOUT)
			ret = -ETIMEDOUT;
		else
			ret = 0;
	} else {
		ret = -EIO;
	}

	free(script_env);

	if (ret < 0) {
		char *errstr = openconnect__win32_strerror(GetLastError());
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn script '%s' for %s: %s\n"),
			     vpninfo->vpnc_script, reason, errstr);
		free(errstr);
		goto cleanup;
	}

 cleanup:
	free(script_w);
	return ret;
}
#else
/* Must only be run after fork(). */
int apply_script_env(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *p = vpninfo->script_env;

	for (p = vpninfo->script_env; p; p = p->next) {
		if (p->value)
			setenv(p->option, p->value, 1);
		else
			unsetenv(p->option);
	}
	return 0;
}

int script_config_tun(struct openconnect_info *vpninfo, const char *reason)
{
	int ret;
	pid_t pid;

	if (!vpninfo->vpnc_script || vpninfo->script_tun)
		return 0;

	pid = fork();
	if (!pid) {
		/* Child */
		char *script = openconnect_utf8_to_legacy(vpninfo, vpninfo->vpnc_script);

		apply_script_env(vpninfo);

		setenv("reason", reason, 1);

		execl("/bin/sh", "/bin/sh", "-c", script, NULL);
		exit(127);
	}
	if (pid == -1 || waitpid(pid, &ret, 0) == -1) {
		int e = errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn script '%s' for %s: %s\n"),
			     vpninfo->vpnc_script, reason, strerror(e));
		return -e;
	}

	if (!WIFEXITED(ret)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Script '%s' exited abnormally (%x)\n"),
			       vpninfo->vpnc_script, ret);
		return -EIO;
	}

	ret = WEXITSTATUS(ret);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Script '%s' returned error %d\n"),
			     vpninfo->vpnc_script, ret);
		return -EIO;
	}
	return 0;
}
#endif
