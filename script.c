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

int setenv_int(const char *opt, int value)
{
	char buf[16];
	sprintf(buf, "%d", value);
	return setenv(opt, buf, 1);
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
		setenv(envname, route, 1);

		snprintf(envname, 79, "CISCO_IPV6_SPLIT_%sC_%d_MASKLEN", in_ex,
			 *v6_incs);
		setenv(envname, slash+1, 1);

		(*v6_incs)++;
		return 0;
	}

	if (!inet_aton(route, &addr)) {
		*slash = '/';
		goto badinc;
	}

	envname[79] = 0;
	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_ADDR", in_ex, *v4_incs);
	setenv(envname, route, 1);

	/* Put it back how we found it */
	*slash = '/';

	if (!inet_aton(slash+1, &addr))
		goto badinc;

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_MASK", in_ex, *v4_incs);
	setenv(envname, slash+1, 1);

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_MASKLEN", in_ex, *v4_incs);
	setenv_int(envname, netmasklen(addr));

	(*v4_incs)++;
	return 0;
}

static int appendenv(const char *opt, const char *new)
{
	char buf[1024];
	char *old = getenv(opt);

	buf[1023] = 0;
	if (old)
		snprintf(buf, 1023, "%s %s", old, new);
	else
		snprintf(buf, 1023, "%s", new);

	return setenv(opt, buf, 1);
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

	setenv("CISCO_CSTP_OPTIONS", env_buf, 1);
	free(env_buf);
}

static void set_banner(struct openconnect_info *vpninfo)
{
	char *banner, *q;
	const char *p;

	if (!vpninfo->banner || !(banner = malloc(strlen(vpninfo->banner)+1))) {
		unsetenv("CISCO_BANNER");
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
	setenv("CISCO_BANNER", banner, 1);

	free(banner);
}

void set_script_env(struct openconnect_info *vpninfo)
{
	char host[80];
	int ret = getnameinfo(vpninfo->peer_addr, vpninfo->peer_addrlen, host,
			      sizeof(host), NULL, 0, NI_NUMERICHOST);
	if (!ret)
		setenv("VPNGATEWAY", host, 1);

	set_banner(vpninfo);
	unsetenv("CISCO_SPLIT_INC");
	unsetenv("CISCO_SPLIT_EXC");

	setenv_int("INTERNAL_IP4_MTU", vpninfo->ip_info.mtu);

	if (vpninfo->ip_info.addr) {
		setenv("INTERNAL_IP4_ADDRESS", vpninfo->ip_info.addr, 1);
		if (vpninfo->ip_info.netmask) {
			struct in_addr addr;
			struct in_addr mask;

			if (inet_aton(vpninfo->ip_info.addr, &addr) &&
			    inet_aton(vpninfo->ip_info.netmask, &mask)) {
				char *netaddr;

				addr.s_addr &= mask.s_addr;
				netaddr = inet_ntoa(addr);

				setenv("INTERNAL_IP4_NETADDR", netaddr, 1);
				setenv("INTERNAL_IP4_NETMASK", vpninfo->ip_info.netmask, 1);
				setenv_int("INTERNAL_IP4_NETMASKLEN", netmasklen(mask));
			}
		}
	}
	if (vpninfo->ip_info.addr6) {
		setenv("INTERNAL_IP6_ADDRESS", vpninfo->ip_info.addr6, 1);
		setenv("INTERNAL_IP6_NETMASK", vpninfo->ip_info.netmask6, 1);
	} else if (vpninfo->ip_info.netmask6) {
               char *slash = strchr(vpninfo->ip_info.netmask6, '/');
               setenv("INTERNAL_IP6_NETMASK", vpninfo->ip_info.netmask6, 1);
               if (slash) {
                       *slash = 0;
                       setenv("INTERNAL_IP6_ADDRESS", vpninfo->ip_info.netmask6, 1);
                       *slash = '/';
               }
	}

	if (vpninfo->ip_info.dns[0])
		setenv("INTERNAL_IP4_DNS", vpninfo->ip_info.dns[0], 1);
	else
		unsetenv("INTERNAL_IP4_DNS");
	if (vpninfo->ip_info.dns[1])
		appendenv("INTERNAL_IP4_DNS", vpninfo->ip_info.dns[1]);
	if (vpninfo->ip_info.dns[2])
		appendenv("INTERNAL_IP4_DNS", vpninfo->ip_info.dns[2]);

	if (vpninfo->ip_info.nbns[0])
		setenv("INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[0], 1);
	else
		unsetenv("INTERNAL_IP4_NBNS");
	if (vpninfo->ip_info.nbns[1])
		appendenv("INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[1]);
	if (vpninfo->ip_info.nbns[2])
		appendenv("INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[2]);

	if (vpninfo->ip_info.domain)
		setenv("CISCO_DEF_DOMAIN", vpninfo->ip_info.domain, 1);
	else
		unsetenv("CISCO_DEF_DOMAIN");

	if (vpninfo->ip_info.proxy_pac)
		setenv("CISCO_PROXY_PAC", vpninfo->ip_info.proxy_pac, 1);

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
			setenv("CISCO_SPLIT_DNS", list, 1);
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
			setenv_int("CISCO_SPLIT_INC", nr_split_includes);
		if (nr_v6_split_includes)
			setenv_int("CISCO_IPV6_SPLIT_INC", nr_v6_split_includes);
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
			setenv_int("CISCO_SPLIT_EXC", nr_split_excludes);
		if (nr_v6_split_excludes)
			setenv_int("CISCO_IPV6_SPLIT_EXC", nr_v6_split_excludes);
	}
	setenv_cstp_opts(vpninfo);
}

int script_config_tun(struct openconnect_info *vpninfo, const char *reason)
{
	int ret;

	if (!vpninfo->vpnc_script || vpninfo->script_tun)
		return 0;

	setenv("reason", reason, 1);
	ret = system(vpninfo->vpnc_script);
	if (ret == -1) {
		int e = errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn script '%s' for %s: %s\n"),
			     vpninfo->vpnc_script, reason, strerror(e));
		return -e;
	}
#ifdef _WIN32
	if (ret == 0x2331) {
		/* This is what cmd.exe returns for unrecognised commands */
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn script '%s' for %s: %s\n"),
			     vpninfo->vpnc_script, reason, strerror(ENOENT));
		return -ENOENT;
	}
#else
	if (!WIFEXITED(ret)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Script '%s' exited abnormally (%x)\n"),
			       vpninfo->vpnc_script, ret);
		return -EIO;
	}

	ret = WEXITSTATUS(ret);
#endif
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Script '%s' returned error %d\n"),
			     vpninfo->vpnc_script, ret);
		return -EIO;
	}
	return 0;
}
