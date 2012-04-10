/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2010 Intel Corporation.
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#if defined(__sun__)
#include <stropts.h>
#include <sys/sockio.h>
#include <net/if_tun.h>
#ifndef TUNNEWPPA
#error "Install TAP driver from http://www.whiteboard.ne.jp/~admin2/tuntap/"
#endif
#endif

#include "openconnect-internal.h"

/*
 * If an if_tun.h include file was found anywhere (by the Makefile), it's 
 * included. Else, we end up assuming that we have BSD-style devices such
 * as /dev/tun0 etc.
 */
#ifdef IF_TUN_HDR
#include IF_TUN_HDR
#endif

/*
 * The OS X tun/tap driver doesn't provide a header file; you're expected
 * to define this for yourself.
 */
#ifdef __APPLE__
#define TUNSIFHEAD  _IOW('t', 96, int)
#endif

/*
 * OpenBSD always puts the protocol family prefix onto packets. Other
 * systems let us enable that with the TUNSIFHEAD ioctl, and some of them
 * (e.g. FreeBSD) _need_ it otherwise they'll interpret IPv6 packets as IPv4.
 */
#if defined(__OpenBSD__) || defined(TUNSIFHEAD)
#define TUN_HAS_AF_PREFIX 1
#endif

#ifdef __sun__
static int local_config_tun(struct openconnect_info *vpninfo, int mtu_only)
{
	if (!mtu_only)
		vpn_progress(vpninfo, PRG_ERR,
			     _("No vpnc-script configured. Need Solaris IP-setting code\n"));
	return 0;
}
#else
static int local_config_tun(struct openconnect_info *vpninfo, int mtu_only)
{
	struct ifreq ifr;
	int net_fd;

	net_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (net_fd < 0) {
		perror(_("open net"));
		return -EINVAL;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, vpninfo->ifname, sizeof(ifr.ifr_name) - 1);

	if (!mtu_only) {
		struct sockaddr_in addr;

		if (ioctl(net_fd, SIOCGIFFLAGS, &ifr) < 0)
			perror(_("SIOCGIFFLAGS"));

		ifr.ifr_flags |= IFF_UP | IFF_POINTOPOINT;
		if (ioctl(net_fd, SIOCSIFFLAGS, &ifr) < 0)
			perror(_("SIOCSIFFLAGS"));

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(vpninfo->vpn_addr);
		memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
		if (ioctl(net_fd, SIOCSIFADDR, &ifr) < 0)
			perror(_("SIOCSIFADDR"));
	}

	ifr.ifr_mtu = vpninfo->mtu;
	if (ioctl(net_fd, SIOCSIFMTU, &ifr) < 0)
		perror(_("SIOCSIFMTU"));

	close(net_fd);

	return 0;
}
#endif

static int setenv_int(const char *opt, int value)
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
	const char *in_ex = include?"IN":"EX";
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
	struct vpn_option *opt;

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

	if (!vpninfo->banner || !(banner = malloc(strlen(vpninfo->banner)))) {
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

static void set_script_env(struct openconnect_info *vpninfo)
{
	char host[80];
	int ret = getnameinfo(vpninfo->peer_addr, vpninfo->peer_addrlen, host,
			      sizeof(host), NULL, 0, NI_NUMERICHOST);
	if (!ret)
		setenv("VPNGATEWAY", host, 1);

	set_banner(vpninfo);
	unsetenv("CISCO_SPLIT_INC");
	unsetenv("CISCO_SPLIT_EXC");

	setenv_int("INTERNAL_IP4_MTU", vpninfo->mtu);

	if (vpninfo->vpn_addr) {
		setenv("INTERNAL_IP4_ADDRESS", vpninfo->vpn_addr, 1);
		if (vpninfo->vpn_netmask) {
			struct in_addr addr;
			struct in_addr mask;

			if (inet_aton(vpninfo->vpn_addr, &addr) &&
			    inet_aton(vpninfo->vpn_netmask, &mask)) {
				char *netaddr;

				addr.s_addr &= mask.s_addr;
				netaddr = inet_ntoa(addr);

				setenv("INTERNAL_IP4_NETADDR", netaddr, 1);
				setenv("INTERNAL_IP4_NETMASK", vpninfo->vpn_netmask, 1);
				setenv_int("INTERNAL_IP4_NETMASKLEN", netmasklen(mask));
			}
		}
	}
	if (vpninfo->vpn_addr6) {
		setenv("INTERNAL_IP6_ADDRESS", vpninfo->vpn_addr6, 1);
		setenv("INTERNAL_IP6_NETMASK", vpninfo->vpn_netmask6, 1);
	}

	if (vpninfo->vpn_dns[0])
		setenv("INTERNAL_IP4_DNS", vpninfo->vpn_dns[0], 1);
	else
		unsetenv("INTERNAL_IP4_DNS");
	if (vpninfo->vpn_dns[1])
		appendenv("INTERNAL_IP4_DNS", vpninfo->vpn_dns[1]);
	if (vpninfo->vpn_dns[2])
		appendenv("INTERNAL_IP4_DNS", vpninfo->vpn_dns[2]);

	if (vpninfo->vpn_nbns[0])
		setenv("INTERNAL_IP4_NBNS", vpninfo->vpn_nbns[0], 1);
	else
		unsetenv("INTERNAL_IP4_NBNS");
	if (vpninfo->vpn_nbns[1])
		appendenv("INTERNAL_IP4_NBNS", vpninfo->vpn_nbns[1]);
	if (vpninfo->vpn_nbns[2])
		appendenv("INTERNAL_IP4_NBNS", vpninfo->vpn_nbns[2]);

	if (vpninfo->vpn_domain)
		setenv("CISCO_DEF_DOMAIN", vpninfo->vpn_domain, 1);
	else unsetenv ("CISCO_DEF_DOMAIN");

	if (vpninfo->vpn_proxy_pac)
		setenv("CISCO_PROXY_PAC", vpninfo->vpn_proxy_pac, 1);

	if (vpninfo->split_includes) {
		struct split_include *this = vpninfo->split_includes;
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
	if (vpninfo->split_excludes) {
		struct split_include *this = vpninfo->split_excludes;
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
	if (!vpninfo->vpnc_script)
		return 0;

	setenv("reason", reason, 1);
	if (system(vpninfo->vpnc_script)) {
		int e = errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn script '%s' for %s: %s\n"),
			     vpninfo->vpnc_script, reason, strerror(e));
		return -e;
	}
	return 0;
}

#ifdef __sun__
static int link_proto(int unit_nr, const char *devname, uint64_t flags)
{
	int ip_fd, mux_id, tun2_fd;
	struct lifreq ifr;

	tun2_fd = open("/dev/tun", O_RDWR);
	if (tun2_fd < 0) {
		perror(_("Could not /dev/tun for plumbing"));
		return -EIO;
	}
	if (ioctl(tun2_fd, I_PUSH, "ip") < 0) {
		perror(_("Can't push IP"));
		close(tun2_fd);
		return -EIO;
	}

	sprintf(ifr.lifr_name, "tun%d", unit_nr);
	ifr.lifr_ppa = unit_nr;
	ifr.lifr_flags = flags;

	if (ioctl(tun2_fd, SIOCSLIFNAME, &ifr) < 0) {
		perror(_("Can't set ifname"));
		close(tun2_fd);
		return -1;
	}

	ip_fd = open(devname, O_RDWR);
	if (ip_fd < 0) {
		fprintf(stderr, _("Can't open %s: %s"), devname,
			strerror(errno));
		close(tun2_fd);
		return -1;
	}
	if (ioctl(ip_fd, I_PUSH, "arp") < 0) {
		perror(_("Can't push ARP"));
		close(tun2_fd);
		close(ip_fd);
		return -1;
	}

	mux_id = ioctl(ip_fd, I_LINK, tun2_fd);
	if (mux_id < 0) {
		fprintf(stderr, _("Can't plumb %s for IPv%d: %s\n"),
			 ifr.lifr_name, (flags == IFF_IPV4) ? 4 : 6,
			 strerror(errno));
		close(tun2_fd);
		close(ip_fd);
		return -1;
	}

	close(tun2_fd);

	return ip_fd;
}
#endif

static int os_setup_tun(struct openconnect_info *vpninfo)
{
	int tun_fd;

#ifdef IFF_TUN /* Linux */
	struct ifreq ifr;
	int tunerr;

	tun_fd = open("/dev/net/tun", O_RDWR);
	if (tun_fd < 0) {
		/* Android has /dev/tun instead of /dev/net/tun
		   Since other systems might have too, just try it
		   as a fallback instead of using ifdef __ANDROID__ */
		tunerr = errno;
		tun_fd = open("/dev/tun", O_RDWR);
	}
	if (tun_fd < 0) {
		/* If the error on /dev/tun is ENOENT, that's boring.
		   Use the error we got on /dev/net/tun instead */
		if (errno != -ENOENT)
			tunerr = errno;

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open tun device: %s\n"),
			     strerror(tunerr));
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (vpninfo->ifname)
		strncpy(ifr.ifr_name, vpninfo->ifname,
			sizeof(ifr.ifr_name) - 1);
	if (ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TUNSETIFF failed: %s\n"),
			     strerror(errno));
		exit(1);
	}
	if (!vpninfo->ifname)
		vpninfo->ifname = strdup(ifr.ifr_name);
#elif defined (__sun__)
	static char tun_name[80];
	int unit_nr;

	tun_fd = open("/dev/tun", O_RDWR);
	if (tun_fd < 0) {
		perror(_("open /dev/tun"));
		return -EIO;
	}

	unit_nr = ioctl(tun_fd, TUNNEWPPA, -1);
	if (unit_nr < 0) {
		perror(_("Failed to create new tun"));
		close(tun_fd);
		return -EIO;
	}

	if (ioctl(tun_fd, I_SRDOPT, RMSGD) < 0) {
		perror(_("Failed to put tun file descriptor into message-discard mode"));
		close(tun_fd);
		return -EIO;
	}

	sprintf(tun_name, "tun%d", unit_nr);
	vpninfo->ifname = strdup(tun_name);

	vpninfo->ip_fd = link_proto(unit_nr, "/dev/udp", IFF_IPV4);
	if (vpninfo->ip_fd < 0) {
		close(tun_fd);
		return -EIO;
	}

	if (vpninfo->vpn_addr6) {
		vpninfo->ip6_fd = link_proto(unit_nr, "/dev/udp6", IFF_IPV6);
		if (vpninfo->ip6_fd < 0) {
			close(tun_fd);
			close(vpninfo->ip_fd);
			vpninfo->ip_fd = -1;
			return -EIO;
		}
	} else
		vpninfo->ip6_fd = -1;

#else /* BSD et al have /dev/tun$x devices */
	static char tun_name[80];
	int i;
	for (i = 0; i < 255; i++) {
		sprintf(tun_name, "/dev/tun%d", i);
		tun_fd = open(tun_name, O_RDWR);
		if (tun_fd >= 0)
			break;
	}
	if (tun_fd < 0) {
		perror(_("open tun"));
		exit(1);
	}
	vpninfo->ifname = strdup(tun_name + 5);
#ifdef TUNSIFHEAD
	i = 1;
	if (ioctl(tun_fd, TUNSIFHEAD, &i) < 0) {
		perror(_("TUNSIFHEAD"));
		exit(1);
	}
#endif
#endif
	return tun_fd;
}

/* Set up a tuntap device. */
int setup_tun(struct openconnect_info *vpninfo)
{
	int tun_fd;

	set_script_env(vpninfo);

	if (vpninfo->script_tun) {
		pid_t child;
		int fds[2];

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)) {
			perror(_("socketpair"));
			exit(1);
		}
		tun_fd = fds[0];
		child = fork();
		if (child < 0) {
			perror(_("fork"));
			exit(1);
		} else if (!child) {
			close(tun_fd);
			setenv_int("VPNFD", fds[1]);
			execl("/bin/sh", "/bin/sh", "-c", vpninfo->vpnc_script, NULL);
			perror(_("execl"));
			exit(1);
		}
		close(fds[1]);
		vpninfo->script_tun = child;
		vpninfo->ifname = strdup(_("(script)"));
	} else {
		script_config_tun(vpninfo, "pre-init");

		tun_fd = os_setup_tun(vpninfo);
		if (tun_fd < 0)
			return tun_fd;

		if (vpninfo->vpnc_script) {
			setenv("TUNDEV", vpninfo->ifname, 1);
			script_config_tun(vpninfo, "connect");
			/* We have to set the MTU for ourselves, because the script doesn't */
			local_config_tun(vpninfo, 1);
		} else
			local_config_tun(vpninfo, 0);
	}

	fcntl(tun_fd, F_SETFD, FD_CLOEXEC);

	vpninfo->tun_fd = tun_fd;

	if (vpninfo->select_nfds <= tun_fd)
		vpninfo->select_nfds = tun_fd + 1;

	FD_SET(tun_fd, &vpninfo->select_rfds);

	fcntl(vpninfo->tun_fd, F_SETFL, fcntl(vpninfo->tun_fd, F_GETFL) | O_NONBLOCK);

	return 0;
}

static struct pkt *out_pkt;

int tun_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int work_done = 0;
	int prefix_size = 0;

#ifdef TUN_HAS_AF_PREFIX
	if (!vpninfo->script_tun)
		prefix_size = sizeof(int);
#endif

	if (FD_ISSET(vpninfo->tun_fd, &vpninfo->select_rfds)) {
		while (1) {
			int len = vpninfo->mtu;

			if (!out_pkt) {
				out_pkt = malloc(sizeof(struct pkt) + len);
				if (!out_pkt) {
					vpn_progress(vpninfo, PRG_ERR, "Allocation failed\n");
					break;
				}
			}

			len = read(vpninfo->tun_fd, out_pkt->data - prefix_size, len + prefix_size);
			if (len <= prefix_size)
				break;
			out_pkt->len = len - prefix_size;

			queue_packet(&vpninfo->outgoing_queue, out_pkt);
			out_pkt = NULL;

			work_done = 1;
			vpninfo->outgoing_qlen++;
			if (vpninfo->outgoing_qlen == vpninfo->max_qlen) {
				FD_CLR(vpninfo->tun_fd, &vpninfo->select_rfds);
				break;
			}
		}
	} else if (vpninfo->outgoing_qlen < vpninfo->max_qlen) {
		FD_SET(vpninfo->tun_fd, &vpninfo->select_rfds);
	}

	/* The kernel returns -ENOMEM when the queue is full, so theoretically
	   we could handle that and retry... but it doesn't let us poll() for
	   the no-longer-full situation, so let's not bother. */
	while (vpninfo->incoming_queue) {
		struct pkt *this = vpninfo->incoming_queue;
		unsigned char *data = this->data;
		int len = this->len;

#ifdef TUN_HAS_AF_PREFIX
		if (!vpninfo->script_tun) {
			struct ip *iph = (void *)data;
			int type;

			if (iph->ip_v == 6)
				type = AF_INET6;
			else if (iph->ip_v == 4)
				type = AF_INET;
			else {
				static int complained = 0;
				if (!complained) {
					complained = 1;
					vpn_progress(vpninfo, PRG_ERR,
						     _("Unknown packet (len %d) received: %02x %02x %02x %02x...\n"),
						     len, data[0], data[1], data[2], data[3]);
				}
				free(this);
				continue;
			}
			data -= 4;
			len += 4;
			*(int *)data = htonl(type);
		}
#endif
		vpninfo->incoming_queue = this->next;

		if (write(vpninfo->tun_fd, data, len) < 0) {
			/* Handle death of "script" socket */
			if (vpninfo->script_tun && errno == ENOTCONN) {
				vpninfo->quit_reason = "Client connection terminated";
				return 1;
			}
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to write incoming packet: %s\n"),
				     strerror(errno));
		}
		free(this);
	}
	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

void shutdown_tun(struct openconnect_info *vpninfo)
{	
	if (vpninfo->script_tun) {
		kill(vpninfo->script_tun, SIGHUP);
	} else {
		script_config_tun(vpninfo, "disconnect");
#ifdef __sun__
		close(vpninfo->ip_fd);
		vpninfo->ip_fd = -1;
		if (vpninfo->ip6_fd != -1) {
			close(vpninfo->ip6_fd);
			vpninfo->ip6_fd = -1;
		}
#endif
	}

	close(vpninfo->tun_fd);
	vpninfo->tun_fd = -1;
}
