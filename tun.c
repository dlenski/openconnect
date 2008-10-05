/*
 * Open AnyConnect (SSL + DTLS) client
 *
 * © 2008 David Woodhouse <dwmw2@infradead.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
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
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "openconnect.h"

static int local_config_tun(struct openconnect_info *vpninfo, int mtu_only)
{
	struct ifreq ifr;
	int net_fd;

	net_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (net_fd < 0) {
		perror("open net");
		return -EINVAL;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, vpninfo->ifname, sizeof(ifr.ifr_name) - 1);

	if (!mtu_only) {
		struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;

		if (ioctl(net_fd, SIOCGIFFLAGS, &ifr) < 0)
			perror("SIOCGIFFLAGS");

		ifr.ifr_flags |= IFF_UP;
		if (ioctl(net_fd, SIOCSIFFLAGS, &ifr) < 0)
			perror("SIOCSIFFLAGS");

		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = inet_addr(vpninfo->vpn_addr);
		if (ioctl(net_fd, SIOCSIFADDR, &ifr) < 0)
			perror("SIOCSIFADDR");

		addr->sin_addr.s_addr = inet_addr(vpninfo->vpn_netmask);
		if (ioctl(net_fd, SIOCSIFNETMASK, &ifr) < 0)
			perror("SIOCSIFNETMASK");
	}

	ifr.ifr_mtu = vpninfo->mtu;
	if (ioctl(net_fd, SIOCSIFMTU, &ifr) < 0)
		perror("SIOCSIFMTU");

	close(net_fd);

	return 0;
}

static int setenv_int(const char *opt, int value)
{
	char buf[16];
	sprintf(buf, "%d", value);
	return setenv(opt, buf, 1);
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

static int script_config_tun(struct openconnect_info *vpninfo)
{
	struct sockaddr_in *sin = (void *)vpninfo->peer_addr;

	if (vpninfo->peer_addr->sa_family != AF_INET) {
		fprintf(stderr, "Script cannot handle anything but Legacy IP\n");
		return -EINVAL;
	}

	setenv("VPNGATEWAY", inet_ntoa(sin->sin_addr), 1);
	setenv("TUNDEV", vpninfo->ifname, 1);
	setenv("reason", "connect", 1);
	unsetenv("CISCO_BANNER");
	unsetenv("CISCO_SPLIT_INC");

	setenv_int("INTERNAL_IP4_MTU", vpninfo->mtu);

	setenv("INTERNAL_IP4_ADDRESS", vpninfo->vpn_addr, 1);
	setenv("INTERNAL_IP4_NETMASK", vpninfo->vpn_netmask, 1);
	
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

	system(vpninfo->vpnc_script);
	return 0;
}


/* Set up a tuntap device. */
int setup_tun(struct openconnect_info *vpninfo)
{
	struct ifreq ifr;
	int tun_fd;
	int pfd;

	tun_fd = open("/dev/net/tun", O_RDWR);
	if (tun_fd < 0) {
		perror("open tun");
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (vpninfo->ifname)
		strncpy(ifr.ifr_name, vpninfo->ifname,
			sizeof(ifr.ifr_name) - 1);
	if (ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
		perror("TUNSETIFF");
		exit(1);
	}
	if (!vpninfo->ifname)
		vpninfo->ifname = strdup(ifr.ifr_name);

	fcntl(tun_fd, F_SETFD, FD_CLOEXEC);

	if (vpninfo->vpnc_script) {
		script_config_tun(vpninfo);
		/* We have to set the MTU for ourselves, because the script doesn't */
		local_config_tun(vpninfo, 1);
	} else
		local_config_tun(vpninfo, 0);

	/* Better still, use lwip and just provide a SOCKS server rather than
	   telling the kernel about it at all */
	vpninfo->tun_fd = tun_fd;
	pfd = vpn_add_pollfd(vpninfo, vpninfo->tun_fd, POLLIN);

	fcntl(vpninfo->tun_fd, F_SETFL, fcntl(vpninfo->tun_fd, F_GETFL) | O_NONBLOCK);

	return 0;
}

int tun_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	char buf[2000];
	int len;
	int work_done = 0;

	while ( (len = read(vpninfo->tun_fd, buf, sizeof(buf))) > 0) {
		queue_new_packet(&vpninfo->outgoing_queue, AF_INET, buf, len);
		work_done = 1;
	}

	/* The kernel returns -ENOMEM when the queue is full, so theoretically
	   we could handle that and retry... but it doesn't let us poll() for
	   the no-longer-full situation, so let's not bother. */
	while (vpninfo->incoming_queue) {
		struct pkt *this = vpninfo->incoming_queue;
		vpninfo->incoming_queue = this->next;
		write(vpninfo->tun_fd, this->data, this->len);
	}
	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}
