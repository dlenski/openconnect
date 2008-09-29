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

#include "anyconnect.h"

int local_config_tun(struct anyconnect_info *vpninfo)
{
	struct vpn_option *cstp_opt = vpninfo->cstp_options;
	struct ifreq ifr;
	struct sockaddr_in *addr;
	int net_fd;

	net_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (net_fd < 0) {
		perror("open net");
		return -EINVAL;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, vpninfo->ifname, sizeof(ifr.ifr_name) - 1);
	if (ioctl(net_fd, SIOCGIFFLAGS, &ifr) < 0)
		perror("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(net_fd, SIOCSIFFLAGS, &ifr) < 0)
		perror("SIOCSIFFLAGS");

	addr = (struct sockaddr_in *) &ifr.ifr_addr;
	while (cstp_opt) {
		printf("CSTP option %s : %s\n", cstp_opt->option, cstp_opt->value);
		if (!strcmp(cstp_opt->option, "X-CSTP-Address")) {
			addr->sin_family = AF_INET;
			addr->sin_addr.s_addr = inet_addr(cstp_opt->value);
			if (ioctl(net_fd, SIOCSIFADDR, &ifr) < 0)
				perror("SIOCSIFADDR");
		} else if (!strcmp(cstp_opt->option, "X-CSTP-Netmask")) {
			addr->sin_family = AF_INET;
			addr->sin_addr.s_addr = inet_addr(cstp_opt->value);
			if (ioctl(net_fd, SIOCSIFNETMASK, &ifr) < 0)
				perror("SIOCSIFNETMASK");
		} else if (!strcmp(cstp_opt->option, "X-CSTP-MTU")) {
			ifr.ifr_mtu = atol(cstp_opt->value);
			if (ioctl(net_fd, SIOCSIFMTU, &ifr) < 0)
				perror("SIOCSIFMTU");
		}
		cstp_opt = cstp_opt->next;
	}
	close(net_fd);

	return 0;
}

int script_config_tun(struct anyconnect_info *vpninfo)
{
	fprintf(stderr, "FIXME: script config\n");
	return -EINVAL;
}


/* Set up a tuntap device. */
int setup_tun(struct anyconnect_info *vpninfo)
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
	strncpy(ifr.ifr_name, vpninfo->ifname, sizeof(ifr.ifr_name) - 1);
	if (ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
		perror("TUNSETIFF");
		exit(1);
	}

	fcntl(tun_fd, F_SETFD, FD_CLOEXEC);

	if (vpninfo->vpnc_script)
		script_config_tun(vpninfo);
	else
		local_config_tun(vpninfo);

	/* Better still, use lwip and just provide a SOCKS server rather than
	   telling the kernel about it at all */
	vpninfo->tun_fd = tun_fd;
	pfd = vpn_add_pollfd(vpninfo, vpninfo->tun_fd, POLLIN);

	fcntl(vpninfo->tun_fd, F_SETFL, fcntl(vpninfo->tun_fd, F_GETFL) | O_NONBLOCK);

	return 0;
}

int tun_mainloop(struct anyconnect_info *vpninfo, int *timeout)
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
