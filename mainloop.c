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

#include <errno.h>
#include <poll.h>
#include <limits.h>
#include <sys/select.h>
#include "anyconnect.h"

int queue_new_packet(struct pkt **q, int type, void *buf, int len)
{
	while (*q)
		q = &(*q)->next;

	*q = malloc(sizeof(struct pkt) + len);
	if (!*q)
		return -ENOMEM;

	(*q)->type = type;
	(*q)->len = len;
	(*q)->next = NULL;
	memcpy((*q)->data, buf, len);
	return 0;
}

int vpn_add_pollfd(struct anyconnect_info *vpninfo, int fd, short events)
{
	vpninfo->nfds++;
	vpninfo->pfds = realloc(vpninfo->pfds, sizeof(struct pollfd) * vpninfo->nfds);
	if (!vpninfo->pfds) {
		fprintf(stderr, "Failed to reallocate pfds\n");
		exit(1);
	}
	vpninfo->pfds[vpninfo->nfds - 1].fd = fd;
	vpninfo->pfds[vpninfo->nfds - 1].events = events;

	return vpninfo->nfds - 1;
}

int vpn_mainloop(struct anyconnect_info *vpninfo)
{
	while (1) {
		int did_work = 0;
		int timeout = INT_MAX;

		if (vpninfo->dtls_fd != -1)
			did_work += dtls_mainloop(vpninfo, &timeout);

		did_work += ssl_mainloop(vpninfo, &timeout);
		did_work += tun_mainloop(vpninfo, &timeout);
		
		if (did_work)
			continue;
		
		if (verbose)
			printf("Did no work; sleeping for %d ms...\n", timeout);

		poll(vpninfo->pfds, vpninfo->nfds, timeout);
	}	
	return 0;
}
