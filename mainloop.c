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
#include <signal.h>
#include <arpa/inet.h>

#include "anyconnect.h"

void queue_packet(struct pkt **q, struct pkt *new)
{
	while (*q)
		q = &(*q)->next;

	new->next = NULL;
	*q = new;
}

int queue_new_packet(struct pkt **q, int type, void *buf, int len)
{
	struct pkt *new = malloc(sizeof(struct pkt) + len);
	if (!new)
		return -ENOMEM;

	new->type = type;
	new->len = len;
	new->next = NULL;
	memcpy(new->data, buf, len);
	queue_packet(q, new);
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

static int killed;

static void handle_sigint(int sig)
{
	killed = 1;
}

int vpn_mainloop(struct anyconnect_info *vpninfo)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sigint;
	
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	while (!killed && !vpninfo->quit_reason) {
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
		if (vpninfo->pfds[vpninfo->ssl_pfd].revents & POLL_HUP) {
			fprintf(stderr, "Server closed connection!\n");
			/* OpenSSL doesn't seem to cope properly with this... */
			exit(1);
		}
	}
	if (!vpninfo->quit_reason)
		vpninfo->quit_reason = "Client received SIGINT";

	ssl_bye(vpninfo, vpninfo->quit_reason);

	if (vpninfo->vpnc_script) {
		setenv("TUNDEV", vpninfo->ifname, 1);
		setenv("reason", "disconnect", 1);
		system(vpninfo->vpnc_script);
	}

	return 0;
}
