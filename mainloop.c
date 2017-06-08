/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifndef _WIN32
/* for setgroups() */
# include <sys/types.h>
# include <grp.h>
#endif

#include "openconnect-internal.h"

int queue_new_packet(struct pkt_q *q, void *buf, int len)
{
	struct pkt *new = malloc(sizeof(struct pkt) + len);
	if (!new)
		return -ENOMEM;

	new->len = len;
	new->next = NULL;
	memcpy(new->data, buf, len);
	queue_packet(q, new);
	return 0;
}

/* This is here because it's generic and hence can't live in either of the
   tun*.c files for specific platforms */
int tun_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	struct pkt *this;
	int work_done = 0;

	if (!tun_is_up(vpninfo)) {
		/* no tun yet; clear any queued packets */
		while ((this = dequeue_packet(&vpninfo->incoming_queue)))
			free(this);

		return 0;
	}

	if (read_fd_monitored(vpninfo, tun)) {
		struct pkt *out_pkt = vpninfo->tun_pkt;
		while (1) {
			int len = vpninfo->ip_info.mtu;

			if (!out_pkt) {
				out_pkt = malloc(sizeof(struct pkt) + len + vpninfo->pkt_trailer);
				if (!out_pkt) {
					vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
					break;
				}
				out_pkt->len = len;
			}

			if (os_read_tun(vpninfo, out_pkt))
				break;

			vpninfo->stats.tx_pkts++;
			vpninfo->stats.tx_bytes += out_pkt->len;
			work_done = 1;

			if (queue_packet(&vpninfo->outgoing_queue, out_pkt) ==
			    vpninfo->max_qlen) {
				out_pkt = NULL;
				unmonitor_read_fd(vpninfo, tun);
				break;
			}
			out_pkt = NULL;
		}
		vpninfo->tun_pkt = out_pkt;
	} else if (vpninfo->outgoing_queue.count < vpninfo->max_qlen) {
		monitor_read_fd(vpninfo, tun);
	}

	while ((this = dequeue_packet(&vpninfo->incoming_queue))) {

		unmonitor_write_fd(vpninfo, tun);

		if (os_write_tun(vpninfo, this)) {
			requeue_packet(&vpninfo->incoming_queue, this);
			break;
		}

		vpninfo->stats.rx_pkts++;
		vpninfo->stats.rx_bytes += this->len;

		free(this);
	}
	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

static int setup_tun_device(struct openconnect_info *vpninfo)
{
	int ret;

	if (vpninfo->setup_tun) {
		vpninfo->setup_tun(vpninfo->cbdata);
		if (tun_is_up(vpninfo))
			return 0;
	}

#ifndef _WIN32
	if (vpninfo->use_tun_script) {
		ret = openconnect_setup_tun_script(vpninfo, vpninfo->vpnc_script);
		if (ret) {
			fprintf(stderr, _("Set up tun script failed\n"));
			return ret;
		}
	} else
#endif
	ret = openconnect_setup_tun_device(vpninfo, vpninfo->vpnc_script, vpninfo->ifname);
	if (ret) {
		fprintf(stderr, _("Set up tun device failed\n"));
		return ret;
	}

#if !defined(_WIN32) && !defined(__native_client__)
	if (vpninfo->uid != getuid()) {
		int e;

		if (setgid(vpninfo->gid)) {
			e = errno;
			fprintf(stderr, _("Failed to set gid %ld: %s\n"),
				(long)vpninfo->gid, strerror(e));
			return -EPERM;
		}

		if (setgroups(1, &vpninfo->gid)) {
			e = errno;
			fprintf(stderr, _("Failed to set groups to %ld: %s\n"),
				(long)vpninfo->gid, strerror(e));
			return -EPERM;
		}

		if (setuid(vpninfo->uid)) {
			e = errno;
			fprintf(stderr, _("Failed to set uid %ld: %s\n"),
				(long)vpninfo->uid, strerror(e));
			return -EPERM;
		}
	}
#endif
	return 0;
}

/* Return value:
 *  = 0, when successfully paused (may call again)
 *  = -EINTR, if aborted locally via OC_CMD_CANCEL
 *  = -ECONNABORTED, if aborted locally via OC_CMD_DETACH
 *  = -EPIPE, if the remote end explicitly terminated the session
 *  = -EPERM, if the gateway sent 401 Unauthorized (cookie expired)
 *  < 0, for any other error
 */
int openconnect_mainloop(struct openconnect_info *vpninfo,
			 int reconnect_timeout,
			 int reconnect_interval)
{
	int ret = 0;

	vpninfo->reconnect_timeout = reconnect_timeout;
	vpninfo->reconnect_interval = reconnect_interval;

	if (vpninfo->cmd_fd != -1) {
		monitor_fd_new(vpninfo, cmd);
		monitor_read_fd(vpninfo, cmd);
	}

	while (!vpninfo->quit_reason) {
		int did_work = 0;
		int timeout;
#ifdef _WIN32
		HANDLE events[4];
		int nr_events = 0;
#else
		struct timeval tv;
		fd_set rfds, wfds, efds;
#endif

		/* If tun is not up, loop more often to detect
		 * a DTLS timeout (due to a firewall block) as soon. */
		if (tun_is_up(vpninfo))
			timeout = INT_MAX;
		else
			timeout = 1000;

		if (vpninfo->dtls_state > DTLS_DISABLED) {
			/* Postpone tun device creation after DTLS is connected so
			 * we have a better knowledge of the link MTU. We also
			 * force the creation if DTLS enters sleeping mode - i.e.,
			 * we failed to connect on time. */
			if (!tun_is_up(vpninfo) && (vpninfo->dtls_state == DTLS_CONNECTED ||
			    vpninfo->dtls_state == DTLS_SLEEPING)) {
				ret = setup_tun_device(vpninfo);
				if (ret) {
					break;
				}
			}

			ret = vpninfo->proto->udp_mainloop(vpninfo, &timeout);
			if (vpninfo->quit_reason)
				break;
			did_work += ret;

		} else if (!tun_is_up(vpninfo)) {
			/* No DTLS - setup TUN device unconditionally */
			ret = setup_tun_device(vpninfo);
			if (ret)
				break;
		}

		ret = vpninfo->proto->tcp_mainloop(vpninfo, &timeout);
		if (vpninfo->quit_reason)
			break;
		did_work += ret;

		/* Tun must be last because it will set/clear its bit
		   in the select_rfds according to the queue length */
		did_work += tun_mainloop(vpninfo, &timeout);
		if (vpninfo->quit_reason)
			break;

		poll_cmd_fd(vpninfo, 0);
		if (vpninfo->got_cancel_cmd) {
			if (vpninfo->cancel_type == OC_CMD_CANCEL) {
				vpninfo->quit_reason = "Aborted by caller";
				ret = -EINTR;
			} else {
				ret = -ECONNABORTED;
			}
			vpninfo->got_cancel_cmd = 0;
			break;
		}

		if (vpninfo->got_pause_cmd) {
			/* close all connections and wait for the user to call
			   openconnect_mainloop() again */
			openconnect_close_https(vpninfo, 0);
			if (vpninfo->dtls_state != DTLS_DISABLED) {
				vpninfo->proto->udp_close(vpninfo);
				vpninfo->new_dtls_started = 0;
			}

			vpninfo->got_pause_cmd = 0;
			vpn_progress(vpninfo, PRG_INFO, _("Caller paused the connection\n"));
			return 0;
		}

		if (did_work)
			continue;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("No work to do; sleeping for %d ms...\n"), timeout);

#ifdef _WIN32
		if (vpninfo->dtls_monitored) {
			WSAEventSelect(vpninfo->dtls_fd, vpninfo->dtls_event, vpninfo->dtls_monitored);
			events[nr_events++] = vpninfo->dtls_event;
		}
		if (vpninfo->ssl_monitored) {
			WSAEventSelect(vpninfo->ssl_fd, vpninfo->ssl_event, vpninfo->ssl_monitored);
			events[nr_events++] = vpninfo->ssl_event;
		}
		if (vpninfo->cmd_monitored) {
			WSAEventSelect(vpninfo->cmd_fd, vpninfo->cmd_event, vpninfo->cmd_monitored);
			events[nr_events++] = vpninfo->cmd_event;
		}
		if (vpninfo->tun_monitored) {
			events[nr_events++] = vpninfo->tun_rd_overlap.hEvent;
		}
		if (WaitForMultipleObjects(nr_events, events, FALSE, timeout) == WAIT_FAILED) {
			char *errstr = openconnect__win32_strerror(GetLastError());
			vpn_progress(vpninfo, PRG_ERR,
				     _("WaitForMultipleObjects failed: %s\n"),
				     errstr);
			free(errstr);
		}
#else
		memcpy(&rfds, &vpninfo->_select_rfds, sizeof(rfds));
		memcpy(&wfds, &vpninfo->_select_wfds, sizeof(wfds));
		memcpy(&efds, &vpninfo->_select_efds, sizeof(efds));

		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;

		select(vpninfo->_select_nfds, &rfds, &wfds, &efds, &tv);
#endif
	}

	if (vpninfo->quit_reason && vpninfo->proto->vpn_close_session)
		vpninfo->proto->vpn_close_session(vpninfo, vpninfo->quit_reason);

	if (tun_is_up(vpninfo))
		os_shutdown_tun(vpninfo);
	return ret < 0 ? ret : -EIO;
}

static int ka_check_deadline(int *timeout, time_t now, time_t due)
{
	if (now >= due)
		return 1;
	if (*timeout > (due - now) * 1000)
		*timeout = (due - now) * 1000;
	return 0;
}

/* Called when the socket is unwritable, to get the deadline for DPD.
   Returns 1 if DPD deadline has already arrived. */
int ka_stalled_action(struct keepalive_info *ka, int *timeout)
{
	time_t now = time(NULL);

	/* We only support the new-tunnel rekey method for now. */
	if (ka->rekey_method != REKEY_NONE &&
	    ka_check_deadline(timeout, now, ka->last_rekey + ka->rekey)) {
		ka->last_rekey = now;
		return KA_REKEY;
	}

	if (ka->dpd &&
	    ka_check_deadline(timeout, now, ka->last_rx + (2 * ka->dpd)))
		return KA_DPD_DEAD;

	return KA_NONE;
}


int keepalive_action(struct keepalive_info *ka, int *timeout)
{
	time_t now = time(NULL);

	if (ka->rekey_method != REKEY_NONE &&
	    ka_check_deadline(timeout, now, ka->last_rekey + ka->rekey)) {
		ka->last_rekey = now;
		return KA_REKEY;
	}

	/* DPD is bidirectional -- PKT 3 out, PKT 4 back */
	if (ka->dpd) {
		time_t due = ka->last_rx + ka->dpd;
		time_t overdue = ka->last_rx + (2 * ka->dpd);

		/* Peer didn't respond */
		if (now > overdue)
			return KA_DPD_DEAD;

		/* If we already have DPD outstanding, don't flood. Repeat by
		   all means, but only after half the DPD period. */
		if (ka->last_dpd > ka->last_rx)
			due = ka->last_dpd + ka->dpd / 2;

		/* We haven't seen a packet from this host for $DPD seconds.
		   Prod it to see if it's still alive */
		if (ka_check_deadline(timeout, now, due)) {
			ka->last_dpd = now;
			return KA_DPD;
		}
	}

	/* Keepalive is just client -> server.
	   If we haven't sent anything for $KEEPALIVE seconds, send a
	   dummy packet (which the server will discard) */
	if (ka->keepalive &&
	    ka_check_deadline(timeout, now, ka->last_tx + ka->keepalive))
		return KA_KEEPALIVE;

	return KA_NONE;
}
