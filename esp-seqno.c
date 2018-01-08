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

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>

#include "openconnect-internal.h"

#define DTLS_EMPTY_BITMAP		(0xFFFFFFFFFFFFFFFFULL)

/* Eventually we're going to have to have more than one incoming ESP
   context at a time, to allow for the overlap period during a rekey.
   So pass the 'esp' even though for now it's redundant. */
int verify_packet_seqno(struct openconnect_info *vpninfo,
			struct esp *esp, uint32_t seq)
{
	int err_val = -EINVAL;
	const char *discard_verb = "Discarding";

	if (!vpninfo->esp_replay_protect) {
		err_val = 0;
		discard_verb = "Tolerating";
	}

	/*
	 * For incoming, esp->seq is the next *expected* packet, being
	 * the sequence number *after* the latest we have received.
	 *
	 * Since it must always be true that packet esp->seq-1 has been
	 * received, so there's no need to explicitly record that.
	 *
	 * So the backlog bitmap covers the 64 packets prior to that,
	 * with the LSB representing packet (esp->seq - 2), and the MSB
	 * representing (esp->seq - 65). A received packet is represented
	 * by a zero bit, and a missing packet is represented by a one.
	 *
	 * Thus we can allow out-of-order reception of packets that are
	 * within a reasonable interval of the latest packet received.
	 */

	if (seq == esp->seq) {
		/* The common case. This is the packet we expected next. */
		esp->seq_backlog <<= 1;

		/* This might reach a value higher than the 32-bit ESP sequence
		 * numbers can actually reach. Which is fine. When that
		 * happens, we'll do the right thing and just not accept any
		 * newer packets. Someone needs to start a new epoch. */
		esp->seq++;
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Accepting expected ESP packet with seq %u\n"),
			     seq);
		return 0;
	} else if (seq > esp->seq) {
		/* The packet we were expecting has gone missing; this one is newer.
		 * We always advance the window to accommodate it. */
		uint32_t delta = seq - esp->seq;

		if (delta >= 64) {
			/* We jumped a long way into the future. We have not seen
			 * any of the previous 32 packets so set the backlog bitmap
			 * to all ones. */
			esp->seq_backlog = DTLS_EMPTY_BITMAP;
		} else if (delta == 63) {
			/* Avoid undefined behaviour that shifting by 64 would incur.
			 * The (clear) top bit represents the packet which is currently
			 * esp->seq - 1, which we know was already received. */
			esp->seq_backlog = DTLS_EMPTY_BITMAP >> 1;
		} else {
			/* We have missed (delta) packets. Shift the backlog by that
			 * amount *plus* the one we would have shifted it anyway if
			 * we'd received the packet we were expecting. The zero bit
			 * representing the packet which is currently esp->seq - 1,
			 * which we know has been received, ends up at bit position
			 * (1<<delta). Then we set all the bits lower than that, which
			 * represent the missing packets. */
			esp->seq_backlog <<= delta + 1;
			esp->seq_backlog |= (1ULL << delta) - 1;
		}
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Accepting later-than-expected ESP packet with seq %u (expected %" PRIu64 ")\n"),
			     seq, esp->seq);
		esp->seq = (uint64_t)seq + 1;
		return 0;
	} else {
		/* This packet is older than the one we were expecting. By how much...? */
		uint32_t delta = esp->seq - seq;

		/* delta==0 is the overflow case where esp->seq is 0x100000000 and seq is 0 */
		if (delta > 65 || delta == 0) {
			/* Too old. We can't know if it's a replay. */
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("%s ancient ESP packet with seq %u (expected %" PRIu64 ")\n"),
				     discard_verb, seq, esp->seq);
			return err_val;
		} else if (delta == 1) {
			/* Not in the bitmask since it is by definition already received. */
		replayed:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("%s replayed ESP packet with seq %u\n"),
				     discard_verb, seq);
			return err_val;
		} else {
			/* Within the backlog window, so we remember whether we've seen it or not. */
			uint64_t mask = 1ULL << (delta - 2);

			if (!(esp->seq_backlog & mask))
				goto replayed;

			esp->seq_backlog &= ~mask;
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Accepting out-of-order ESP packet with seq %u (expected %" PRIu64 ")\n"),
				     seq, esp->seq);
			return 0;
		}
	}
}

