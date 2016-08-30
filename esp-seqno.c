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
#include <stdlib.h>
#include <errno.h>

#include "openconnect-internal.h"

/* Eventually we're going to have to have more than one incoming ESP
   context at a time, to allow for the overlap period during a rekey.
   So pass the 'esp' even though for now it's redundant. */
int verify_packet_seqno(struct openconnect_info *vpninfo,
			struct esp *esp, uint32_t seq)
{
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
		esp->seq++;
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Accepting expected ESP packet with seq %u\n"),
			     seq);
		return 0;
	} else if (esp->seq > 65 && seq < esp->seq - 65) {
		/* Too old. We can't know if it's a replay. */
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Discarding ancient ESP packet with seq %u (expected %u)\n"),
			     seq, esp->seq);
		return -EINVAL;
	} else if (seq < esp->seq) {
		/* Within the backlog window, so we remember whether we've seen it or not. */
		uint64_t mask = 1ULL << (esp->seq - seq - 2);

		if (esp->seq_backlog & mask) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Accepting out-of-order ESP packet with seq %u (expected %u)\n"),
				     seq, esp->seq);
			esp->seq_backlog &= ~mask;
			return 0;
		}
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Discarding replayed ESP packet with seq %u\n"),
			     seq);
		return -EINVAL;
	} else {
		/* The packet we were expecting has gone missing; this one is newer. */
		uint64_t delta = seq - esp->seq;

		if (delta >= 64) {
			/* We jumped a long way into the future. We have not seen
			 * any of the previous 32 packets so set the backlog bitmap
			 * to all ones. */
			esp->seq_backlog = 0xffffffffffffffffULL;
		} else if (delta == 63) {
			/* Avoid undefined behaviour that shifting by 64 would incur.
			 * The (clear) top bit represents the packet which is currently
			 * esp->seq - 1, which we know was already received. */
			esp->seq_backlog = 0x7fffffffffffffffULL;
		} else {
			/* We have missed (delta) packets. Shift the backlog by that
			 * amount *plus* the one we would have shifted it anyway if
			 * we'd received the packet we were expecting. The zero bit
			 * representing the packet which is currently esp->seq - 1,
			 * which we know has been received, ends up at bit position
			 * (1<<delta). Then we set all the bits lower than that, which
			 * represent the missing packets. */
			esp->seq_backlog <<= delta + 1;
			esp->seq_backlog |= (1ULL<<delta) - 1;
		}
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Accepting later-than-expected ESP packet with seq %u (expected %u)\n"),
			     seq, esp->seq);
		esp->seq = seq + 1;
		return 0;
	}
}

