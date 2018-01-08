/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2016 Intel Corporation.
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
#include <stdio.h>

#define __OPENCONNECT_INTERNAL_H__

#define vpn_progress(v, d, ...) printf(__VA_ARGS__)
#define _(x) x

struct openconnect_info {
	int esp_replay_protect;
};

struct esp {
	uint64_t seq_backlog;
	uint64_t seq;
};

#include "../esp-seqno.c"


int main(void)
{
	struct esp esptest = { 0, 0 };
	struct openconnect_info vpninfo = { 1};

	if ( verify_packet_seqno(&vpninfo, &esptest, 0) ||
	     verify_packet_seqno(&vpninfo, &esptest, 2) ||
	     verify_packet_seqno(&vpninfo, &esptest, 1) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 0) ||
	     verify_packet_seqno(&vpninfo, &esptest, 64) ||
	     verify_packet_seqno(&vpninfo, &esptest, 65) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 65) ||
	     verify_packet_seqno(&vpninfo, &esptest, 66) ||
	     verify_packet_seqno(&vpninfo, &esptest, 67) ||
	     verify_packet_seqno(&vpninfo, &esptest, 68) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 68) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 2) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 3) ||
	     verify_packet_seqno(&vpninfo, &esptest, 4) ||
	     verify_packet_seqno(&vpninfo, &esptest, 164) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 99) ||
	     verify_packet_seqno(&vpninfo, &esptest, 100) ||
	     verify_packet_seqno(&vpninfo, &esptest, 200) ||
	     verify_packet_seqno(&vpninfo, &esptest, 264) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 199) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 200) ||
	     verify_packet_seqno(&vpninfo, &esptest, 265) ||
	     verify_packet_seqno(&vpninfo, &esptest, 210) ||
	     verify_packet_seqno(&vpninfo, &esptest, 201) ||
	     verify_packet_seqno(&vpninfo, &esptest, 270) ||
	     verify_packet_seqno(&vpninfo, &esptest, 206) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 210) ||
	     verify_packet_seqno(&vpninfo, &esptest, 333) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 268) ||
	     verify_packet_seqno(&vpninfo, &esptest, 269) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 270) ||
	     verify_packet_seqno(&vpninfo, &esptest, 0xfffffffd) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 1) ||
	     verify_packet_seqno(&vpninfo, &esptest, 0xffffffc1) ||
	     verify_packet_seqno(&vpninfo, &esptest, 0xfffffffc) ||
	     verify_packet_seqno(&vpninfo, &esptest, 0xffffffff) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 0) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 0xffffffbe) ||
	     verify_packet_seqno(&vpninfo, &esptest, 0xffffffbf) ||
	    !verify_packet_seqno(&vpninfo, &esptest, 0xffffffc1) ||
	     verify_packet_seqno(&vpninfo, &esptest, 0xffffffc0))
		return 1;

	return 0;
}
