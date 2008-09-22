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

#include "anyconnect.h"

/*
 * The master-secret is generated randomly by the client. The server
 * responds with a DTLS Session-ID. These, done over the HTTPS
 * connection, are enough to 'resume' a DTLS session, bypassing all
 * the normal setup of a normal DTLS connection.
 * 
 * Cisco's own client uses an old version of OpenSSL, which implements
 * the pre-RFC version of DTLS. I haven't been able to get it working 
 * when I force it to link against any of my own builds of OpenSSL.
 *
 * Hopefully, it'll just work when I get round to implementing it
 * here, either with the system OpenSSL, or linking against their
 * library (which will at least be progress, and make it a little
 * easier to debug.
 */   


int setup_dtls(struct anyconnect_info *vpninfo)
{
	struct vpn_option *dtls_opt = vpninfo->dtls_options;

	while (dtls_opt) {
		printf("DTLS option %s : %s\n", dtls_opt->option, dtls_opt->value);
		dtls_opt = dtls_opt->next;
	}
	/* No idea how to do this yet */
	return -EINVAL;
}

int dtls_mainloop(struct anyconnect_info *vpninfo, int *timeout)
{
	return 0;
}


