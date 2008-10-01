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

#include <ne_session.h>
#include <ne_uri.h>
#include <ne_basic.h>
#include <ne_utils.h>
#include <ne_ssl.h>

#include "anyconnect.h"

int obtain_cookie_cert(struct anyconnect_info *vpninfo)

{
	char bodybuf[16384];
	ne_session *sess;
	ne_request *rq;
	ne_ssl_certificate *cacert = NULL, *clientcert;
	int ret;
	ne_sock_init();

	if (vpninfo->cafile)
		cacert = ne_ssl_cert_read(vpninfo->cafile);
	if (vpninfo->cert) {
		clientcert = ne_ssl_cert_read(vpninfo->cert);
	}
	sess = ne_session_create("https", vpninfo->hostname, 443);
	if (cacert) {
		ne_ssl_trust_cert(sess, cacert);
		ne_ssl_cert_free(cacert);
	}
	rq = ne_request_create(sess, "GET", "/");
	ne_add_request_header(rq, "X-Transcend-Version", "1");
	printf("Attempt dispatch\n");
	ret = ne_request_dispatch(rq);
	if (ret) {
		printf("dispatch returned %d\n", ret);
		if (ret == 1)
			printf("err: %s\n", ne_get_error(sess));

	}
	printf("done\n");
	return -1;

	
}
