/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Author: Daniel Lenski <dlenski@gmail.com>
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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif
#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#if defined(__linux__)
/* For TCP_INFO */
# include <linux/tcp.h>
#endif

#include <assert.h>

#include "openconnect-internal.h"

/*
 * Data packets are encapsulated in the SSL stream as follows:
 *
 * 0000: Magic "\x1a\x2b\x3c\x4d"
 * 0004: Big-endian EtherType (0x0800 for IPv4)
 * 0006: Big-endian 16-bit length (not including 16-byte header)
 * 0008: Always "\x01\0\0\0\0\0\0\0"
 * 0010: data payload
 */

/* Strange initialisers here to work around GCC PR#10676 (which was
 * fixed in GCC 4.6 but it takes a while for some systems to catch
 * up. */
static const struct pkt dpd_pkt = {
	.next = NULL,
	{ .gpst.hdr = { 0x1a, 0x2b, 0x3c, 0x4d } }
};

/* similar to auth.c's xmlnode_get_text, except that *var should be freed by the caller */
static int xmlnode_get_text(xmlNode *xml_node, const char *name, const char **var)
{
	const char *str;

	if (name && !xmlnode_is_named(xml_node, name))
		return -EINVAL;

	str = (const char *)xmlNodeGetContent(xml_node);
	if (!str)
		return -ENOENT;

	*var = str;
	return 0;
}

/* We behave like CSTP — create a linked list in vpninfo->cstp_options
 * with the strings containing the information we got from the server,
 * and oc_ip_info contains const copies of those pointers.
 *
 * (unlike version in oncp.c, val is stolen rather than strdup'ed) */

static const char *add_option(struct openconnect_info *vpninfo, const char *opt, const char *val)
{
	struct oc_vpn_option *new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->option = strdup(opt);
	if (!new->option) {
		free(new);
		return NULL;
	}
	new->value = val;
	new->next = vpninfo->cstp_options;
	vpninfo->cstp_options = new;

	return new->value;
}


static int filter_opts(struct oc_text_buf *buf, const char *query, const char *incexc, int include)
{
	const char *f, *endf, *eq;
	const char *found, *comma;

	for (f = query; *f; f=(*endf) ? endf+1 : endf) {
		endf = strchr(f, '&') ? : f+strlen(f);
		eq = strchr(f, '=');
		if (!eq || eq > endf)
			eq = endf;

		for (found = incexc; *found; found=(*comma) ? comma+1 : comma) {
			comma = strchr(found, ',') ? : found+strlen(found);
			if (!strncmp(found, f, MAX(comma-found, eq-f)))
				break;
		}

		if ((include && *found) || (!include && !*found)) {
			if (buf->pos && buf->data[buf->pos-1] != '?' && buf->data[buf->pos-1] != '&')
				buf_append(buf, "&");
			buf_append_bytes(buf, f, (int)(endf-f));
		}
	}
	return buf_error(buf);
}

/* Parse this JavaScript-y mess:

	"var respStatus = \"Challenge|Error\";\n"
	"var respMsg = \"<prompt>\";\n"
	"thisForm.inputStr.value = "<inputStr>";\n"
*/
static int parse_javascript(char *buf, char **prompt, char **inputStr)
{
	const char *start, *end = buf;
	int status;

	const char *pre_status = "var respStatus = \"",
	           *pre_prompt = "var respMsg = \"",
	           *pre_inputStr = "thisForm.inputStr.value = \"";

	/* Status */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_status, strlen(pre_status)))
		goto err;

	start = end+strlen(pre_status);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"')
		goto err;

	if (!strncmp(start, "Challenge", 8))    status = 0;
	else if (!strncmp(start, "Error", 5))   status = 1;
	else                                    goto err;

	/* Prompt */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_prompt, strlen(pre_prompt)))
		goto err;

	start = end+strlen(pre_prompt);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"')
		goto err;

	if (prompt)
		*prompt = strndup(start, end-start-2);

	/* inputStr */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_inputStr, strlen(pre_inputStr)))
		goto err2;

	start = end+strlen(pre_inputStr);
	end = strchr(start, '\n');
	if (!end || end[-1] != ';' || end[-2] != '"')
		goto err2;

	if (inputStr)
		*inputStr = strndup(start, end-start-2);

	while (isspace(*end))
		end++;
	if (*end != '\0')
		goto err3;

	return status;

err3:
	if (inputStr) free((void *)*inputStr);
err2:
	if (prompt) free((void *)*prompt);
err:
	return -EINVAL;
}

int gpst_xml_or_error(struct openconnect_info *vpninfo, int result, char *response,
					  int (*xml_cb)(struct openconnect_info *, xmlNode *xml_node),
					  char **prompt, char **inputStr)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	const char *err = NULL;

	/* custom error codes returned by /ssl-vpn/login.esp and maybe others */
	if (result == -EACCES)
		vpn_progress(vpninfo, PRG_ERR, _("Invalid username or password.\n"));
	else if (result == -EBADMSG)
		vpn_progress(vpninfo, PRG_ERR, _("Invalid client certificate.\n"));

	if (result < 0)
		return result;

	if (!response) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	/* is it XML? */
	xml_doc = xmlReadMemory(response, strlen(response), "noname.xml", NULL,
				XML_PARSE_NOERROR);
	if (!xml_doc) {
		/* is it Javascript? */
		char *p, *i;
		result = parse_javascript(response, &p, &i);
		switch (result) {
		case 1:
			vpn_progress(vpninfo, PRG_ERR, _("%s\n"), p);
			break;
		case 0:
			vpn_progress(vpninfo, PRG_INFO, _("Challenge: %s\n"), p);
			if (prompt && inputStr) {
				*prompt=p;
				*inputStr=i;
				return -EAGAIN;
			}
			break;
		default:
			goto bad_xml;
		}
		free((char *)p);
		free((char *)i);
		goto out;
	}

	xml_node = xmlDocGetRootElement(xml_doc);

	/* is it <response status="error"><error>..</error></response> ? */
	if (xmlnode_is_named(xml_node, "response")
	    && !xmlnode_match_prop(xml_node, "status", "error")) {
		for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
			if (!xmlnode_get_text(xml_node, "error", &err))
				goto out;
		}
		goto bad_xml;
	}

	if (xml_cb)
		result = xml_cb(vpninfo, xml_node);

	if (result == -EINVAL) {
	bad_xml:
		vpn_progress(vpninfo, PRG_ERR,
					 _("Failed to parse server response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Response was:%s\n"), response);
	}

out:
	if (err) {
		if (!strcmp(err, "GlobalProtect gateway does not exist")
		    || !strcmp(err, "GlobalProtect portal does not exist")) {
			vpn_progress(vpninfo, PRG_DEBUG, "%s\n", err);
			result = -EEXIST;
		} else if (!strcmp(err, "Invalid authentication cookie")) {
			vpn_progress(vpninfo, PRG_ERR, "%s\n", err);
			result = -EPERM;
		} else {
			vpn_progress(vpninfo, PRG_ERR, "%s\n", err);
			result = -EINVAL;
		}
		free((void *)err);
	}
	if (xml_doc)
		xmlFreeDoc(xml_doc);
	return result;
}


#define ESP_HEADER_SIZE (4 /* SPI */ + 4 /* sequence number */)
#define ESP_FOOTER_SIZE (1 /* pad length */ + 1 /* next header */)
#define UDP_HEADER_SIZE 8
#define TCP_HEADER_SIZE 20 /* with no options */
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40

/* Based on cstp.c's calculate_mtu().
 *
 * With HTTPS tunnel, there are 21 bytes of overhead beyond the
 * TCP MSS: 5 bytes for TLS and 16 for GPST.
 */
static int calculate_mtu(struct openconnect_info *vpninfo, int can_use_esp)
{
	int mtu = vpninfo->reqmtu, base_mtu = vpninfo->basemtu;
	int mss = 0;

#if defined(__linux__) && defined(TCP_INFO)
	if (!mtu) {
		struct tcp_info ti;
		socklen_t ti_size = sizeof(ti);

		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_INFO,
				&ti, &ti_size)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("TCP_INFO rcv mss %d, snd mss %d, adv mss %d, pmtu %d\n"),
				     ti.tcpi_rcv_mss, ti.tcpi_snd_mss, ti.tcpi_advmss, ti.tcpi_pmtu);

			if (!base_mtu) {
				base_mtu = ti.tcpi_pmtu;
			}

			/* XXX: GlobalProtect has no mechanism to inform the server about the
			 * desired MTU, so could just ignore the "incoming" MSS (tcpi_rcv_mss).
			 */
			mss = MIN(ti.tcpi_rcv_mss, ti.tcpi_snd_mss);
		}
	}
#endif
#ifdef TCP_MAXSEG
	if (!mtu && !mss) {
		socklen_t mss_size = sizeof(mss);
		if (!getsockopt(vpninfo->ssl_fd, IPPROTO_TCP, TCP_MAXSEG,
				&mss, &mss_size)) {
			vpn_progress(vpninfo, PRG_DEBUG, _("TCP_MAXSEG %d\n"), mss);
		}
	}
#endif
	if (!base_mtu) {
		/* Default */
		base_mtu = 1406;
	}

	if (base_mtu < 1280)
		base_mtu = 1280;

#ifdef HAVE_ESP
	/* If we can use the ESP tunnel then we should pick the optimal MTU for ESP. */
	if (!mtu && can_use_esp) {
		/* remove ESP, UDP, IP headers from base (wire) MTU */
		mtu = ( base_mtu - UDP_HEADER_SIZE - ESP_HEADER_SIZE
		        - 12 /* both supported algos (SHA1 and MD5) have 96-bit MAC lengths (RFC2403 and RFC2404) */
		        - (vpninfo->enc_key_len ? : 32) /* biggest supported IV (AES-256) */ );
		if (vpninfo->peer_addr->sa_family == AF_INET6)
			mtu -= IPV6_HEADER_SIZE;
		else
			mtu -= IPV4_HEADER_SIZE;
		/* round down to a multiple of blocksize */
		mtu -= mtu % (vpninfo->enc_key_len ? : 32);
		/* subtract ESP footer, which is included in the payload before padding to the blocksize */
		mtu -= ESP_FOOTER_SIZE;

	} else
#endif

    /* We are definitely using the TLS tunnel, so we should base our MTU on the TCP MSS. */
	if (!mtu) {
		if (mss)
			mtu = mss - 21;
		else {
			mtu = base_mtu - TCP_HEADER_SIZE - 21;
			if (vpninfo->peer_addr->sa_family == AF_INET6)
				mtu -= IPV6_HEADER_SIZE;
			else
				mtu -= IPV4_HEADER_SIZE;
		}
	}
	return mtu;
}

#ifdef HAVE_ESP
static int set_esp_algo(struct openconnect_info *vpninfo, const char *s, int hmac)
{
	if (hmac) {
		if (!strcmp(s, "sha1"))		{ vpninfo->esp_hmac = HMAC_SHA1; vpninfo->hmac_key_len = 20; return 0; }
		if (!strcmp(s, "md5"))		{ vpninfo->esp_hmac = HMAC_MD5;  vpninfo->hmac_key_len = 16; return 0; }
	} else {
		if (!strcmp(s, "aes128") || !strcmp(s, "aes-128-cbc"))
		                                { vpninfo->esp_enc = ENC_AES_128_CBC; vpninfo->enc_key_len = 16; return 0; }
		if (!strcmp(s, "aes-256-cbc"))	{ vpninfo->esp_enc = ENC_AES_256_CBC; vpninfo->enc_key_len = 32; return 0; }
	}
	vpn_progress(vpninfo, PRG_ERR, _("Unknown ESP %s algorithm: %s"), hmac ? "MAC" : "encryption", s);
	return -ENOENT;
}

static int get_key_bits(xmlNode *xml_node, unsigned char *dest)
{
	int bits = -1;
	xmlNode *child;
	const char *s, *p;

	for (child = xml_node->children; child; child=child->next) {
		if (xmlnode_get_text(child, "bits", &s) == 0) {
			bits = atoi(s);
			free((void *)s);
		} else if (xmlnode_get_text(child, "val", &s) == 0) {
			for (p=s; *p && *(p+1) && (bits-=8)>=0; p+=2)
				*dest++ = unhex(p);
			free((void *)s);
		}
	}
	return (bits == 0) ? 0 : -EINVAL;
}
#endif

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int gpst_parse_config_xml(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	xmlNode *member;
	const char *s;
	int ii;

	if (!xml_node || !xmlnode_is_named(xml_node, "response"))
		return -EINVAL;

	/* Clear old options which will be overwritten */
	vpninfo->ip_info.addr = vpninfo->ip_info.netmask = NULL;
	vpninfo->ip_info.addr6 = vpninfo->ip_info.netmask6 = NULL;
	vpninfo->ip_info.domain = NULL;
	vpninfo->ip_info.mtu = 0;
	vpninfo->esp_magic = inet_addr(vpninfo->ip_info.gateway_addr);
	vpninfo->esp_replay_protect = 1;
	vpninfo->ssl_times.rekey_method = REKEY_NONE;
	vpninfo->cstp_options = NULL;

	for (ii = 0; ii < 3; ii++)
		vpninfo->ip_info.dns[ii] = vpninfo->ip_info.nbns[ii] = NULL;
	free_split_routes(vpninfo);

	/* Parse config */
	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		if (!xmlnode_get_text(xml_node, "ip-address", &s))
			vpninfo->ip_info.addr = add_option(vpninfo, "ipaddr", s);
		else if (!xmlnode_get_text(xml_node, "netmask", &s))
			vpninfo->ip_info.netmask = add_option(vpninfo, "netmask", s);
		else if (!xmlnode_get_text(xml_node, "mtu", &s)) {
			vpninfo->ip_info.mtu = atoi(s);
			free((void *)s);
		} else if (!xmlnode_get_text(xml_node, "ssl-tunnel-url", &s)) {
			free(vpninfo->urlpath);
			vpninfo->urlpath = (char *)s;
			if (strcmp(s, "/ssl-tunnel-connect.sslvpn"))
				vpn_progress(vpninfo, PRG_INFO, _("Non-standard SSL tunnel path: %s\n"), s);
		} else if (!xmlnode_get_text(xml_node, "timeout", &s)) {
			int sec = atoi(s);
			vpn_progress(vpninfo, PRG_INFO, _("Tunnel timeout (rekey interval) is %d minutes.\n"), sec/60);
			vpninfo->ssl_times.last_rekey = time(NULL);
			vpninfo->ssl_times.rekey = sec - 60;
			vpninfo->ssl_times.rekey_method = REKEY_TUNNEL;
			free((void *)s);
		} else if (!xmlnode_get_text(xml_node, "gw-address", &s)) {
			/* As remarked in oncp.c, "this is a tunnel; having a
			 * gateway is meaningless." See esp_send_probes_gp for the
			 * gory details of what this field actually means.
			 */
			if (strcmp(s, vpninfo->ip_info.gateway_addr))
				vpn_progress(vpninfo, PRG_DEBUG,
							 _("Gateway address in config XML (%s) differs from external gateway address (%s).\n"), s, vpninfo->ip_info.gateway_addr);
			vpninfo->esp_magic = inet_addr(s);
			free((void *)s);
		} else if (xmlnode_is_named(xml_node, "dns")) {
			for (ii=0, member = xml_node->children; member && ii<3; member=member->next)
				if (!xmlnode_get_text(member, "member", &s))
					vpninfo->ip_info.dns[ii++] = add_option(vpninfo, "DNS", s);
		} else if (xmlnode_is_named(xml_node, "wins")) {
			for (ii=0, member = xml_node->children; member && ii<3; member=member->next)
				if (!xmlnode_get_text(member, "member", &s))
					vpninfo->ip_info.nbns[ii++] = add_option(vpninfo, "WINS", s);
		} else if (xmlnode_is_named(xml_node, "dns-suffix")) {
			for (ii=0, member = xml_node->children; member && ii<1; member=member->next)
				if (!xmlnode_get_text(member, "member", &s)) {
					vpninfo->ip_info.domain = add_option(vpninfo, "search", s);
					ii++;
				}
		} else if (xmlnode_is_named(xml_node, "access-routes")) {
			for (member = xml_node->children; member; member=member->next) {
				if (!xmlnode_get_text(member, "member", &s)) {
					struct oc_split_include *inc = malloc(sizeof(*inc));
					if (!inc)
						continue;
					inc->route = add_option(vpninfo, "split-include", s);
					inc->next = vpninfo->ip_info.split_includes;
					vpninfo->ip_info.split_includes = inc;
				}
			}
		} else if (xmlnode_is_named(xml_node, "ipsec")) {
#ifdef HAVE_ESP
			if (vpninfo->dtls_state != DTLS_DISABLED) {
				int c = (vpninfo->current_esp_in ^= 1);
				vpninfo->old_esp_maxseq = vpninfo->esp_in[c^1].seq + 32;
				for (member = xml_node->children; member; member=member->next) {
					s = NULL;
					if (!xmlnode_get_text(member, "udp-port", &s))		udp_sockaddr(vpninfo, atoi(s));
					else if (!xmlnode_get_text(member, "enc-algo", &s)) 	set_esp_algo(vpninfo, s, 0);
					else if (!xmlnode_get_text(member, "hmac-algo", &s))	set_esp_algo(vpninfo, s, 1);
					else if (!xmlnode_get_text(member, "c2s-spi", &s))	vpninfo->esp_out.spi = htonl(strtoul(s, NULL, 16));
					else if (!xmlnode_get_text(member, "s2c-spi", &s))	vpninfo->esp_in[c].spi = htonl(strtoul(s, NULL, 16));
					else if (xmlnode_is_named(member, "ekey-c2s"))		get_key_bits(member, vpninfo->esp_out.enc_key);
					else if (xmlnode_is_named(member, "ekey-s2c"))		get_key_bits(member, vpninfo->esp_in[c].enc_key);
					else if (xmlnode_is_named(member, "akey-c2s"))		get_key_bits(member, vpninfo->esp_out.hmac_key);
					else if (xmlnode_is_named(member, "akey-s2c"))		get_key_bits(member, vpninfo->esp_in[c].hmac_key);
					else if (!xmlnode_get_text(member, "ipsec-mode", &s) && strcmp(s, "esp-tunnel"))
						vpn_progress(vpninfo, PRG_ERR, _("GlobalProtect config sent ipsec-mode=%s (expected esp-tunnel)\n"), s);
					free((void *)s);
				}
				if (setup_esp_keys(vpninfo, 0))
					vpn_progress(vpninfo, PRG_ERR, "Failed to setup ESP keys.\n");
				else
					/* prevent race condition between esp_mainloop() and gpst_mainloop() timers */
					vpninfo->dtls_times.last_rekey = time(&vpninfo->new_dtls_started);
			}
#else
			vpn_progress(vpninfo, PRG_DEBUG, _("Ignoring ESP keys since ESP support not available in this build\n"));
#endif
		}
	}

	/* No IPv6 support for SSL VPN:
	 * https://live.paloaltonetworks.com/t5/Learning-Articles/IPv6-Support-on-the-Palo-Alto-Networks-Firewall/ta-p/52994 */
	openconnect_disable_ipv6(vpninfo);

	/* Set 10-second DPD/keepalive (same as Windows client) unless
	 * overridden with --force-dpd */
	if (!vpninfo->ssl_times.dpd)
		vpninfo->ssl_times.dpd = 10;
	vpninfo->ssl_times.keepalive = vpninfo->esp_ssl_fallback = vpninfo->ssl_times.dpd;

	return 0;
}

static int gpst_get_config(struct openconnect_info *vpninfo)
{
	char *orig_path;
	int result;
	struct oc_text_buf *request_body = buf_alloc();
	struct oc_vpn_option *old_cstp_opts = vpninfo->cstp_options;
	const char *old_addr = vpninfo->ip_info.addr, *old_netmask = vpninfo->ip_info.netmask;
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL;

	/* submit getconfig request */
	buf_append(request_body, "client-type=1&protocol-version=p1&app-version=3.0.1-10");
	append_opt(request_body, "os-version", vpninfo->platname);
	if (!strcmp(vpninfo->platname, "win"))
		append_opt(request_body, "clientos", "Windows");
	else
		append_opt(request_body, "clientos", vpninfo->platname);
	append_opt(request_body, "hmac-algo", "sha1,md5");
	append_opt(request_body, "enc-algo", "aes-128-cbc,aes-256-cbc");
	if (old_addr) {
		append_opt(request_body, "preferred-ip", old_addr);
		filter_opts(request_body, vpninfo->cookie, "preferred-ip", 0);
	} else
		buf_append(request_body, "&%s", vpninfo->cookie);
	if ((result = buf_error(request_body)))
		goto out;

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("ssl-vpn/getconfig.esp");
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	if (result < 0)
		goto out;

	/* parse getconfig result */
	result = gpst_xml_or_error(vpninfo, result, xml_buf, gpst_parse_config_xml, NULL, NULL);
	if (result)
		return result;

	if (!vpninfo->ip_info.mtu) {
		/* FIXME: GP gateway config always seems to be <mtu>0</mtu> */
		char *no_esp_reason = NULL;
#ifdef HAVE_ESP
		if (vpninfo->dtls_state == DTLS_DISABLED)
			no_esp_reason = _("ESP disabled");
		else if (vpninfo->dtls_state == DTLS_NOSECRET)
			no_esp_reason = _("No ESP keys received");
#else
		no_esp_reason = _("ESP support not available in this build");
#endif
		vpninfo->ip_info.mtu = calculate_mtu(vpninfo, !no_esp_reason);
		vpn_progress(vpninfo, PRG_ERR,
			     _("No MTU received. Calculated %d for %s%s\n"), vpninfo->ip_info.mtu,
			     no_esp_reason ? "TLS tunnel. " : "ESP tunnel", no_esp_reason ? : "");
		/* return -EINVAL; */
	}
	if (!vpninfo->ip_info.addr) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No IP address received. Aborting\n"));
		result = -EINVAL;
		goto out;
	}
	if (old_addr) {
		/* XXX: if --request-ip option is used, we'll have old_addr!=NULL even on the
		   first connection attempt, but if old_netmask is also non-NULL then we know
		   it's a reconnect. */
		if (strcmp(old_addr, vpninfo->ip_info.addr)) {
			if (!old_netmask)
				vpn_progress(vpninfo, PRG_ERR,
							 _("Legacy IP address %s was requested, but server provided %s\n"),
							 old_addr, vpninfo->ip_info.addr);
			else {
				vpn_progress(vpninfo, PRG_ERR,
							 _("Reconnect gave different Legacy IP address (%s != %s)\n"),
							 vpninfo->ip_info.addr, old_addr);
				result = -EINVAL;
				goto out;
			}
		}
	}
	if (old_netmask) {
		if (strcmp(old_netmask, vpninfo->ip_info.netmask)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP netmask (%s != %s)\n"),
				     vpninfo->ip_info.netmask, old_netmask);
			result = -EINVAL;
			goto out;
		}
	}

out:
	buf_free(request_body);
	free_optlist(old_cstp_opts);
	free(xml_buf);
	return result;
}

static int gpst_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	const char start_tunnel[12] = "START_TUNNEL"; /* NOT zero-terminated */
	char buf[256];

	/* Connect to SSL VPN tunnel */
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Connecting to HTTPS tunnel endpoint ...\n"));

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET %s?", vpninfo->urlpath);
	filter_opts(reqbuf, vpninfo->cookie, "user,authcookie", 1);
	buf_append(reqbuf, " HTTP/1.1\r\n\r\n");
	if ((ret = buf_error(reqbuf)))
		goto out;

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);

	if ((ret = vpninfo->ssl_read(vpninfo, buf, 12)) < 0) {
		if (ret == -EINTR)
			goto out;
		vpn_progress(vpninfo, PRG_ERR,
		             _("Error fetching GET-tunnel HTTPS response.\n"));
		ret = -EINVAL;
		goto out;
	}

	if (!strncmp(buf, start_tunnel, sizeof(start_tunnel))) {
		ret = 0;
	} else if (ret==0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Gateway disconnected immediately after GET-tunnel request.\n"));
		ret = -EPIPE;
	} else {
		if (ret==sizeof(start_tunnel)) {
			ret = vpninfo->ssl_gets(vpninfo, buf+sizeof(start_tunnel), sizeof(buf)-sizeof(start_tunnel));
			ret = (ret>0 ? ret : 0) + sizeof(start_tunnel);
		}
		vpn_progress(vpninfo, PRG_ERR,
		             _("Got inappropriate HTTP GET-tunnel response: %.*s\n"), ret, buf);
		ret = -EINVAL;
	}

	if (ret < 0)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
		vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
		if (vpninfo->proto->udp_close)
			vpninfo->proto->udp_close(vpninfo);
	}

out:
	buf_free(reqbuf);
	return ret;
}

static int parse_hip_report_check(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	const char *s;
	int result = -EINVAL;

	if (!xml_node || !xmlnode_is_named(xml_node, "response"))
		goto out;

	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		if (!xmlnode_get_text(xml_node, "hip-report-needed", &s)) {
			if (!strcmp(s, "no"))
				result = 0;
			else if (!strcmp(s, "yes"))
				result = -EAGAIN;
			else
				result = -EINVAL;
			free((void *)s);
			goto out;
		}
	}

out:
	return result;
}

/* Unlike CSD, the HIP security checker runs during the connection
 * phase, not during the authentication phase.
 *
 * The HIP security checker will (probably) ask us to resubmit the
 * HIP report if either of the following changes:
 *   - Client IP address
 *	 - Client HIP report md5sum
 *
 * I'm not sure what the md5sum is computed over in the official
 * client, but it doesn't really matter.
 *
 * We just need an identifier for the combination of the local host
 * and the VPN gateway which won't change when our IP address
 * or authcookie are changed.
 */
static int build_csd_token(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *buf;
	unsigned char md5[16];
	int i;

	if (vpninfo->csd_token)
		return 0;

	vpninfo->csd_token = malloc(MD5_SIZE * 2 + 1);
	if (!vpninfo->csd_token)
		return -ENOMEM;

	/* use localname and cookie (excluding volatile authcookie and preferred-ip) to build md5sum */
	buf = buf_alloc();
	append_opt(buf, "computer", vpninfo->localname);
	filter_opts(buf, vpninfo->cookie, "authcookie,preferred-ip", 0);
	if (buf_error(buf))
		goto out;

	/* save as csd_token */
	openconnect_md5(md5, buf->data, buf->pos);
	for (i=0; i < MD5_SIZE; i++)
		sprintf(&vpninfo->csd_token[i*2], "%02x", md5[i]);

out:
	return buf_free(buf);
}

/* check if HIP report is needed (to ssl-vpn/hipreportcheck.esp) or submit HIP report contents (to ssl-vpn/hipreport.esp) */
static int check_or_submit_hip_report(struct openconnect_info *vpninfo, const char *report)
{
	int result;

	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type = "application/x-www-form-urlencoded";
	const char *method = "POST";
	char *xml_buf=NULL, *orig_path;

	/* cookie gives us these fields: authcookie, portal, user, domain, and (maybe the unnecessary) preferred-ip */
	buf_append(request_body, "client-role=global-protect-full&%s", vpninfo->cookie);
	append_opt(request_body, "computer", vpninfo->localname);
	append_opt(request_body, "client-ip", vpninfo->ip_info.addr);
	if (report) {
		/* XML report contains many characters requiring URL-encoding (%xx) */
		buf_ensure_space(request_body, strlen(report)*3);
		append_opt(request_body, "report", report);
	} else {
		result = build_csd_token(vpninfo);
		if (result)
			goto out;
		append_opt(request_body, "md5", vpninfo->csd_token);
	}
	if ((result = buf_error(request_body)))
		goto out;

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup(report ? "ssl-vpn/hipreport.esp" : "ssl-vpn/hipreportcheck.esp");
	result = do_https_request(vpninfo, method, request_body_type, request_body,
				  &xml_buf, 0);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	result = gpst_xml_or_error(vpninfo, result, xml_buf, report ? NULL : parse_hip_report_check, NULL, NULL);

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

static int run_hip_script(struct openconnect_info *vpninfo)
{
#if !defined(_WIN32) && !defined(__native_client__)
	int pipefd[2];
	int ret;
	pid_t child;
#endif

	if (!vpninfo->csd_wrapper) {
		vpn_progress(vpninfo, PRG_ERR,
		             _("WARNING: Server asked us to submit HIP report with md5sum %s.\n"
		               "VPN connectivity may be disabled or limited without HIP report submission.\n"
		               "You need to provide a --csd-wrapper argument with the HIP report submission script.\n"),
		             vpninfo->csd_token);
		/* XXX: Many GlobalProtect VPNs work fine despite allegedly requiring HIP report submission */
		return 0;
	}

#if defined(_WIN32) || defined(__native_client__)
	vpn_progress(vpninfo, PRG_ERR,
		     _("Error: Running the 'HIP Report' script on this platform is not yet implemented.\n"));
	return -EPERM;
#else
	if (pipe(pipefd) == -1)
		goto out;
	child = fork();
	if (child == -1) {
		goto out;
	} else if (child > 0) {
		/* in parent: read report from child */
		struct oc_text_buf *report_buf = buf_alloc();
		char b[256];
		int i, status;
		close(pipefd[1]);

		buf_truncate(report_buf);
		while ((i = read(pipefd[0], b, sizeof(b))) > 0)
			buf_append_bytes(report_buf, b, i);

		waitpid(child, &status, 0);
		if (status != 0) {
			vpn_progress(vpninfo, PRG_ERR,
						 _("HIP script returned non-zero status: %d\n"), status);
			ret = -EINVAL;
		} else {
			ret = check_or_submit_hip_report(vpninfo, report_buf->data);
			if (ret < 0)
				vpn_progress(vpninfo, PRG_ERR, _("HIP report submission failed.\n"));
			else {
				vpn_progress(vpninfo, PRG_INFO, _("HIP report submitted successfully.\n"));
				ret = 0;
			}
		}
		buf_free(report_buf);
		return ret;
	} else {
		/* in child: run HIP script */
		char *hip_argv[32];
		int i = 0;
		close(pipefd[0]);
		dup2(pipefd[1], 1);

		hip_argv[i++] = openconnect_utf8_to_legacy(vpninfo, vpninfo->csd_wrapper);
		hip_argv[i++] = (char *)"--cookie";
		hip_argv[i++] = vpninfo->cookie;
		hip_argv[i++] = (char *)"--computer";
		hip_argv[i++] = vpninfo->localname;
		hip_argv[i++] = (char *)"--client-ip";
		hip_argv[i++] = (char *)vpninfo->ip_info.addr;
		hip_argv[i++] = (char *)"--md5";
		hip_argv[i++] = vpninfo->csd_token;
		hip_argv[i++] = NULL;
		execv(hip_argv[0], hip_argv);

	out:
		vpn_progress(vpninfo, PRG_ERR,
				 _("Failed to exec HIP script %s\n"), hip_argv[0]);
		exit(1);
	}

#endif /* !_WIN32 && !__native_client__ */
}

int gpst_setup(struct openconnect_info *vpninfo)
{
	int ret;

	/* ESP tunnel is unusable as soon as we (re-)fetch the configuration */
	if (vpninfo->proto->udp_close)
		vpninfo->proto->udp_close(vpninfo);

	/* Get configuration */
	ret = gpst_get_config(vpninfo);
	if (ret)
		goto out;

	/* Check HIP */
	ret = check_or_submit_hip_report(vpninfo, NULL);
	if (ret == -EAGAIN) {
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Gateway says HIP report submission is needed.\n"));
		ret = run_hip_script(vpninfo);
		if (ret != 0)
			goto out;
	} else if (ret == 0)
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Gateway says no HIP report submission is needed.\n"));

	/* We do NOT actually start the HTTPS tunnel yet if we want to
	 * use ESP, because the ESP tunnel won't work if the HTTPS tunnel
	 * is connected! >:-(
	 */
	if (vpninfo->dtls_state == DTLS_DISABLED || vpninfo->dtls_state == DTLS_NOSECRET)
		ret = gpst_connect(vpninfo);

out:
	return ret;
}

int gpst_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	int ret;
	int work_done = 0;
	uint16_t ethertype;
	uint32_t one, zero, magic;

	/* Starting the HTTPS tunnel kills ESP, so we avoid starting
	 * it if the ESP tunnel is connected or connecting.
	 */
	switch (vpninfo->dtls_state) {
	case DTLS_CONNECTING:
		openconnect_close_https(vpninfo, 0); /* don't keep stale HTTPS socket */
		vpn_progress(vpninfo, PRG_INFO,
			     _("ESP tunnel connected; exiting HTTPS mainloop.\n"));
		vpninfo->dtls_state = DTLS_CONNECTED;
	case DTLS_CONNECTED:
		/* Rekey if needed */
		if (keepalive_action(&vpninfo->ssl_times, timeout) == KA_REKEY)
			goto do_rekey;
		return 0;
	case DTLS_SECRET:
	case DTLS_SLEEPING:
		if (!ka_check_deadline(timeout, time(NULL), vpninfo->new_dtls_started + 5)) {
			/* Allow 5 seconds after configuration for ESP to start */
			return 0;
		} else {
			/* ... before we switch to HTTPS instead */
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to connect ESP tunnel; using HTTPS instead.\n"));
			if (gpst_connect(vpninfo)) {
				vpninfo->quit_reason = "GPST connect failed";
				return 1;
			}
		}
		break;
	case DTLS_NOSECRET:
		/* HTTPS tunnel already started, or getconfig.esp did not provide any ESP keys */
	case DTLS_DISABLED:
		/* ESP is disabled */
		;
	}

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	while (1) {
		int receive_mtu = MAX(2048, vpninfo->ip_info.mtu + 256);
		int len, payload_len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = malloc(sizeof(struct pkt) + receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, vpninfo->cstp_pkt->gpst.hdr, receive_mtu + 16);
		if (!len)
			break;
		if (len < 0) {
			vpn_progress(vpninfo, PRG_ERR, _("Packet receive error: %s\n"), strerror(-len));
			goto do_reconnect;
		}
		if (len < 16) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		/* check packet header */
		magic = load_be32(vpninfo->cstp_pkt->gpst.hdr);
		ethertype = load_be16(vpninfo->cstp_pkt->gpst.hdr + 4);
		payload_len = load_be16(vpninfo->cstp_pkt->gpst.hdr + 6);
		one = load_le32(vpninfo->cstp_pkt->gpst.hdr + 8);
		zero = load_le32(vpninfo->cstp_pkt->gpst.hdr + 12);

		if (magic != 0x1a2b3c4d)
			goto unknown_pkt;

		if (len != 16 + payload_len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected packet length. SSL_read returned %d (includes 16 header bytes) but header payload_len is %d\n"),
			             len, payload_len);
			dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->gpst.hdr, 16);
			continue;
		}

		vpninfo->ssl_times.last_rx = time(NULL);
		switch (ethertype) {
		case 0:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Got GPST DPD/keepalive response\n"));

			if (one != 0 || zero != 0) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Expected 0000000000000000 as last 8 bytes of DPD/keepalive packet header, but got:\n"));
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}
			continue;
		case 0x0800:
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received data packet of %d bytes\n"),
				     payload_len);
			vpninfo->cstp_pkt->len = payload_len;
			queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			work_done = 1;

			if (one != 1 || zero != 0) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Expected 0100000000000000 as last 8 bytes of data packet header, but got:\n"));
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}
			continue;
		}

	unknown_pkt:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown packet. Header dump follows:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->gpst.hdr, 16);
		vpninfo->quit_reason = "Unknown packet received";
		return 1;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo,
					 vpninfo->current_ssl_pkt->gpst.hdr,
					 vpninfo->current_ssl_pkt->len + 16);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_REKEY:
				goto do_rekey;
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_NONE:
				return work_done;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len + 16) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 16, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt != &dpd_pkt)
			free(vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		vpn_progress(vpninfo, PRG_INFO, _("GlobalProtect rekey due\n"));
		goto do_reconnect;

	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("GPST Dead Peer Detection detected dead peer!\n"));
	do_reconnect:
		ret = ssl_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "GPST reconnect failed";
			return ret;
		}
		if (vpninfo->proto->udp_setup)
			vpninfo->proto->udp_setup(vpninfo, vpninfo->dtls_attempt_period);
		return 1;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_CONNECTED &&
		    vpninfo->outgoing_queue.head)
			break;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send GPST DPD/keepalive request\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;
	}


	/* Service outgoing packet queue */
	while (vpninfo->dtls_state != DTLS_CONNECTED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		/* store header */
		store_be32(this->gpst.hdr, 0x1a2b3c4d);
		store_be16(this->gpst.hdr + 4, 0x0800); /* IPv4 EtherType */
		store_be16(this->gpst.hdr + 6, this->len);
		store_le32(this->gpst.hdr + 8, 1);
		store_le32(this->gpst.hdr + 12, 0);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending data packet of %d bytes\n"),
			     this->len);

		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}
