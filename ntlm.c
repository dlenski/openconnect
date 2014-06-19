/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2014 Intel Corporation.
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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif

#include "openconnect-internal.h"


#define NTLM_SSO_REQ		2	/* SSO type1 packet sent */
#define NTLM_MANUAL		3	/* SSO challenge/response sent or skipped; manual next */
#define NTLM_MANUAL_REQ		4	/* manual type1 packet sent */

#ifndef _WIN32
static int ntlm_helper_spawn(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	char *username;
	int pipefd[2];
	pid_t pid;
	char helperbuf[4096];
	int len;

	if (access("/usr/bin/ntlm_auth", X_OK))
		return -errno;

	username = vpninfo->proxy_user;
	if (!username)
		username = getenv("NTLMUSER");
	if (!username)
		username = getenv("USER");
	if (!username)
		return -EINVAL;

#ifdef SOCK_CLOEXEC
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pipefd))
#endif
	{
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd))
			return -errno;
		set_fd_cloexec(pipefd[0]);
		set_fd_cloexec(pipefd[1]);
	}
	pid = fork();
	if (pid == -1)
		return -errno;

	if (!pid) {
		int i;
		char *p;
		const char *argv[9];

		/* Fork again to detach grandchild */
		if (fork())
			exit(1);

		close(pipefd[1]);
		/* The duplicated fd does not have O_CLOEXEC */
		dup2(pipefd[0], 0);
		dup2(pipefd[0], 1);
		/* Should we leave stderr open? */
		for (i = 3; i < 1024 ; i++)
			close(i);


		i = 0;
		argv[i++] = "/usr/bin/ntlm_auth";
		argv[i++] = "--helper-protocol";
		argv[i++] = "ntlmssp-client-1";
		argv[i++] = "--use-cached-creds";
		argv[i++] = "--username";
		p = strchr(username, '\\');
		if (p) {
			argv[i++] = p+1;
			argv[i++] = "--domain";
			argv[i++] = strndup(username, p - username);
		} else
			argv[i++] = username;
		argv[i++] = NULL;

		execv(argv[0], (char **)argv);
		exit(1);
	}
	waitpid(pid, NULL, 0);
	close(pipefd[0]);

	if (write(pipefd[1], "YR\n", 3) != 3) {
		close(pipefd[1]);
		return -EIO;
	}

	len = read(pipefd[1], helperbuf, sizeof(helperbuf));
	if (len < 4 || helperbuf[0] != 'Y' || helperbuf[1] != 'R' ||
	    helperbuf[2] != ' ' || helperbuf[len - 1] != '\n') {
		close(pipefd[1]);
		return -EIO;
	}
	helperbuf[len - 1] = 0;
	buf_append(buf, "Proxy-Authorization: NTLM %s\r\n", helperbuf + 3);
	vpninfo->ntlm_helper_fd = pipefd[1];
	return 0;
}

static int ntlm_helper_challenge(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	char helperbuf[4096];
	int len;

	if (!vpninfo->ntlm_auth.challenge ||
	    write(vpninfo->ntlm_helper_fd, "TT ", 3) != 3 ||
	    write(vpninfo->ntlm_helper_fd, vpninfo->ntlm_auth.challenge,
		  strlen(vpninfo->ntlm_auth.challenge)) != strlen(vpninfo->ntlm_auth.challenge) ||
	    write(vpninfo->ntlm_helper_fd, "\n", 1) != 1) {
	err:
		close(vpninfo->ntlm_helper_fd);
		vpninfo->ntlm_helper_fd = -1;
		return -EIO;
	}
	len = read(vpninfo->ntlm_helper_fd, helperbuf, sizeof(helperbuf));
	if (len < 4 || helperbuf[0] != 'K' || helperbuf[1] != 'K' ||
	    helperbuf[2] != ' ' || helperbuf[len - 1] != '\n') {
		goto err;
	}
	helperbuf[len - 1] = 0;
	buf_append(buf, "Proxy-Authorization: NTLM %s\r\n", helperbuf + 3);
	close(vpninfo->ntlm_helper_fd);
	vpninfo->ntlm_helper_fd = -1;

	vpn_progress(vpninfo, PRG_INFO, _("Attempting HTTP NTLM authentication to proxy (single-sign-on)\n"));
	return 0;

}
#endif /* !_WIN32 */

static int ntlm_manual_challenge(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	vpn_progress(vpninfo, PRG_INFO, _("Attempting HTTP NTLM authentication to proxy (manual)\n"));
	return -EIO;
}

int ntlm_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	if (vpninfo->ntlm_auth.state == AUTH_AVAILABLE) {
		vpninfo->ntlm_auth.state = NTLM_MANUAL;
#ifndef _WIN32
		if (!ntlm_helper_spawn(vpninfo, buf)) {
			vpninfo->ntlm_auth.state = NTLM_SSO_REQ;
			return 0;
		}
	}
	if (vpninfo->ntlm_auth.state == NTLM_SSO_REQ) {
		vpninfo->ntlm_auth.state = NTLM_MANUAL;
		if (!ntlm_helper_challenge(vpninfo, buf))
			return 0;
#endif
	}
	if (vpninfo->ntlm_auth.state == NTLM_MANUAL && vpninfo->proxy_user &&
	    vpninfo->proxy_pass) {
		buf_append(buf, "Proxy-Authorization: NTLM %s\r\n",
			   "TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA");
		vpninfo->ntlm_auth.state = NTLM_MANUAL_REQ;
		return 0;
	}
	if (vpninfo->ntlm_auth.state == NTLM_MANUAL_REQ) {
		vpninfo->ntlm_auth.state = AUTH_FAILED;
		return ntlm_manual_challenge(vpninfo, buf);

	}
	return -EINVAL;
}
