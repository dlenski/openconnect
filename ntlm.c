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
#include <ctype.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
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

/*
 * NTLM implementation taken from libsoup / Evolution Data Server
 * Copyright (C) 2007 Red Hat, Inc.
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 */

/* DES */
typedef uint32_t DES_KS[16][2]; /* Single-key DES key schedule */

/*
 * MD4 encoder. (The one everyone else uses is not GPL-compatible;
 * this is a reimplementation from spec.) This doesn't need to be
 * efficient for our purposes, although it would be nice to fix
 * it to not malloc()...
 */

#define F(X,Y,Z) ( ((X)&(Y)) | ((~(X))&(Z)) )
#define G(X,Y,Z) ( ((X)&(Y)) | ((X)&(Z)) | ((Y)&(Z)) )
#define H(X,Y,Z) ( (X)^(Y)^(Z) )
#define ROT(val, n) ( ((val) << (n)) | ((val) >> (32 - (n))) )

static void md4sum (const unsigned char *in, int nbytes, unsigned char digest[16])
{
	unsigned char *M;
	uint32_t A, B, C, D, AA, BB, CC, DD, X[16];
	int pbytes, nbits = nbytes * 8, i, j;

	pbytes = (120 - (nbytes % 64)) % 64;
	M = alloca (nbytes + pbytes + 8);
	memcpy (M, in, nbytes);
	memset (M + nbytes, 0, pbytes + 8);
	M[nbytes] = 0x80;
	M[nbytes + pbytes] = nbits & 0xFF;
	M[nbytes + pbytes + 1] = (nbits >> 8) & 0xFF;
	M[nbytes + pbytes + 2] = (nbits >> 16) & 0xFF;
	M[nbytes + pbytes + 3] = (nbits >> 24) & 0xFF;

	A = 0x67452301;
	B = 0xEFCDAB89;
	C = 0x98BADCFE;
	D = 0x10325476;

	for (i = 0; i < nbytes + pbytes + 8; i += 64) {
		for (j = 0; j < 16; j++) {
			X[j] =  (M[i + j * 4]) |
				(M[i + j * 4 + 1] << 8) |
				(M[i + j * 4 + 2] << 16) |
				(M[i + j * 4 + 3] << 24);
		}

		AA = A;
		BB = B;
		CC = C;
		DD = D;

		A = ROT (A + F (B, C, D) + X[0], 3);
		D = ROT (D + F (A, B, C) + X[1], 7);
		C = ROT (C + F (D, A, B) + X[2], 11);
		B = ROT (B + F (C, D, A) + X[3], 19);
		A = ROT (A + F (B, C, D) + X[4], 3);
		D = ROT (D + F (A, B, C) + X[5], 7);
		C = ROT (C + F (D, A, B) + X[6], 11);
		B = ROT (B + F (C, D, A) + X[7], 19);
		A = ROT (A + F (B, C, D) + X[8], 3);
		D = ROT (D + F (A, B, C) + X[9], 7);
		C = ROT (C + F (D, A, B) + X[10], 11);
		B = ROT (B + F (C, D, A) + X[11], 19);
		A = ROT (A + F (B, C, D) + X[12], 3);
		D = ROT (D + F (A, B, C) + X[13], 7);
		C = ROT (C + F (D, A, B) + X[14], 11);
		B = ROT (B + F (C, D, A) + X[15], 19);

		A = ROT (A + G (B, C, D) + X[0] + 0x5A827999, 3);
		D = ROT (D + G (A, B, C) + X[4] + 0x5A827999, 5);
		C = ROT (C + G (D, A, B) + X[8] + 0x5A827999, 9);
		B = ROT (B + G (C, D, A) + X[12] + 0x5A827999, 13);
		A = ROT (A + G (B, C, D) + X[1] + 0x5A827999, 3);
		D = ROT (D + G (A, B, C) + X[5] + 0x5A827999, 5);
		C = ROT (C + G (D, A, B) + X[9] + 0x5A827999, 9);
		B = ROT (B + G (C, D, A) + X[13] + 0x5A827999, 13);
		A = ROT (A + G (B, C, D) + X[2] + 0x5A827999, 3);
		D = ROT (D + G (A, B, C) + X[6] + 0x5A827999, 5);
		C = ROT (C + G (D, A, B) + X[10] + 0x5A827999, 9);
		B = ROT (B + G (C, D, A) + X[14] + 0x5A827999, 13);
		A = ROT (A + G (B, C, D) + X[3] + 0x5A827999, 3);
		D = ROT (D + G (A, B, C) + X[7] + 0x5A827999, 5);
		C = ROT (C + G (D, A, B) + X[11] + 0x5A827999, 9);
		B = ROT (B + G (C, D, A) + X[15] + 0x5A827999, 13);

		A = ROT (A + H (B, C, D) + X[0] + 0x6ED9EBA1, 3);
		D = ROT (D + H (A, B, C) + X[8] + 0x6ED9EBA1, 9);
		C = ROT (C + H (D, A, B) + X[4] + 0x6ED9EBA1, 11);
		B = ROT (B + H (C, D, A) + X[12] + 0x6ED9EBA1, 15);
		A = ROT (A + H (B, C, D) + X[2] + 0x6ED9EBA1, 3);
		D = ROT (D + H (A, B, C) + X[10] + 0x6ED9EBA1, 9);
		C = ROT (C + H (D, A, B) + X[6] + 0x6ED9EBA1, 11);
		B = ROT (B + H (C, D, A) + X[14] + 0x6ED9EBA1, 15);
		A = ROT (A + H (B, C, D) + X[1] + 0x6ED9EBA1, 3);
		D = ROT (D + H (A, B, C) + X[9] + 0x6ED9EBA1, 9);
		C = ROT (C + H (D, A, B) + X[5] + 0x6ED9EBA1, 11);
		B = ROT (B + H (C, D, A) + X[13] + 0x6ED9EBA1, 15);
		A = ROT (A + H (B, C, D) + X[3] + 0x6ED9EBA1, 3);
		D = ROT (D + H (A, B, C) + X[11] + 0x6ED9EBA1, 9);
		C = ROT (C + H (D, A, B) + X[7] + 0x6ED9EBA1, 11);
		B = ROT (B + H (C, D, A) + X[15] + 0x6ED9EBA1, 15);

		A += AA;
		B += BB;
		C += CC;
		D += DD;
	}

	digest[0]  =  A        & 0xFF;
	digest[1]  = (A >>  8) & 0xFF;
	digest[2]  = (A >> 16) & 0xFF;
	digest[3]  = (A >> 24) & 0xFF;
	digest[4]  =  B        & 0xFF;
	digest[5]  = (B >>  8) & 0xFF;
	digest[6]  = (B >> 16) & 0xFF;
	digest[7]  = (B >> 24) & 0xFF;
	digest[8]  =  C        & 0xFF;
	digest[9]  = (C >>  8) & 0xFF;
	digest[10] = (C >> 16) & 0xFF;
	digest[11] = (C >> 24) & 0xFF;
	digest[12] =  D        & 0xFF;
	digest[13] = (D >>  8) & 0xFF;
	digest[14] = (D >> 16) & 0xFF;
	digest[15] = (D >> 24) & 0xFF;
}

/* Public domain DES implementation from Phil Karn */
static uint32_t Spbox[8][64] = {
	{ 0x01010400, 0x00000000, 0x00010000, 0x01010404,
	  0x01010004, 0x00010404, 0x00000004, 0x00010000,
	  0x00000400, 0x01010400, 0x01010404, 0x00000400,
	  0x01000404, 0x01010004, 0x01000000, 0x00000004,
	  0x00000404, 0x01000400, 0x01000400, 0x00010400,
	  0x00010400, 0x01010000, 0x01010000, 0x01000404,
	  0x00010004, 0x01000004, 0x01000004, 0x00010004,
	  0x00000000, 0x00000404, 0x00010404, 0x01000000,
	  0x00010000, 0x01010404, 0x00000004, 0x01010000,
	  0x01010400, 0x01000000, 0x01000000, 0x00000400,
	  0x01010004, 0x00010000, 0x00010400, 0x01000004,
	  0x00000400, 0x00000004, 0x01000404, 0x00010404,
	  0x01010404, 0x00010004, 0x01010000, 0x01000404,
	  0x01000004, 0x00000404, 0x00010404, 0x01010400,
	  0x00000404, 0x01000400, 0x01000400, 0x00000000,
	  0x00010004, 0x00010400, 0x00000000, 0x01010004 },
	{ 0x80108020, 0x80008000, 0x00008000, 0x00108020,
	  0x00100000, 0x00000020, 0x80100020, 0x80008020,
	  0x80000020, 0x80108020, 0x80108000, 0x80000000,
	  0x80008000, 0x00100000, 0x00000020, 0x80100020,
	  0x00108000, 0x00100020, 0x80008020, 0x00000000,
	  0x80000000, 0x00008000, 0x00108020, 0x80100000,
	  0x00100020, 0x80000020, 0x00000000, 0x00108000,
	  0x00008020, 0x80108000, 0x80100000, 0x00008020,
	  0x00000000, 0x00108020, 0x80100020, 0x00100000,
	  0x80008020, 0x80100000, 0x80108000, 0x00008000,
	  0x80100000, 0x80008000, 0x00000020, 0x80108020,
	  0x00108020, 0x00000020, 0x00008000, 0x80000000,
	  0x00008020, 0x80108000, 0x00100000, 0x80000020,
	  0x00100020, 0x80008020, 0x80000020, 0x00100020,
	  0x00108000, 0x00000000, 0x80008000, 0x00008020,
	  0x80000000, 0x80100020, 0x80108020, 0x00108000 },
	{ 0x00000208, 0x08020200, 0x00000000, 0x08020008,
	  0x08000200, 0x00000000, 0x00020208, 0x08000200,
	  0x00020008, 0x08000008, 0x08000008, 0x00020000,
	  0x08020208, 0x00020008, 0x08020000, 0x00000208,
	  0x08000000, 0x00000008, 0x08020200, 0x00000200,
	  0x00020200, 0x08020000, 0x08020008, 0x00020208,
	  0x08000208, 0x00020200, 0x00020000, 0x08000208,
	  0x00000008, 0x08020208, 0x00000200, 0x08000000,
	  0x08020200, 0x08000000, 0x00020008, 0x00000208,
	  0x00020000, 0x08020200, 0x08000200, 0x00000000,
	  0x00000200, 0x00020008, 0x08020208, 0x08000200,
	  0x08000008, 0x00000200, 0x00000000, 0x08020008,
	  0x08000208, 0x00020000, 0x08000000, 0x08020208,
	  0x00000008, 0x00020208, 0x00020200, 0x08000008,
	  0x08020000, 0x08000208, 0x00000208, 0x08020000,
	  0x00020208, 0x00000008, 0x08020008, 0x00020200 },
	{ 0x00802001, 0x00002081, 0x00002081, 0x00000080,
	  0x00802080, 0x00800081, 0x00800001, 0x00002001,
	  0x00000000, 0x00802000, 0x00802000, 0x00802081,
	  0x00000081, 0x00000000, 0x00800080, 0x00800001,
	  0x00000001, 0x00002000, 0x00800000, 0x00802001,
	  0x00000080, 0x00800000, 0x00002001, 0x00002080,
	  0x00800081, 0x00000001, 0x00002080, 0x00800080,
	  0x00002000, 0x00802080, 0x00802081, 0x00000081,
	  0x00800080, 0x00800001, 0x00802000, 0x00802081,
	  0x00000081, 0x00000000, 0x00000000, 0x00802000,
	  0x00002080, 0x00800080, 0x00800081, 0x00000001,
	  0x00802001, 0x00002081, 0x00002081, 0x00000080,
	  0x00802081, 0x00000081, 0x00000001, 0x00002000,
	  0x00800001, 0x00002001, 0x00802080, 0x00800081,
	  0x00002001, 0x00002080, 0x00800000, 0x00802001,
	  0x00000080, 0x00800000, 0x00002000, 0x00802080 },
	{ 0x00000100, 0x02080100, 0x02080000, 0x42000100,
	  0x00080000, 0x00000100, 0x40000000, 0x02080000,
	  0x40080100, 0x00080000, 0x02000100, 0x40080100,
	  0x42000100, 0x42080000, 0x00080100, 0x40000000,
	  0x02000000, 0x40080000, 0x40080000, 0x00000000,
	  0x40000100, 0x42080100, 0x42080100, 0x02000100,
	  0x42080000, 0x40000100, 0x00000000, 0x42000000,
	  0x02080100, 0x02000000, 0x42000000, 0x00080100,
	  0x00080000, 0x42000100, 0x00000100, 0x02000000,
	  0x40000000, 0x02080000, 0x42000100, 0x40080100,
	  0x02000100, 0x40000000, 0x42080000, 0x02080100,
	  0x40080100, 0x00000100, 0x02000000, 0x42080000,
	  0x42080100, 0x00080100, 0x42000000, 0x42080100,
	  0x02080000, 0x00000000, 0x40080000, 0x42000000,
	  0x00080100, 0x02000100, 0x40000100, 0x00080000,
	  0x00000000, 0x40080000, 0x02080100, 0x40000100 },
	{ 0x20000010, 0x20400000, 0x00004000, 0x20404010,
	  0x20400000, 0x00000010, 0x20404010, 0x00400000,
	  0x20004000, 0x00404010, 0x00400000, 0x20000010,
	  0x00400010, 0x20004000, 0x20000000, 0x00004010,
	  0x00000000, 0x00400010, 0x20004010, 0x00004000,
	  0x00404000, 0x20004010, 0x00000010, 0x20400010,
	  0x20400010, 0x00000000, 0x00404010, 0x20404000,
	  0x00004010, 0x00404000, 0x20404000, 0x20000000,
	  0x20004000, 0x00000010, 0x20400010, 0x00404000,
	  0x20404010, 0x00400000, 0x00004010, 0x20000010,
	  0x00400000, 0x20004000, 0x20000000, 0x00004010,
	  0x20000010, 0x20404010, 0x00404000, 0x20400000,
	  0x00404010, 0x20404000, 0x00000000, 0x20400010,
	  0x00000010, 0x00004000, 0x20400000, 0x00404010,
	  0x00004000, 0x00400010, 0x20004010, 0x00000000,
	  0x20404000, 0x20000000, 0x00400010, 0x20004010 },
	{ 0x00200000, 0x04200002, 0x04000802, 0x00000000,
	  0x00000800, 0x04000802, 0x00200802, 0x04200800,
	  0x04200802, 0x00200000, 0x00000000, 0x04000002,
	  0x00000002, 0x04000000, 0x04200002, 0x00000802,
	  0x04000800, 0x00200802, 0x00200002, 0x04000800,
	  0x04000002, 0x04200000, 0x04200800, 0x00200002,
	  0x04200000, 0x00000800, 0x00000802, 0x04200802,
	  0x00200800, 0x00000002, 0x04000000, 0x00200800,
	  0x04000000, 0x00200800, 0x00200000, 0x04000802,
	  0x04000802, 0x04200002, 0x04200002, 0x00000002,
	  0x00200002, 0x04000000, 0x04000800, 0x00200000,
	  0x04200800, 0x00000802, 0x00200802, 0x04200800,
	  0x00000802, 0x04000002, 0x04200802, 0x04200000,
	  0x00200800, 0x00000000, 0x00000002, 0x04200802,
	  0x00000000, 0x00200802, 0x04200000, 0x00000800,
	  0x04000002, 0x04000800, 0x00000800, 0x00200002 },
	{ 0x10001040, 0x00001000, 0x00040000, 0x10041040,
	  0x10000000, 0x10001040, 0x00000040, 0x10000000,
	  0x00040040, 0x10040000, 0x10041040, 0x00041000,
	  0x10041000, 0x00041040, 0x00001000, 0x00000040,
	  0x10040000, 0x10000040, 0x10001000, 0x00001040,
	  0x00041000, 0x00040040, 0x10040040, 0x10041000,
	  0x00001040, 0x00000000, 0x00000000, 0x10040040,
	  0x10000040, 0x10001000, 0x00041040, 0x00040000,
	  0x00041040, 0x00040000, 0x10041000, 0x00001000,
	  0x00000040, 0x10040040, 0x00001000, 0x00041040,
	  0x10001000, 0x00000040, 0x10000040, 0x10040000,
	  0x10040040, 0x10000000, 0x00040000, 0x10001040,
	  0x00000000, 0x10041040, 0x00040040, 0x10000040,
	  0x10040000, 0x10001000, 0x10001040, 0x00000000,
	  0x10041040, 0x00041000, 0x00041000, 0x00001040,
	  0x00001040, 0x00040040, 0x10000000, 0x10041000 }
};

#undef F
#define	F(l,r,key){\
	work = ((r >> 4) | (r << 28)) ^ key[0];\
	l ^= Spbox[6][work & 0x3f];\
	l ^= Spbox[4][(work >> 8) & 0x3f];\
	l ^= Spbox[2][(work >> 16) & 0x3f];\
	l ^= Spbox[0][(work >> 24) & 0x3f];\
	work = r ^ key[1];\
	l ^= Spbox[7][work & 0x3f];\
	l ^= Spbox[5][(work >> 8) & 0x3f];\
	l ^= Spbox[3][(work >> 16) & 0x3f];\
	l ^= Spbox[1][(work >> 24) & 0x3f];\
}

/* Encrypt or decrypt a block of data in ECB mode */
static void des (uint32_t ks[16][2], unsigned char block[8])
{
	uint32_t left, right, work;

	/* Read input block and place in left/right in big-endian order */
	left = ((uint32_t) block[0] << 24)
	 | ((uint32_t) block[1] << 16)
	 | ((uint32_t) block[2] << 8)
	 | (uint32_t) block[3];
	right = ((uint32_t) block[4] << 24)
	 | ((uint32_t) block[5] << 16)
	 | ((uint32_t) block[6] << 8)
	 | (uint32_t) block[7];

	/* Hoey's clever initial permutation algorithm, from Outerbridge
	 * (see Schneier p 478)
	 *
	 * The convention here is the same as Outerbridge: rotate each
	 * register left by 1 bit, i.e., so that "left" contains permuted
	 * input bits 2, 3, 4, ... 1 and "right" contains 33, 34, 35, ... 32
	 * (using origin-1 numbering as in the FIPS). This allows us to avoid
	 * one of the two rotates that would otherwise be required in each of
	 * the 16 rounds.
	 */
	work = ((left >> 4) ^ right) & 0x0f0f0f0f;
	right ^= work;
	left ^= work << 4;
	work = ((left >> 16) ^ right) & 0xffff;
	right ^= work;
	left ^= work << 16;
	work = ((right >> 2) ^ left) & 0x33333333;
	left ^= work;
	right ^= (work << 2);
	work = ((right >> 8) ^ left) & 0xff00ff;
	left ^= work;
	right ^= (work << 8);
	right = (right << 1) | (right >> 31);
	work = (left ^ right) & 0xaaaaaaaa;
	left ^= work;
	right ^= work;
	left = (left << 1) | (left >> 31);

	/* Now do the 16 rounds */
	F (left,right,ks[0]);
	F (right,left,ks[1]);
	F (left,right,ks[2]);
	F (right,left,ks[3]);
	F (left,right,ks[4]);
	F (right,left,ks[5]);
	F (left,right,ks[6]);
	F (right,left,ks[7]);
	F (left,right,ks[8]);
	F (right,left,ks[9]);
	F (left,right,ks[10]);
	F (right,left,ks[11]);
	F (left,right,ks[12]);
	F (right,left,ks[13]);
	F (left,right,ks[14]);
	F (right,left,ks[15]);

	/* Inverse permutation, also from Hoey via Outerbridge and Schneier */
	right = (right << 31) | (right >> 1);
	work = (left ^ right) & 0xaaaaaaaa;
	left ^= work;
	right ^= work;
	left = (left >> 1) | (left  << 31);
	work = ((left >> 8) ^ right) & 0xff00ff;
	right ^= work;
	left ^= work << 8;
	work = ((left >> 2) ^ right) & 0x33333333;
	right ^= work;
	left ^= work << 2;
	work = ((right >> 16) ^ left) & 0xffff;
	left ^= work;
	right ^= work << 16;
	work = ((right >> 4) ^ left) & 0x0f0f0f0f;
	left ^= work;
	right ^= work << 4;

	/* Put the block back into the user's buffer with final swap */
	block[0] = right >> 24;
	block[1] = right >> 16;
	block[2] = right >> 8;
	block[3] = right;
	block[4] = left >> 24;
	block[5] = left >> 16;
	block[6] = left >> 8;
	block[7] = left;
}

/* Key schedule-related tables from FIPS-46 */

/* permuted choice table (key) */
static unsigned char pc1[] = {
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,

	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

/* number left rotations of pc1 */
static unsigned char totrot[] = {
	1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28
};

/* permuted choice key (table) */
static unsigned char pc2[] = {
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

/* End of DES-defined tables */

/* bit 0 is left-most in byte */
static int bytebit[] = {
	0200,0100,040,020,010,04,02,01
};

/* Generate key schedule for encryption or decryption
 * depending on the value of "decrypt"
 */
static void deskey (DES_KS k, unsigned char *key, int decrypt)
{
	unsigned char pc1m[56];		/* place to modify pc1 into */
	unsigned char pcr[56];		/* place to rotate pc1 into */
	register int i,j,l;
	int m;
	unsigned char ks[8];

	for (j=0; j<56; j++) {		/* convert pc1 to bits of key */
		l=pc1[j]-1;		/* integer bit location	 */
		m = l & 07;		/* find bit		 */
		pc1m[j]=(key[l>>3] &	/* find which key byte l is in */
			bytebit[m])	/* and which bit of that byte */
			? 1 : 0;	/* and store 1-bit result */
	}
	for (i=0; i<16; i++) {		/* key chunk for each iteration */
		memset (ks,0,sizeof (ks));	/* Clear key schedule */
		for (j=0; j<56; j++)	/* rotate pc1 the right amount */
			pcr[j] = pc1m[(l = j + totrot[decrypt? 15 - i : i]) < (j < 28? 28 : 56) ? l: l - 28];
			/* rotate left and right halves independently */
		for (j=0; j<48; j++){	/* select bits individually */
			/* check bit that goes to ks[j] */
			if (pcr[pc2[j]-1]) {
				/* mask it in if it's there */
				l= j % 6;
				ks[j / 6] |= bytebit[l] >> 2;
			}
		}
		/* Now convert to packed odd/even interleaved form */
		k[i][0] = ((uint32_t) ks[0] << 24)
		 | ((uint32_t) ks[2] << 16)
		 | ((uint32_t) ks[4] << 8)
		 | ((uint32_t) ks[6]);
		k[i][1] = ((uint32_t) ks[1] << 24)
		 | ((uint32_t) ks[3] << 16)
		 | ((uint32_t) ks[5] << 8)
		 | ((uint32_t) ks[7]);
	}
}

#define KEYBITS(k,s) \
        (((k[(s) / 8] << ((s) % 8)) & 0xFF) | (k[(s) / 8 + 1] >> (8 - (s) % 8)))

/* DES utils */
/* Set up a key schedule based on a 56bit key */
static void setup_schedule (const unsigned char *key_56, DES_KS ks)
{
	unsigned char key[8];
	int i, c, bit;

	for (i = 0; i < 8; i++) {
		key[i] = KEYBITS (key_56, i * 7);

		/* Fix parity */
		for (c = bit = 0; bit < 8; bit++)
			if (key[i] & (1 << bit))
				c++;
		if (!(c & 1))
			key[i] ^= 0x01;
	}

	deskey (ks, key, 0);
}

#define LM_PASSWORD_MAGIC "\x4B\x47\x53\x21\x40\x23\x24\x25" \
                          "\x4B\x47\x53\x21\x40\x23\x24\x25" \
			  "\x00\x00\x00\x00\x00"

static void ntlm_lanmanager_hash (const char *password, char hash[21])
{
	unsigned char lm_password[15];
	DES_KS ks;
	int i;

	for (i = 0; i < 14 && password[i]; i++)
		lm_password[i] = toupper ((unsigned char) password[i]);

	for (; i < 15; i++)
		lm_password[i] = '\0';

	memcpy (hash, LM_PASSWORD_MAGIC, 21);

	setup_schedule (lm_password, ks);
	des (ks, (unsigned char *) hash);

	setup_schedule (lm_password + 7, ks);
	des (ks, (unsigned char *) hash + 8);
}

static void ntlm_nt_hash (struct oc_text_buf *pass, char hash[21])
{
	md4sum ((void *)pass->data, pass->pos, (unsigned char *) hash);
	memset (hash + 16, 0, 5);
}

static void ntlm_calc_response (const unsigned char key[21],
				const unsigned char plaintext[8],
				unsigned char results[24])
{
	DES_KS ks;

	memcpy (results, plaintext, 8);
	memcpy (results + 8, plaintext, 8);
	memcpy (results + 16, plaintext, 8);

	setup_schedule (key, ks);
	des (ks, results);

	setup_schedule (key + 7, ks);
	des (ks, results + 8);

	setup_schedule (key + 14, ks);
	des (ks, results + 16);
}

static inline uint32_t load_le32(void *_p)
{
	unsigned char *p = _p;
	return (p[3] << 24) | (p[2] << 16) | p[1] << 8 | p[0];
}
static inline uint16_t load_le16(void *_p)
{
	unsigned char *p = _p;
	return p[1] << 8 | p[0];
}

static inline void store_le32(void *_p, uint32_t v)
{
	unsigned char *p = _p;
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}
static inline void store_le16(void *_p, uint16_t v)
{
	unsigned char *p = _p;
	p[0] = v;
	p[1] = v >> 8;
}

#define NTLM_CHALLENGE_DOMAIN_OFFSET		12
#define NTLM_CHALLENGE_FLAGS_OFFSET		20
#define NTLM_CHALLENGE_NONCE_OFFSET		24

#define NTLM_RESPONSE_BASE_SIZE      64
#define NTLM_RESPONSE_LM_RESP_OFFSET 12
#define NTLM_RESPONSE_NT_RESP_OFFSET 20
#define NTLM_RESPONSE_DOMAIN_OFFSET  28
#define NTLM_RESPONSE_USER_OFFSET    36
#define NTLM_RESPONSE_HOST_OFFSET    44
#define NTLM_RESPONSE_FLAGS_OFFSET   60

static const char ntlm_response_base[NTLM_RESPONSE_BASE_SIZE] = {
	'N',  'T',  'L',  'M',  'S',  'S',  'P',  0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x82, 0x01, 0x00, 0x00
};

static int buf_append_ucs2le(struct oc_text_buf *buf, const char *utf8)
{
	int len = 0;
	unsigned char c;
	unsigned char b[2];
	int utfchar;

	/* Ick. Now I'm implementing my own UTF8 handling too. Perhaps it's
	   time to bite the bullet and start requiring something like glib? */
	while (*utf8) {
		c = *(utf8++);
		if (c < 128) {
			utfchar = c;
		} else if ((c & 0xe0) == 0xc0) {
			utfchar = (c & 0x1f) << 6;
			c = *(utf8++);
			if ((c & 0xc0) != 0x80)
				return -EINVAL;
			utfchar |= (c & 0x3f);
			if (utfchar < 0x80)
				return -EINVAL;
		} else if ((c & 0xf0) == 0xe0) {
			utfchar = (c & 0x0f) << 12;
			c = *(utf8++);
			if ((c & 0xc0) != 0x80)
				return -EINVAL;
			utfchar |= (c & 0x3f) << 6;
			c = *(utf8++);
			if ((c & 0xc0) != 0x80)
				return -EINVAL;
			utfchar |= (c & 0x3f);
			if (utfchar < 0x800)
				return -EINVAL;
		} else {
			/* We can't encode anything higher into UCS2LE so bail. */
			return -EINVAL;
		}

		b[0] = utfchar & 0xff;
		b[1] = utfchar >> 8;
		buf_append_bytes(buf, b, 2);
		len += 2;
	}
	return len;
}


static void ntlm_set_string_utf8(struct oc_text_buf *buf, int offset,
				 const char *data)
{
	int oldpos = buf->pos;
	int len = buf_append_ucs2le(buf, data);

	/* Fill in the SecurityBuffer pointing to the string */
	store_le16(buf->data + offset, len);		/* len */
	store_le16(buf->data + offset + 2, len);	/* allocated */
	store_le32(buf->data + offset + 4, oldpos);	/* offset */
}

static void ntlm_set_string_binary(struct oc_text_buf *buf, int offset,
				   const void *data, int len)
{
	/* Fill in the SecurityBuffer pointing to the string */
	store_le16(buf->data + offset, len);		/* len */
	store_le16(buf->data + offset + 2, len);	/* allocated */
	store_le32(buf->data + offset + 4, buf->pos);	/* offset */

	buf_append_bytes(buf, data, len);
}

static int ntlm_manual_challenge(struct openconnect_info *vpninfo, struct oc_text_buf *hdrbuf)
{
	struct oc_text_buf *resp, *ucs2pass;
	char *user;
	unsigned char nonce[8], hash[21], lm_resp[24], nt_resp[24];
	unsigned char *token;
	int token_len;
	int ntlmver;

	if (!vpninfo->ntlm_auth.challenge)
		return -EINVAL;

	token_len = openconnect_base64_decode(&token,
					      vpninfo->ntlm_auth.challenge);
	if (token_len < 0)
		return token_len;

	if (token_len < NTLM_CHALLENGE_NONCE_OFFSET + 8 || token[0] != 'N' ||
	    token[1] != 'T' || token[2] != 'L' || token[3] != 'M' ||
	    token[4] != 'S' || token[5] != 'S' || token[6] != 'P' ||
	    token[7] || token[8] != 2 || token[9] || token[10] || token[11]) {
		free(token);
		return -EINVAL;
	}

	ucs2pass = buf_alloc();
	if (buf_append_ucs2le(ucs2pass, vpninfo->proxy_pass) < 0 ||
	    buf_error(ucs2pass)) {
		free(token);
		return -EINVAL;
	}

	/* 0x00080000: Negotiate NTLM2 Key */
	if (token[NTLM_CHALLENGE_FLAGS_OFFSET + 2] & 8) {
		/* NTLM2 session response */
		struct {
			uint32_t srv[2];
			uint32_t clnt[2];
		} sess_nonce;
		unsigned char digest[16];

		ntlmver = 2;
		if (openconnect_random(sess_nonce.clnt, sizeof(sess_nonce.clnt))) {
			free(token);
			buf_free(ucs2pass);
			return -EIO;
		}

		/* LM response is 8-byte client nonce, NUL-padded to 24 */
		memcpy (lm_resp, sess_nonce.clnt, 8);
		memset (lm_resp + 8, 0, 16);

		/* Session nonce is client nonce + server nonce */
		memcpy (sess_nonce.srv,
			token + NTLM_CHALLENGE_NONCE_OFFSET, 8);

		/* Take MD5 of session nonce */
		if (openconnect_md5(digest, &sess_nonce, sizeof(sess_nonce))) {
			free(token);
			buf_free(ucs2pass);
			return -EIO;
		}
		ntlm_nt_hash (ucs2pass, (char *) hash);
		ntlm_calc_response (hash, digest, nt_resp);
	} else {
		/* NTLM1 */
		ntlmver = 1;
		memcpy (nonce, token + NTLM_CHALLENGE_NONCE_OFFSET, 8);
		ntlm_lanmanager_hash (vpninfo->proxy_pass, (char *) hash);
		ntlm_calc_response (hash, nonce, lm_resp);
		ntlm_nt_hash (ucs2pass, (char *) hash);
		ntlm_calc_response (hash, nonce, nt_resp);
	}
	buf_free(ucs2pass);

	resp = buf_alloc();
	buf_append_bytes(resp, ntlm_response_base, sizeof(ntlm_response_base));
	if (buf_error(resp)) {
		free(token);
		return buf_free(resp);
	}
	/* Mask in the NTLM2SESSION flag */
	resp->data[NTLM_RESPONSE_FLAGS_OFFSET + 2] = token[NTLM_CHALLENGE_FLAGS_OFFSET + 2] & 8;

	user = strchr(vpninfo->proxy_user, '\\');
	if (user) {
		*user = 0;
		ntlm_set_string_utf8(resp, NTLM_RESPONSE_DOMAIN_OFFSET, vpninfo->proxy_user);
		*user = '\\';
		user++;
	} else {
		int offset = load_le32(token + NTLM_CHALLENGE_DOMAIN_OFFSET + 4);
		int len = load_le16(token + NTLM_CHALLENGE_DOMAIN_OFFSET);
		if (!len || offset + len >= token_len) {
			free(token);
			buf_free(resp);
			return -EINVAL;
		}
		ntlm_set_string_binary(resp, NTLM_RESPONSE_DOMAIN_OFFSET, token + offset, len);

		user = vpninfo->proxy_user;
	}

	ntlm_set_string_utf8(resp, NTLM_RESPONSE_USER_OFFSET, user);
	ntlm_set_string_utf8(resp, NTLM_RESPONSE_HOST_OFFSET, "UNKNOWN");
	ntlm_set_string_binary(resp, NTLM_RESPONSE_LM_RESP_OFFSET, lm_resp, sizeof(lm_resp));
	ntlm_set_string_binary(resp, NTLM_RESPONSE_NT_RESP_OFFSET, nt_resp, sizeof(nt_resp));

	free(token);

	if (buf_error(resp))
		return buf_free(resp);

	buf_append(hdrbuf, "Proxy-Authorization: NTLM ");
	buf_append_base64(hdrbuf, resp->data, resp->pos);
	buf_append(hdrbuf, "\r\n");

	buf_free(resp);
	vpn_progress(vpninfo, PRG_INFO,
		     _("Attempting HTTP NTLMv%d authentication to proxy\n"),
		     ntlmver);
	return 0;
}

int ntlm_authorization(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	if (vpninfo->ntlm_auth.state == AUTH_AVAILABLE) {
		vpninfo->ntlm_auth.state = NTLM_MANUAL;
#ifndef _WIN32
		/* Don't attempt automatic NTLM auth if we were given a password */
		if (!vpninfo->proxy_pass && !ntlm_helper_spawn(vpninfo, buf)) {
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
			   "TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA");
		vpninfo->ntlm_auth.state = NTLM_MANUAL_REQ;
		return 0;
	}
	if (vpninfo->ntlm_auth.state == NTLM_MANUAL_REQ) {
		vpninfo->ntlm_auth.state = AUTH_FAILED;
		return ntlm_manual_challenge(vpninfo, buf);

	}
	return -EINVAL;
}
