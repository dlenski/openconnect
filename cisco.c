#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

#if 0
/* If the cookie expires, you can get another one by connecting with 
   the certificate:

openssl s_client -cert mycert.pem -connect vpnserver:443 -crlf
GET /+webvpn+/index.html HTTP/1.1
User-Agent: AnyConnect Linux 2.2.0133
Host: localhost
Accept: */*
Accept-Encoding: identity
X-Transcend-Version: 1

#endif

char request[] = "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"
	"Host: vpnserver\r\n"
	"User-Agent: Cisco AnyConnect VPN Agent for Windows 2.2.0\r\n"
	"Cookie: webvpn=835267836@921600@1221512527@6BC73D90EB2F59E242F75B424D42F223D0912984\r\n"
	"X-CSTP-Version: 1\r\n"
	"X-CSTP-Hostname: macbook.infradead.org\r\n"
	"X-CSTP-Accept-Encoding: xxdeflate;q=1.0\r\n"
	"X-CSTP-MTU: 1406\r\n"
	"X-CSTP-Address-Type: IPv6,IPv4\r\n"
	"X-DTLS-Master-Secret: 5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A\r\n"
	"X-DTLS-CipherSuite: AES256-SHA:AES128-SHA:DES-CBC3-SHA:DES-CBC-SHA\r\n\r\n";

/* The master-secret is generated randomly by the client. The server
   responds with a DTLS Session-ID. These are enough to 'resume' the DTLS
   session, bypassing all the initial setup of a normal DTLS connection.
   Or you can just send traffic over the HTTPS connection... */

int main(int argc, char **argv)
{
	int in_pipes[2];
	int out_pipes[2];
	pid_t ssl_pid;
	unsigned char buf[65536 + 8];
	int buflen;
	int state = 0;
	struct ifreq ifr;
	int tun_fd;

	tun_fd = open("/dev/net/tun", O_RDWR);
	if (tun_fd == -1) {
		perror("open tun");
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, "cisco0", sizeof(ifr.ifr_name) - 1);
	if (ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0){
		perror("TUNSETIFF");
		exit(1);
	}

	pipe(in_pipes);
	pipe(out_pipes);

	ssl_pid = fork();
	if (!ssl_pid) {
		dup2(out_pipes[0], 0);
		dup2(in_pipes[1], 1);

		close(in_pipes[0]);
		close(in_pipes[1]);
		close(out_pipes[0]);
		close(out_pipes[1]);
		execlp("openssl", "openssl", "s_client", "-quiet", "-connect", "vpnserver:443", NULL);
		perror("exec");
		exit(1);
	}

	write(out_pipes[1], request, sizeof(request));
	while (state < 4) {
		read(in_pipes[0], buf, 1);
		if ((state == 0 || state == 2) &&
		    buf[0] == '\r')
			state++;
		else if ((state == 1 || state == 3) &&
		    buf[0] == '\n')
			state++;
		else state = 0;
		write(1, buf, 1);
	}
	printf("Connected\n");

	if (fork()) {
		while (1) {
			size_t len;

			buf[0] = 'S';
			buf[1] = 'T';
			buf[2] = 'F';
			buf[3] = 1;
			buf[4] = 0;
			buf[5] = 0;
			buf[6] = 0;
			buf[7] = 0;
				
			len = read(tun_fd, &buf[8], 65536);
			if (len >= 0) {
				buf[4] = len >> 8;
				buf[5] = len & 0xff;
			}
			write(out_pipes[1], buf, len + 8);
		}
	} else {
		while (1) {
			int len;
			read(in_pipes[0], buf, 8);
			
			len = (buf[4] << 8) + buf [5];
			read(in_pipes[0], buf + 8, len);
			if (buf[0] != 'S' ||
			    buf[1] != 'T' ||
			    buf[2] != 'F' ||
			    buf[3] != 1 ||
			    buf[6] != 0 ||
			    buf[7] != 0) {
				printf("Unknown packet %02x %02x %02x %02x %02x %02x %02x %02x\n",
				       buf[0], buf[1], buf[2], buf[3],
				       buf[4], buf[5], buf[6], buf[7]);
			} else {
				write(tun_fd, buf + 8, len);
			}
		}
	}
}
