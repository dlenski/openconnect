
CFLAGS += -I/usr/include/openssl -g -I/usr/include/libxml2 -Wall


cisco: cisco.o tun.o dtls.o ssl.o
	$(CC) -o $@ -lssl $^
