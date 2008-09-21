
CFLAGS += -Lssl -I/usr/include/openssl


cisco: cisco.o
	$(CC) -o $@ $<
