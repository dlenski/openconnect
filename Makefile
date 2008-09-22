
ifdef RPM_OPT_FLAGS
CFLAGS := $(RPM_OPT_FLAGS)
else
CFLAGS := -O2 -g -Wall
endif

CFLAGS += -I/usr/include/openssl #-I/usr/include/libxml2
LDFLAGS += -lssl

OBJECTS := cisco.o tun.o dtls.o ssl.o

cisco: $(OBJECTS)
	$(CC) -o $@ $(LDFLAGS) $^

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $< -MD -MF .$@.dep

clean:
	rm -f $(OBJECTS) cisco $(wildcard .*.o.dep)

include /dev/null $(wildcard .*.o.dep)

