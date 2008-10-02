
ifdef RPM_OPT_FLAGS
OPT_FLAGS := $(RPM_OPT_FLAGS)
else
OPT_FLAGS := -O2 -g -Wall
endif

# Allow people to override OpenSSL and build it statically, if they need
# a special build for the DTLS support
ifdef OPENSSL
SSL_CFLAGS += -I$(OPENSSL)/include
SSL_LDFLAGS += -lz $(OPENSSL)/libssl.a $(OPENSSL)/libcrypto.a -ldl
else
SSL_CFLAGS += -I/usr/include/openssl
SSL_LDFLAGS += -lssl
endif

XML2_CFLAGS += $(shell xml2-config --cflags) 
XML2_LDFLAGS += $(shell xml2-config --libs)

CFLAGS := $(OPT_FLAGS) $(SSL_CFLAGS) $(XML2_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := $(SSL_LDFLAGS) $(XML2_LDFLAGS) $(EXTRA_LDFLAGS)

OBJECTS := main.o tun.o dtls.o ssl.o mainloop.o xml.o http.o

all: anyconnect getwebvpn

version.h: $(patsubst %.o,%.c,$(OBJECTS)) anyconnect.h $(wildcard .git/index .git/refs/tags) version.sh
	@./version.sh
	@echo -en "New version.h: "
	@grep define version.h | cut -f2 -d\"

main.o: version.h

anyconnect: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $< -MD -MF .$@.dep

getwebvpn: curl.c
	$(CC) -o $@ -I/usr/include/libxml2 $< -lcurl -lxml2

clean:
	rm -f $(OBJECTS) anyconnect getwebvpn $(wildcard .*.o.dep)

install:
	mkdir -p $(DESTDIR)/usr/bin
	install -m0755 anyconnect $(DESTDIR)/usr/bin

include /dev/null $(wildcard .*.o.dep)
