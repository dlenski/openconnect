
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

GTK_CFLAGS += $(shell pkg-config --cflags gtk+-x11-2.0)
GTK_LDFLAGS += $(shell pkg-config --libs gtk+-x11-2.0)

GCONF_CFLAGS += $(shell pkg-config --cflags gconf-2.0)
GCONF_LDFLAGS += $(shell pkg-config --libs gconf-2.0)

GNOMEUI_CFLAGS += $(shell pkg-config --cflags libgnomeui-2.0)
GNOMEUI_LDFLAGS += $(shell pkg-config --libs libgnomeui-2.0)

CFLAGS := $(OPT_FLAGS) $(SSL_CFLAGS) $(XML2_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := $(SSL_LDFLAGS) $(XML2_LDFLAGS) $(EXTRA_LDFLAGS)

CFLAGS_ssl_ui_gtk.o += $(GTK_CFLAGS)	
CFLAGS_nm-auth-dialog.o += $(GTK_CFLAGS) $(GCONF_CFLAGS) $(GNOMEUI_CFLAGS)

OPENCONNECT_OBJS := main.o ssl_ui.o xml.o
CONNECTION_OBJS := dtls.o cstp.o mainloop.o tun.o 
AUTH_OBJECTS := ssl.o http.o

all: anyconnect nm-openconnect-auth-dialog

version.h: $(patsubst %.o,%.c,$(OBJECTS)) anyconnect.h $(wildcard .git/index .git/refs/tags) version.sh
	@./version.sh
	@echo -en "New version.h: "
	@grep define version.h | cut -f2 -d\"

main.o: version.h

libopenconnect.a: $(AUTH_OBJECTS)
	$(AR) rcs $@ $^

anyconnect: $(OPENCONNECT_OBJS) $(CONNECTION_OBJS) libopenconnect.a
	$(CC) -o $@ $^ $(LDFLAGS)

nm-openconnect-auth-dialog: nm-auth-dialog.o ssl_ui_gtk.o libopenconnect.a 
	$(CC) -o $@ $^ $(LDFLAGS) $(GTK_LDFLAGS) $(GCONF_LDFLAGS) $(GNOMEUI_LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $(CFLAGS_$@) $< -MD -MF .$@.dep

clean:
	rm -f *.o anyconnect $(wildcard .*.o.dep)

install:
	mkdir -p $(DESTDIR)/usr/bin
	install -m0755 anyconnect $(DESTDIR)/usr/bin

include /dev/null $(wildcard .*.o.dep)

ifdef VERSION
tag:
	@if git diff-index --name-only HEAD | grep ^ ; then \
		echo Uncommitted changes in above files; exit 1; fi
	sed 's/^v=.*/v="v$(VERSION)"/' -i version.sh
	git commit -m "Tag version $(VERSION)" version.sh
	git tag v$(VERSION)

tarball:
	git archive --format=tar --prefix=anyconnect-$(VERSION)/ v$(VERSION) | gzip -9 > anyconnect-$(VERSION).tar.gz
endif

