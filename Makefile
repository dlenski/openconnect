#
# in order to use a private copy of openssl instead of the installed one,
# set OPENSSL to the path to the source directory that you built openssl in
#
# OPENSSL := ../openssl-0.9.8i

ifdef RPM_OPT_FLAGS
OPT_FLAGS := $(RPM_OPT_FLAGS)
else
OPT_FLAGS := -O2 -g -Wall
endif

# Allow people to override OpenSSL and build it statically, if they need
# a special build for the DTLS support. $(OPENSSL) points to the build 
# dir; there's no need to install it anywhere (we link it statically).
ifdef OPENSSL
SSL_CFLAGS += -I$(OPENSSL)/include
SSL_LDFLAGS += -lz $(OPENSSL)/libssl.a $(OPENSSL)/libcrypto.a -ldl
else
ifeq ($(wildcard /usr/include/openssl),)
$(error "No OpenSSL in /usr/include/openssl. Cannot continue");
endif
SSL_CFLAGS += -I/usr/include/openssl
SSL_LDFLAGS += -lcrypto -lssl
endif

XML2_CFLAGS += $(shell xml2-config --cflags) 
XML2_LDFLAGS += $(shell xml2-config --libs)
ifeq ($(XML2_LDFLAGS),)
$(error "No libxml2 support. Cannot continue");
endif

GTK_CFLAGS += $(shell pkg-config --cflags gtk+-x11-2.0 gthread-2.0 2>/dev/null)
GTK_LDFLAGS += $(shell pkg-config --libs gtk+-x11-2.0 gthread-2.0 2>/dev/null)
ifeq ($(GTK_LDFLAGS),)
MISSINGPKGS += gtk+-x11-2.0
endif

GCONF_CFLAGS += $(shell pkg-config --cflags gconf-2.0 2>/dev/null)
GCONF_LDFLAGS += $(shell pkg-config --libs gconf-2.0 2>/dev/null)
ifeq ($(GCONF_LDFLAGS),)
MISSINGPKGS += gconf-2.0
endif

CFLAGS := $(OPT_FLAGS) $(SSL_CFLAGS) $(XML2_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := $(SSL_LDFLAGS) $(XML2_LDFLAGS) $(EXTRA_LDFLAGS)

ifdef SSL_UI
CFLAGS += -DSSL_UI
endif

CFLAGS_nm-auth-dialog.o += $(GTK_CFLAGS) $(GCONF_CFLAGS) $(XML2_CFLAGS)

OPENCONNECT_OBJS := main.o $(SSL_UI) xml.o
CONNECTION_OBJS := dtls.o cstp.o mainloop.o tun.o 
AUTH_OBJECTS := ssl.o http.o version.o securid.o auth.o

VERSION_OBJS := $(filter-out version.o, \
		$(OPENCONNECT_OBJS) $(CONNECTION_OBJS) $(AUTH_OBJECTS))

all: openconnect maybe-auth-dialog

version.c: $(patsubst %.o,%.c,$(VERSION_OBJS)) Makefile openconnect.h \
		$(wildcard .git/index .git/refs/tags) version.sh
	@./version.sh

openconnect: $(OPENCONNECT_OBJS) $(CONNECTION_OBJS) $(AUTH_OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

ifeq ($(MISSINGPKGS),)
maybe-auth-dialog: nm-openconnect-auth-dialog
else
maybe-auth-dialog: $(warning Cannot build NetworkManager auth-dialog:) \
		   $(warning Missing pkg-config packages: $(MISSINGPKGS))
endif

nm-openconnect-auth-dialog: nm-auth-dialog.o $(AUTH_OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) $(GTK_LDFLAGS) $(GCONF_LDFLAGS) $(XML2_LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $(CFLAGS_$@) $< -MD -MF .$@.dep

clean:
	rm -f *.o *.a openconnect $(wildcard .*.o.dep)

install:
	mkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/libexec
	install -m0755 openconnect $(DESTDIR)/usr/bin
	install -m0755 nm-openconnect-auth-dialog $(DESTDIR)/usr/libexec

include /dev/null $(wildcard .*.o.dep)

ifdef VERSION
tag:
	@git update-index --refresh --unmerged
	@if git diff-index --name-only HEAD | grep ^ ; then \
		echo Uncommitted changes in above files; exit 1; fi
	@sed 's/^v=.*/v="v$(VERSION)"/' -i version.sh
	@( echo "s/Last modified: .*/Last modified: $(shell date)/" ;\
	   echo '/  <LI><B>OpenConnect HEAD/a\' ;\
	   echo '     <UL>\' ;\
	   echo '       <LI><I>No changelog entries yet</I></LI>\';\
	   echo '     </UL><BR>\' ;  echo '  </LI>\' ;\
	   echo '  <LI><B><A HREF="ftp://ftp.infradead.org/pub/openconnect/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a></B> &mdash; $(shell date +%Y-%m-%d)<BR>' ) | \
		sed -f - -i openconnect.html
# stupid syntax highlighting '
	@git commit -s -m "Tag version $(VERSION)" version.sh openconnect.html
	@git tag v$(VERSION)

tarball: version.c
	@if ! grep -q '"v$(VERSION)"' version.c; then \
		echo "Tree not at v$(VERSION)"; exit 1 ; fi
	@git update-index --refresh --unmerged
	@if git diff-index --name-only HEAD | grep ^ ; then \
		echo Uncommitted changes in above files; exit 1; fi
	git add -f version.c
	git write-tree 
	git commit -m "add version.c for v$(VERSION)" version.c
	git archive --format=tar --prefix=openconnect-$(VERSION)/ `git write-tree` | gzip -9 > openconnect-$(VERSION).tar.gz
	git reset v$(VERSION)
	git gc --prune
endif

