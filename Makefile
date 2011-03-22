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
SSL_LDFLAGS += $(OPENSSL)/libssl.a $(OPENSSL)/libcrypto.a
else
SSL_CFLAGS += $(shell pkg-config --cflags libssl)
SSL_LDFLAGS += $(shell pkg-config --libs libssl)
ifeq ($(SSL_LDFLAGS),)
$(error "No OpenSSL support. Cannot continue");
endif
endif

XML2_CFLAGS += $(shell xml2-config --cflags) 
XML2_LDFLAGS += $(shell xml2-config --libs)
ifeq ($(XML2_LDFLAGS),)
$(error "No libxml2 support. Cannot continue");
endif

CFLAGS := $(OPT_FLAGS) $(SSL_CFLAGS) $(XML2_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := -lz $(SSL_LDFLAGS) $(XML2_LDFLAGS) $(EXTRA_LDFLAGS)

ifdef SSL_UI
CFLAGS += -DSSL_UI
endif

-include Make.config

ifneq ($(IF_TUN_HDR),)
CFLAGS_tun.o += -DIF_TUN_HDR=\"$(IF_TUN_HDR)\"
endif

ifneq ($(LIBPROXY_HDR),)
CFLAGS += -DOPENCONNECT_LIBPROXY -DLIBPROXY_HDR=\"$(LIBPROXY_HDR)\"
LDFLAGS += -lproxy
endif

OPENCONNECT_OBJS := xml.o main.o $(SSL_UI)
CONNECTION_OBJS := dtls.o cstp.o mainloop.o tun.o 
AUTH_OBJECTS := ssl.o http.o version.o auth.o library.o

VERSION_OBJS := $(filter-out version.o, \
		$(OPENCONNECT_OBJS) $(CONNECTION_OBJS) $(AUTH_OBJECTS))

.PHONY: all clean realclean install tag tarball openconnect.pc

all: openconnect

libopenconnect.a: ${AUTH_OBJECTS}
	$(AR) rcs $@ $^

version.c: $(patsubst %.o,%.c,$(VERSION_OBJS)) Makefile openconnect.h \
	   openconnect-internal.h $(wildcard .git/index .git/refs/tags) \
	   version.sh
	@./version.sh

openconnect: $(OPENCONNECT_OBJS) $(CONNECTION_OBJS) libopenconnect.a
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $(CFLAGS_$@) $< -MD -MF .$@.dep

clean:
	rm -f *.o *.a openconnect $(wildcard .*.o.dep .*.h.dep) Make.config openconnect.pc

realclean: clean
	rm -f *~

install: all
	mkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/share/man/man8
	install -m 0755 openconnect $(DESTDIR)/usr/bin
	install -m 0644 openconnect.8 $(DESTDIR)/usr/share/man/man8

include /dev/null $(wildcard .*.o.dep)

HDRTEST = for a in $2 ; do if echo "\#include <$$a>" | $(CC) -o/dev/null -xc - -M -MF $1 -MP -MT Make.config 2>/dev/null; then \
		echo $$a; break ; fi; done

Make.config: LIBPROXY_H = $(shell $(call HDRTEST,.libproxy.h.dep,proxy.h libproxy/proxy.h))
Make.config: IF_TUN_H = $(shell $(call HDRTEST,.if_tun.h.dep, linux/if_tun.h net/if_tun.h net/tun/if_tun.h))
Make.config: Makefile
	( echo "IF_TUN_HDR := $(IF_TUN_H)"; echo "LIBPROXY_HDR := $(LIBPROXY_H)" ) > $@

-include Make.config

INCDIR := /usr/include
LIBDIR := /usr/lib
PKGCONFIGDIR := ${LIBDIR}/pkgconfig
ifeq ($(LIBPROXY_HDR),)
LIBPROXYPC :=
else
LIBPROXYPC := libproxy-1.0
endif

openconnect.pc: VERSION = $(shell sed 's/.*v\(.*\)";/\1/' version.c)
openconnect.pc: openconnect.pc.in version.c
	sed -e 's^VERSION^$(VERSION)^' -e 's^LIBDIR^$(LIBDIR)^' -e 's^LIBPROXY^$(LIBPROXYPC)^' $< > $@

install-lib: libopenconnect.a openconnect.pc
	install -D -m 0644 libopenconnect.a $(DESTDIR)$(LIBDIR)/libopenconnect.a
	install -D -m 0644 openconnect.pc $(DESTDIR)$(PKGCONFIGDIR)/openconnect.pc
	install -D -m 0644 openconnect.h $(DESTDIR)$(INCDIR)/openconnect.h

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

