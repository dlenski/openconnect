

lib_LTLIBRARIES = libopenconnect.la
bin_PROGRAMS = openconnect
man8_MANS = openconnect.8

openconnect_SOURCES = xml.c main.c dtls.c cstp.c mainloop.c tun.c

openconnect_CFLAGS = $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS) $(LIBPROXY_CFLAGS)
openconnect_LDADD = libopenconnect.la $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(LIBPROXY_LIBS)

libopenconnect_la_SOURCES = ssl.c http.c version.c auth.c library.c
libopenconnect_la_CFLAGS = $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS) $(LIBPROXY_CFLAGS)
libopenconnect_la_LIBADD = $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(LIBPROXY_LIBS)
libopenconnect_la_LDFLAGS = -version-number 1:2
noinst_HEADERS = openconnect-internal.h openconnect.h
include_HEADERS = openconnect.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = openconnect.pc

EXTRA_DIST = version.sh openconnect.html openconnect.8 COPYING.LGPL

DISTCLEANFILES = $(pkgconfig_DATA) version.c

version.c: $(filter-out version.c, $(libopenconnect_la_SOURCES)) \
	   $(openconnect_SOURCES) Makefile.am configure.ac \
	   openconnect.h openconnect-internal.h version.sh \
	   $(wildcard .git/index .git/refs/tags)
	@./version.sh

dist-hook:
	@if ! git rev-parse --verify v$(VERSION) > /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is not tagged"; exit 1; fi
	@if ! git diff --name-only --exit-code v$(VERSION) HEAD > /dev/null; then \
		echo "*** ERROR: Git checkout not at version v$(VERSION)"; exit 1; fi
	@git update-index --refresh --unmerged
	@if ! git diff-index --name-only --exit-code HEAD; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; fi

 ifdef VERSION
tag:
	@git update-index --refresh --unmerged
	@if ! git diff-index --name-only --exit-code HEAD; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; fi
	@sed 's/AC_INIT.*/AC_INIT(openconnect, $(VERSION))/' -i configure.ac
	@sed 's/^v=.*/v="v$(VERSION)"/' -i version.sh
	@( echo "s/Last modified: .*/Last modified: $(shell date)/" ;\
	   echo '/  <LI><B>OpenConnect HEAD/a\' ;\
	   echo '     <UL>\' ;\
	   echo '       <LI><I>No changelog entries yet</I></LI>\';\
	   echo '     </UL><BR>\' ;  echo '  </LI>\' ;\
	   echo '  <LI><B><A HREF="ftp://ftp.infradead.org/pub/openconnect/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a></B> &mdash; $(shell date +%Y-%m-%d)<BR>' ) | \
		sed -f - -i openconnect.html
# stupid syntax highlighting '
	@git commit -s -m "Tag version $(VERSION)" configure.ac version.sh openconnect.html
	@git tag v$(VERSION)
	@./autogen.sh

 endif
