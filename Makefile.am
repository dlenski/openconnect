
SUBDIRS =
if BUILD_WWW
SUBDIRS += www
endif
if USE_NLS
SUBDIRS += po
endif

lib_LTLIBRARIES = libopenconnect.la
bin_PROGRAMS = openconnect
man8_MANS = openconnect.8

openconnect_SOURCES = xml.c main.c dtls.c cstp.c mainloop.c tun.c

openconnect_CFLAGS = $(OPENSSL_CFLAGS) $(LIBXML2_CFLAGS) $(LIBPROXY_CFLAGS) $(ZLIB_CFLAGS)
openconnect_LDADD = libopenconnect.la $(OPENSSL_LIBS) $(LIBXML2_LIBS) $(LIBPROXY_LIBS) $(ZLIB_LIBS)

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

tmp-dist: uncommitted-check
	$(MAKE) $(AM_MAKEFLAGS) VERSION=$(patsubst v%,%,$(shell git describe --tags)) NODISTHOOK=1 dist

uncommitted-check:
	@if ! git update-index --refresh --unmerged || \
	    ! git diff-index --name-only --exit-code HEAD; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; fi

dist-hook: uncommitted-check
 ifndef NODISTHOOK
	@if ! git rev-parse --verify v$(VERSION) &> /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is not tagged"; exit 1; fi
	@if ! git diff --name-only --exit-code v$(VERSION) HEAD > /dev/null; then \
		echo "*** ERROR: Git checkout not at version v$(VERSION)"; exit 1; fi
 endif

tag: uncommitted-check
	@if git rev-parse --verify v$(VERSION) &> /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is already tagged"; exit 1; fi
	@sed 's/AC_INIT.*/AC_INIT(openconnect, $(VERSION))/' -i configure.ac
	@sed 's/^v=.*/v="v$(VERSION)"/' -i version.sh
	@( echo '1,/<!-- latest-release-start -->/p' ;\
	   echo '/<!-- latest-release-end -->/,$$p' ;\
	   echo  '/<!-- latest-release-start -->/a\' ;\
	   echo  'The latest release is <a href="ftp://ftp.infradead.org/pub/openconnect/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a>, released on $(shell date +%Y-%m-%d) with the following changelog:</p>\' ;\
	   sed '0,/<b>OpenConnect HEAD/d;/<\/ul><br\/>/,$$d;s/$$/\\/' www/changelog.xml ;\
	   echo '     </ul>' ) | \
	 sed -n -f - -i www/download.xml
	@( echo "s/Last modified: .*/Last modified: $(shell date)/" ;\
	   echo '/  <li><b>OpenConnect HEAD/a\' ;\
	   echo '     <ul>\' ;\
	   echo '       <li><i>No changelog entries yet</i></li>\';\
	   echo '     </ul><br/>\' ;  echo '  </li>\' ;\
	   echo '  <li><b><a href="ftp://ftp.infradead.org/pub/openconnect/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a></b> &#8212; $(shell date +%Y-%m-%d)' ) | \
		sed -f - -i www/changelog.xml
# stupid syntax highlighting '
	@git commit -s -m "Tag version $(VERSION)" configure.ac version.sh www/download.xml www/changelog.xml
	@git tag v$(VERSION)
	@./autogen.sh

update-translations:
	@if ! git diff-index --name-only --exit-code HEAD -- po/; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; fi
	@tx pull -af
	@git commit -s -m "Update translations from Transifex" -- po/

