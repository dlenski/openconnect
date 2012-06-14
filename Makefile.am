
SUBDIRS =
if BUILD_WWW
SUBDIRS += www
endif
if USE_NLS
SUBDIRS += po
endif

lib_LTLIBRARIES = libopenconnect.la
sbin_PROGRAMS = openconnect
man8_MANS = openconnect.8

AM_CPPFLAGS = -DLOCALEDIR="\"$(localedir)\""
openconnect_SOURCES = xml.c main.c dtls.c cstp.c mainloop.c tun.c

openconnect_CFLAGS = $(SSL_CFLAGS) $(DTLS_SSL_CFLAGS) $(LIBXML2_CFLAGS) $(LIBPROXY_CFLAGS) $(ZLIB_CFLAGS)
openconnect_LDADD = libopenconnect.la $(SSL_LIBS) $(DTLS_SSL_LIBS) $(LIBXML2_LIBS) $(LIBPROXY_LIBS) $(ZLIB_LIBS) $(LIBINTL)

library_srcs = ssl.c http.c auth.c library.c compat.c
lib_srcs_gnutls = gnutls.c gnutls_pkcs12.c
lib_srcs_openssl = openssl.c
if OPENCONNECT_GNUTLS
library_srcs += $(lib_srcs_gnutls)
endif
if OPENCONNECT_OPENSSL
library_srcs += $(lib_srcs_openssl)
endif
libopenconnect_la_SOURCES = version.c $(library_srcs)
libopenconnect_la_CFLAGS = $(SSL_CFLAGS) $(LIBXML2_CFLAGS) $(LIBPROXY_CFLAGS) $(P11KIT_CFLAGS) $(TSS_CFLAGS)
libopenconnect_la_LIBADD = $(SSL_LIBS) $(LIBXML2_LIBS) $(LIBPROXY_LIBS) $(LIBINTL) $(P11KIT_LIBS) $(TSS_LIBS)
libopenconnect_la_LDFLAGS = -version-number @APIMAJOR@:@APIMINOR@
noinst_HEADERS = openconnect-internal.h openconnect.h
include_HEADERS = openconnect.h
if HAVE_SYMBOL_VERSIONING
libopenconnect_la_LDFLAGS += -Wl,@VERSION_SCRIPT_ARG@,libopenconnect.map
libopenconnect_la_DEPENDENCIES = libopenconnect.map
endif

pkgconfig_DATA = openconnect.pc

EXTRA_DIST = version.sh COPYING.LGPL $(lib_srcs_openssl) $(lib_srcs_gnutls)

DISTCLEANFILES = $(pkgconfig_DATA)

main.o: version.c
version.c: $(library_srcs) $(lib_openssl_srcs) $(lib_gnutls_srcs) \
	   $(openconnect_SOURCES) Makefile.am configure.ac \
	   openconnect.h openconnect-internal.h version.sh @GITVERSIONDEPS@
	@cd $(srcdir) && ./version.sh $(abs_builddir)/version.c

tmp-dist: uncommitted-check
	$(MAKE) $(AM_MAKEFLAGS) VERSION=$(patsubst v%,%,$(shell git describe --tags)) DISTHOOK=0 dist

uncommitted-check:
	@if ! git update-index --refresh --unmerged || \
	    ! git diff-index --name-only --exit-code HEAD; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; fi

DISTHOOK=1
dist-hook: uncommitted-check
	@if [ $(DISTHOOK) = 1 ]; then \
	    if ! git rev-parse --verify v$(VERSION) &> /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is not tagged"; exit 1; fi ; \
	    if ! git diff --name-only --exit-code v$(VERSION) HEAD > /dev/null; then \
		echo "*** ERROR: Git checkout not at version v$(VERSION)"; exit 1; fi ; \
	fi

sign-dist: dist
	@for a in $(DIST_ARCHIVES); do \
		gpg --default-key 67E2F359 --detach-sign -a $$a ; \
	done

tag: uncommitted-check
	@if git rev-parse --verify v$(VERSION) &> /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is already tagged"; exit 1; fi
	@sed 's/AC_INIT.*/AC_INIT(openconnect, $(VERSION))/' -i $(srcdir)/configure.ac
	@sed 's/^v=.*/v="v$(VERSION)"/' -i $(srcdir)/version.sh
	@( echo '1,/<!-- latest-release-start -->/p' ;\
	   echo '/<!-- latest-release-end -->/,$$p' ;\
	   echo  '/<!-- latest-release-start -->/a\' ;\
	   echo  'The latest release is <a href="ftp://ftp.infradead.org/pub/openconnect/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a>\' ;\
	   echo  '<i>(<a href="ftp://ftp.infradead.org/pub/openconnect/openconnect-$(VERSION).tar.gz.asc">PGP signature</a>)</i>,\' ;\
	   echo 'released on $(shell date +%Y-%m-%d) with the following changelog:</p>\' ;\
	   sed '0,/<b>OpenConnect HEAD/d;/<\/ul><br\/>/,$$d;s/$$/\\/' $(srcdir)/www/changelog.xml ;\
	   echo '     </ul>' ) | \
	 sed -n -f - -i $(srcdir)/www/download.xml
	@( echo "s/Last modified: .*/Last modified: $(shell date)/" ;\
	   echo '/  <li><b>OpenConnect HEAD/a\' ;\
	   echo '     <ul>\' ;\
	   echo '       <li><i>No changelog entries yet</i></li>\';\
	   echo '     </ul><br/>\' ;  echo '  </li>\' ;\
	   echo '  <li><b><a href="ftp://ftp.infradead.org/pub/openconnect/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a></b>\' ;\
	   echo '     <i>(<a href="ftp://ftp.infradead.org/pub/openconnect/openconnect-$(VERSION).tar.gz.asc">PGP signature</a>)</i> &#8212; $(shell date +%Y-%m-%d)' ) | \
		sed -f - -i $(srcdir)/www/changelog.xml
# stupid syntax highlighting '
	@cd $(srcdir) && git commit -s -m "Tag version $(VERSION)" configure.ac version.sh www/download.xml www/changelog.xml
	@git tag v$(VERSION)
	@cd $(srcdir) && ./autogen.sh

update-translations:
	@cd $(top_srcdir); if ! git diff-index --name-only --exit-code HEAD -- po/; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; \
	else \
		tx pull -af ; git commit -s -m "Update translations from Transifex" -- po/ ; \
	fi

upload-pot:
	if [ ${abs_top_builddir} != $(abs_top_srcdir) ]; then \
		ln -sf ${abs_top_srcdir}/.tx .tx; fi
	@make -C po openconnect.pot && tx push -s
