
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

AM_CFLAGS = @WFLAGS@
AM_CPPFLAGS = -DLOCALEDIR="\"$(localedir)\""

openconnect_SOURCES = xml.c main.c
openconnect_CFLAGS = $(AM_CFLAGS) $(SSL_CFLAGS) $(DTLS_SSL_CFLAGS) $(LIBXML2_CFLAGS) $(LIBPROXY_CFLAGS) $(ZLIB_CFLAGS) $(LIBSTOKEN_CFLAGS) $(LIBOATH_CFLAGS) $(LIBPSKC_CFLAGS) $(GSSAPI_CFLAGS) $(ICONV_CFLAGS)
openconnect_LDADD = libopenconnect.la $(LIBXML2_LIBS) $(LIBPROXY_LIBS) $(LIBINTL) $(ICONV_LIBS)

library_srcs = ssl.c http.c auth.c library.c compat.c dtls.c cstp.c \
	       mainloop.c script.c ntlm.c digest.c
lib_srcs_gnutls = gnutls.c gnutls_pkcs12.c gnutls_tpm.c
lib_srcs_openssl = openssl.c
lib_srcs_win32 = tun-win32.c sspi.c
lib_srcs_posix = tun.c
lib_srcs_gssapi = gssapi.c
lib_srcs_iconv = iconv.c
lib_srcs_oath = oath.c
lib_srcs_stoken = stoken.c

POTFILES = $(openconnect_SOURCES) $(lib_srcs_openssl) $(lib_srcs_gnutls) \
	   $(library_srcs) $(lib_srcs_win32) $(lib_srcs_posix) $(lib_srcs_gssapi) \
	   $(lib_srcs_iconv) $(lib_srcs_oath) $(lib_srcs_stoken) openconnect-internal.h

if OPENCONNECT_STOKEN
library_srcs += $(lib_srcs_stoken)
endif
if OPENCONNECT_OATH
library_srcs += $(lib_srcs_oath)
endif
if OPENCONNECT_GSSAPI
library_srcs += $(lib_srcs_gssapi)
endif
if OPENCONNECT_GNUTLS
library_srcs += $(lib_srcs_gnutls)
endif
if OPENCONNECT_OPENSSL
library_srcs += $(lib_srcs_openssl)
endif
if OPENCONNECT_ICONV
library_srcs += $(lib_srcs_iconv)
endif
if OPENCONNECT_WIN32
library_srcs += $(lib_srcs_win32)
else
library_srcs += $(lib_srcs_posix)
endif

libopenconnect_la_SOURCES = version.c $(library_srcs)
libopenconnect_la_CFLAGS = $(AM_CFLAGS) $(SSL_CFLAGS) $(DTLS_SSL_CFLAGS) $(LIBXML2_CFLAGS) $(LIBPROXY_CFLAGS) $(ZLIB_CFLAGS) $(P11KIT_CFLAGS) $(TSS_CFLAGS) $(LIBSTOKEN_CFLAGS) $(LIBOATH_CFLAGS) $(LIBPSKC_CFLAGS) $(GSSAPI_CFLAGS) $(ICONV_CFLAGS)
libopenconnect_la_LIBADD = $(SSL_LIBS) $(DTLS_SSL_LIBS) $(LIBXML2_LIBS) $(LIBPROXY_LIBS) $(ZLIB_LIBS) $(LIBINTL) $(P11KIT_LIBS) $(TSS_LIBS) $(LIBSTOKEN_LIBS) $(LIBOATH_LIBS) $(LIBPSKC_LIBS) $(GSSAPI_LIBS) $(ICONV_LIBS)
if OPENBSD_LIBTOOL
# OpenBSD's libtool doesn't have -version-number, but its -version-info arg
# does what GNU libtool's -version-number does. Which arguably is what the
# GNU -version-info arg ought to do too. I hate libtool.
LT_VER_ARG = -version-info
else
LT_VER_ARG = -version-number
endif
libopenconnect_la_LDFLAGS = $(LT_VER_ARG) @APIMAJOR@:@APIMINOR@ -no-undefined
noinst_HEADERS = openconnect-internal.h openconnect.h gnutls.h
include_HEADERS = openconnect.h
if HAVE_SYMBOL_VERSIONING
libopenconnect_la_LDFLAGS += -Wl,@VERSION_SCRIPT_ARG@,libopenconnect.map
libopenconnect_la_DEPENDENCIES = libopenconnect.map
endif

if OPENCONNECT_JNI
if JNI_STANDALONE
libopenconnect_la_SOURCES += jni.c
libopenconnect_la_CFLAGS += $(JNI_CFLAGS) -Wno-missing-declarations
else
lib_LTLIBRARIES += libopenconnect-wrapper.la
libopenconnect_wrapper_la_SOURCES = jni.c
libopenconnect_wrapper_la_CFLAGS = $(AM_CFLAGS) $(JNI_CFLAGS) -Wno-missing-declarations
libopenconnect_wrapper_la_LIBADD = libopenconnect.la
endif
endif

pkgconfig_DATA = openconnect.pc

EXTRA_DIST = version.sh COPYING.LGPL $(lib_srcs_openssl) $(lib_srcs_gnutls)
EXTRA_DIST += $(shell cd "$(top_srcdir)" && \
		git ls-tree HEAD -r --name-only -- android/ java/ 2>/dev/null)

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

update-po: po/$(PACKAGE).pot
	@cd $(top_srcdir); if ! git diff-index --name-only --exit-code HEAD -- po/; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; \
	else \
		> po/LINGUAS; \
		for a in po/*.po; do \
			msgmerge -q -N -F $$a $(abs_builddir)/po/$(PACKAGE).pot > $$a.merge ; \
			msgattrib -F --no-fuzzy --no-obsolete $$a.merge > $$a ; \
			rm $$a.merge ; \
			if msgattrib --translated $$a | grep -q msgstr; then \
				echo $$a | sed 's%^po/\(.*\)\.po%\1%' >> po/LINGUAS ; \
			fi ; \
		done && \
		if ! git update-index -q --refresh --unmerged || \
		   ! git diff-index --name-only --exit-code HEAD -- po/ >/dev/null; then \
			git commit -s -m "Resync translations with sources" -- po/ ; \
		else \
			echo No changes to commit ; \
		fi; \
	fi

update-translations: po/$(PACKAGE).pot
	@cd $(top_srcdir); if ! git diff-index --name-only --exit-code HEAD -- po/; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; \
	else \
		for a in po/*.po; do \
			msgmerge -q -N -F $$a $(abs_builddir)/po/$(PACKAGE).pot > $$a.old; \
			sed '0,/^#:/d' $$a.old > $$a.old.cmp ; \
		done && \
		tx pull -af && \
		> po/LINGUAS; \
		for a in po/*.po; do \
			touch $$a.old; \
			msgmerge -q -N -F -C $$a.old $$a $(abs_builddir)/po/$(PACKAGE).pot > $$a.new ; \
			sed '0,/^#:/d' $$a.new > $$a.new.cmp ; \
			if ! git ls-tree --name-only HEAD $$a | grep -q $$a; then \
				echo New file $$a ; \
				mv $$a.new $$a; \
				git add $$a ; \
			elif ! diff -u $$a.old.cmp $$a.new.cmp; then \
				echo New changes for $$a; \
				mv $$a.new $$a; \
			else \
				git checkout -f HEAD $$a ; \
			fi ; \
			rm -f $$a.old $$a.old.cmp $$a.new $$a.new.cmp ; \
			if msgattrib --translated $$a | grep -q msgstr; then \
				echo $$a | sed 's%^po/\(.*\)\.po%\1%' >> po/LINGUAS ; \
			fi ; \
		done && \
		if ! git update-index -q --refresh --unmerged || \
		   ! git diff-index --name-only --exit-code HEAD -- po/ >/dev/null; then \
			git commit -s -m "Update translations from Transifex" -- po/ ; \
		else \
			echo No changes to commit ; \
		fi ; \
	fi

upload-pot: po/$(PACKAGE).pot
	@if [ ${abs_top_builddir} != $(abs_top_srcdir) ]; then \
		ln -sf ${abs_top_srcdir}/.tx .tx; fi
	@tx push -s

po/$(PACKAGE).pot: $(POTFILES) version.sh
	@echo "Regenerating $@" ; rm -f $@ && \
	xgettext --directory=$(top_srcdir) --from-code=UTF-8 \
	  --sort-by-file --add-comments --keyword=_ --keyword=N_ \
	  --package-name="@PACKAGE@" --package-version="@VERSION@" \
	  --msgid-bugs-address=openconnect-devel@lists.infradead.org \
	  -o $@ $(POTFILES)
