#
# This Makefile attempts to build OpenConnect and its dependencies for Android
#
# It doesn't do a stunning job of tracking changes in the dependencies and
# automatically rebuilding them, but it's good enough for getting them built
# and installed into its own local sysroot.
#
# As long as you have the Android NDK toolchain on your path, you should then
# be able to edit fairly much anything in place and rebuild it locally.
#
# It should also be fairly simple to extend this to cross-compile for any target

NDK     := /opt/android-sdk-linux_x86/android-ndk-r8d/
ARCH    := arm
APIVER  := 14
TRIPLET := arm-linux-androideabi
GCCVER  := 4.6

NDK_SYSROOT := $(NDK)/platforms/android-$(APIVER)/arch-$(ARCH)
OC_SYSROOT  := $(shell pwd)/sysroot

OPENSSL_VER := 1.0.1e

PATH := $(NDK)/toolchains/$(TRIPLET)-$(GCCVER)/prebuilt/linux-x86/bin:$(PATH)
PKG_CONFIG_LIBDIR=$(OC_SYSROOT)/lib/pkgconfig
export PATH PKG_CONFIG_LIBDIR


MAKEINSTALL=$(MAKE) INSTALL=$(shell pwd)/install_symlink.sh

CONFIGURE_ARGS := --host=$(TRIPLET) --prefix=$(OC_SYSROOT) \
		  --disable-shared --enable-static \
		  CFLAGS="--sysroot=$(NDK_SYSROOT)"

all: openconnect

#####################################################################
#
# Build libxml2 with minimal configuration for OpenConnect
#
LIBXML2_VER := 2.9.0
LIBXML2_DIR := libxml2-$(LIBXML2_VER)

libxml2-$(LIBXML2_VER).tar.gz:
	curl ftp://xmlsoft.org/libxml2/libxml2-$(LIBXML2_VER).tar.gz -o $@.tmp && mv $@.tmp $@

$(LIBXML2_DIR)/configure: libxml2-$(LIBXML2_VER).tar.gz
	tar xfz $<

$(LIBXML2_DIR)/Makefile: $(LIBXML2_DIR)/configure
	cd libxml2-$(LIBXML2_VER) && ./configure $(CONFIGURE_ARGS) \
	    --without-c14n -without-catalog --without-debug --without-docbook \
	    --without-fexceptions --without-ftp --without-history \
	    --without-html --without-http --without-iconv --without-iconv \
	    --without-iso8859x --without-legacy --without-pattern \
	    --without-push --without-regexps --without-run-debug \
	    --without-sax1 --without-schemas --without-schematron \
	    --without-threads --without-valid --without-xinclude \
	    --without-xpath --without-xptr --without-zlib --without-lzma \
	    --without-coverage --without-python

$(LIBXML2_DIR)/libxml2.la: $(LIBXML2_DIR)/Makefile
	$(MAKE) -C libxml2-$(LIBXML2_VER) libxml2.la

$(LIBXML2_DIR)/libxml-2.0.pc: $(LIBXML2_DIR)/Makefile
	$(MAKE) -C libxml2-$(LIBXML2_VER) libxml-2.0.pc

$(OC_SYSROOT)/lib/libxml2.la: $(LIBXML2_DIR)/libxml2.la
	$(MAKEINSTALL) -C libxml2-$(LIBXML2_VER) install-libLTLIBRARIES

$(OC_SYSROOT)/lib/pkgconfig/libxml-2.0.pc: $(LIBXML2_DIR)/libxml-2.0.pc
	$(MAKEINSTALL) -C libxml2-$(LIBXML2_VER) install-data

LIBXML_DEPS := $(OC_SYSROOT)/lib/libxml2.la $(OC_SYSROOT)/lib/pkgconfig/libxml-2.0.pc

libxml: $(LIBXML_DEPS)


#####################################################################
#
# Build OpenSSL for Android
#
OPENSSL_VER := 1.0.1e
OPENSSL_DIR := openssl-$(OPENSSL_VER)

openssl-$(OPENSSL_VER).tar.gz:
	curl http://www.openssl.org/source/openssl-$(OPENSSL_VER).tar.gz -o $@.tmp && mv $@.tmp $@

$(OPENSSL_DIR)/Configure: openssl-$(OPENSSL_VER).tar.gz
	tar xfz $<
	cd openssl-$(OPENSSL_VER) && patch -p1 < ../0001-Check-DTLS_BAD_VER-for-version-number.patch
	touch $(OPENSSL_DIR)/Configure # Make sure it's newer than Makefile and tarball

$(OPENSSL_DIR)/Makefile: $(OPENSSL_DIR)/Configure
	cd $(OPENSSL_DIR) && perl Configure --prefix=$(OC_SYSROOT) \
		--cross-compile-prefix=$(TRIPLET)- no-shared \
		android-armv7:"gcc --sysroot=$(NDK_SYSROOT)"

$(OPENSSL_DIR)/libssl.a: $(OPENSSL_DIR)/Makefile
	$(MAKE) -C $(OPENSSL_DIR)

$(OC_SYSROOT)/lib/libssl.a: $(OPENSSL_DIR)/libssl.a
	# Do this manually instead of using 'make install' since we want symlinks
	mkdir -p $(OC_SYSROOT)/include/openssl
	ln -sf $(shell pwd)/$(OPENSSL_DIR)/include/openssl/*.h $(OC_SYSROOT)/include/openssl
	mkdir -p $(OC_SYSROOT)/lib/pkgconfig
	ln -sf $(shell pwd)/$(OPENSSL_DIR)/*.pc $(OC_SYSROOT)/lib/pkgconfig
	ln -sf $(shell pwd)/$(OPENSSL_DIR)/*.a $(OC_SYSROOT)/lib

OPENSSL_DEPS := $(OC_SYSROOT)/lib/libssl.a

openssl: $(OPENSSL_DEPS)

#####################################################################
#
# Build OpenConnect for Android
#

ocbuild/Makefile: $(OPENSSL_DEPS) $(LIBXML_DEPS)
	mkdir -p ocbuild
	cd ocbuild && ../../configure $(CONFIGURE_ARGS) \
	CFLAGS="--sysroot=$(NDK_SYSROOT) -DNO_BROKEN_DTLS_CHECK -DANDROID"

openconnect: ocbuild/Makefile
	make -C ocbuild
