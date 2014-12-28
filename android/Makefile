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

NDK     := /opt/android-sdk-linux_x86/android-ndk-r10d/
ARCH    := arm

# You should be able to just 'make ARCH=x86' and it should DTRT.
ifeq ($(ARCH),arm)
TRIPLET := arm-linux-androideabi
OPENSSL_TARGET := android-armv7
EXTRA_CFLAGS := -march=armv7-a
endif
ifeq ($(ARCH),x86)
TRIPLET := i686-linux-android
OPENSSL_TARGET := android-x86
endif
ifeq ($(ARCH),mips)
TRIPLET := mipsel-linux-android
OPENSSL_TARGET := android
EXTRA_LDFLAGS := -lz
endif

TOPDIR := $(shell pwd)
DESTDIR := $(TOPDIR)/$(TRIPLET)/out

TOOLCHAIN := $(TOPDIR)/$(TRIPLET)/toolchain
TOOLCHAIN_BUILT := $(TOOLCHAIN)/.built
TOOLCHAIN_OPTS := --platform=android-14 --arch=$(ARCH) \
		  --install-dir=$(TOOLCHAIN)
PATH := $(TOOLCHAIN)/bin:$(PATH)

OC_SYSROOT := $(TOOLCHAIN)/sysroot/usr
PKG_CONFIG_LIBDIR := $(OC_SYSROOT)/lib/pkgconfig

export PATH PKG_CONFIG_LIBDIR

# PKG_CONFIG_LIBDIR gets exported to sub-makes, but not to $(shell
PKG_CONFIG := PKG_CONFIG_LIBDIR=$(PKG_CONFIG_LIBDIR) pkg-config

MAKEINSTALL=$(MAKE) INSTALL=$(TOPDIR)/install_symlink.sh
FETCH=$(TOPDIR)/fetch.sh

CONFIGURE_ARGS := --host=$(TRIPLET) --prefix=$(OC_SYSROOT) \
		  --disable-shared --enable-static \
		  CFLAGS="$(EXTRA_CFLAGS)"

SOURCE_LIST = $(LIBXML2_SRC)/configure $(GMP_SRC)/configure \
	$(NETTLE_SRC)/configure $(GNUTLS_SRC)/configure \
	$(STOKEN_SRC)/configure $(OATH_SRC)/configure

PKG_LIST := LIBXML2 OPENSSL GMP NETTLE GNUTLS STOKEN OATH

MIRROR_TEST_TARGETS := $(addprefix mirror-test-,$(PKG_LIST))

all: openconnect

#####################################################################
#
# Install a local cross toolchain + sysroot
#
# (The fallback logic is because NDK versions <= r8e can fail after trying to
# use 32-bit binaries on a 64-bit NDK installation.)
#
$(TOOLCHAIN_BUILT):
	mkdir -p $(TOOLCHAIN)
	$(NDK)/build/tools/make-standalone-toolchain.sh $(TOOLCHAIN_OPTS) || \
		$(NDK)/build/tools/make-standalone-toolchain.sh \
			$(TOOLCHAIN_OPTS) --system=linux-x86_64
	touch $@

#####################################################################
#
# Build libxml2 with minimal configuration for OpenConnect
#
LIBXML2_VER := 2.9.0
LIBXML2_TAR := libxml2-$(LIBXML2_VER).tar.gz
LIBXML2_SHA1 := a43d7c0a8e463ac5a7846254f2a732a9af146fab
LIBXML2_SRC := sources/libxml2-$(LIBXML2_VER)
LIBXML2_BUILD := $(TRIPLET)/libxml2

$(LIBXML2_TAR):
	$(FETCH) $@ $(LIBXML2_SHA1)

$(LIBXML2_SRC)/configure: $(LIBXML2_TAR)
	mkdir -p sources
	tar xfz $<  -C sources
	touch $@

$(LIBXML2_BUILD)/Makefile: $(TOOLCHAIN_BUILT) $(LIBXML2_SRC)/configure
	mkdir -p $(LIBXML2_BUILD)
	cd $(LIBXML2_BUILD) && ../../$(LIBXML2_SRC)/configure $(CONFIGURE_ARGS) \
	    --without-c14n -without-catalog --without-debug --without-docbook \
	    --without-fexceptions --without-ftp --without-history \
	    --without-html --without-http --without-iconv --without-iconv \
	    --without-iso8859x --without-legacy --without-pattern \
	    --without-push --without-regexps --without-run-debug \
	    --without-sax1 --without-schemas --without-schematron \
	    --without-threads --without-valid --without-xinclude \
	    --without-xpath --without-xptr --without-zlib --without-lzma \
	    --without-coverage --without-python

$(LIBXML2_BUILD)/libxml2.la: $(LIBXML2_BUILD)/Makefile
	$(MAKE) -C $(LIBXML2_BUILD) libxml2.la

$(LIBXML2_BUILD)/libxml-2.0.pc: $(LIBXML2_BUILD)/Makefile
	$(MAKE) -C $(LIBXML2_BUILD) libxml-2.0.pc

$(OC_SYSROOT)/lib/libxml2.la: $(LIBXML2_BUILD)/libxml2.la
	$(MAKEINSTALL) -C $(LIBXML2_BUILD) install-libLTLIBRARIES

$(OC_SYSROOT)/lib/pkgconfig/libxml-2.0.pc: $(LIBXML2_BUILD)/libxml-2.0.pc
	$(MAKEINSTALL) -C $(LIBXML2_BUILD) install-data

LIBXML_DEPS := $(OC_SYSROOT)/lib/libxml2.la $(OC_SYSROOT)/lib/pkgconfig/libxml-2.0.pc

libxml: $(LIBXML_DEPS)


#####################################################################
#
# Build OpenSSL for Android
#
OPENSSL_VER := 1.0.1g
OPENSSL_TAR := openssl-$(OPENSSL_VER).tar.gz
OPENSSL_SHA1 := b28b3bcb1dc3ee7b55024c9f795be60eb3183e3c
OPENSSL_DIR := $(TRIPLET)/openssl-$(OPENSSL_VER)

$(OPENSSL_TAR):
	$(FETCH) $@ $(OPENSSL_SHA1)

$(OPENSSL_DIR)/Configure: $(OPENSSL_TAR)
	mkdir -p $(TRIPLET)
	tar xfz $< -C $(TRIPLET)
	touch $(OPENSSL_DIR)/Configure # Make sure it's newer than Makefile and tarball

$(OPENSSL_DIR)/Makefile: $(TOOLCHAIN_BUILT) $(OPENSSL_DIR)/Configure
	cd $(OPENSSL_DIR) && perl Configure --prefix=$(OC_SYSROOT) \
		--cross-compile-prefix=$(TRIPLET)- no-shared \
		$(OPENSSL_TARGET):gcc

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
# Build GNU MP
#
GMP_VER := 5.1.2
GMP_TAR := gmp-$(GMP_VER).tar.bz2
GMP_SHA1 := 2cb498322b9be4713829d94dee944259c017d615
GMP_SRC := sources/gmp-$(GMP_VER)
GMP_BUILD := $(TRIPLET)/gmp

$(GMP_TAR):
	$(FETCH) $@ $(GMP_SHA1)

$(GMP_SRC)/configure: $(GMP_TAR)
	mkdir -p sources
	tar xfj $< -C sources
	touch $@

$(GMP_BUILD)/Makefile: $(TOOLCHAIN_BUILT) $(GMP_SRC)/configure
	mkdir -p $(GMP_BUILD)
	cd $(GMP_BUILD) && ../../$(GMP_SRC)/configure $(CONFIGURE_ARGS) 


$(GMP_BUILD)/libgmp.la: $(GMP_BUILD)/Makefile
	$(MAKE) -C $(GMP_BUILD)

$(OC_SYSROOT)/lib/libgmp.la: $(GMP_BUILD)/libgmp.la
	$(MAKEINSTALL) -C $(GMP_BUILD) install

GMP_DEPS := $(OC_SYSROOT)/lib/libgmp.la

gmp: $(GMP_DEPS)


#####################################################################
#
# Build nettle
#
NETTLE_VER := 2.7.1
NETTLE_TAR := nettle-$(NETTLE_VER).tar.gz
NETTLE_SHA1 := e7477df5f66e650c4c4738ec8e01c2efdb5d1211
NETTLE_SRC := sources/nettle-$(NETTLE_VER)
NETTLE_BUILD := $(TRIPLET)/nettle

$(NETTLE_TAR):
	$(FETCH) $@ $(NETTLE_SHA1)

$(NETTLE_SRC)/configure: $(NETTLE_TAR)
	mkdir -p sources
	tar xfz $< -C sources
	touch $@

$(NETTLE_BUILD)/Makefile: $(TOOLCHAIN_BUILT) $(NETTLE_SRC)/configure $(GMP_DEPS)
	mkdir -p $(NETTLE_BUILD)
	cd $(NETTLE_BUILD) && ../../$(NETTLE_SRC)/configure $(CONFIGURE_ARGS)

$(NETTLE_BUILD)/libnettle.a: $(NETTLE_BUILD)/Makefile
	$(MAKE) -C $(NETTLE_BUILD) SUBDIRS=

$(OC_SYSROOT)/lib/libnettle.a: $(NETTLE_BUILD)/libnettle.a
	$(MAKEINSTALL) -C $(NETTLE_BUILD) SUBDIRS= install

NETTLE_DEPS := $(OC_SYSROOT)/lib/libnettle.a

nettle: $(NETTLE_DEPS)


#####################################################################
#
# Build GnuTLS
#
GNUTLS_VER := 3.2.21
GNUTLS_TAR := gnutls-$(GNUTLS_VER).tar.xz
GNUTLS_SHA1 := fa12e643ad21bcaf450d534f262c813d75843966
GNUTLS_SRC := sources/gnutls-$(GNUTLS_VER)
GNUTLS_BUILD := $(TRIPLET)/gnutls

$(GNUTLS_TAR):
	$(FETCH) $@ $(GNUTLS_SHA1)

$(GNUTLS_SRC)/configure: $(GNUTLS_TAR)
	mkdir -p sources
	xz -d < $< | tar xf - -C sources
	touch $@

#$(GNUTLS_SRC)/configure.ac:
#	mkdir -p sources
#	cd sources && git clone git://gitorious.org/gnutls/gnutls.git

#$(GNUTLS_SRC)/configure: $(GNUTLS_SRC)/configure.ac
#	touch $(GNUTLS_SRC)/ChangeLog
#	cd $(GNUTLS_SRC) && autoreconf -fvi

$(GNUTLS_BUILD)/Makefile: $(TOOLCHAIN_BUILT) $(GNUTLS_SRC)/configure $(NETTLE_DEPS)
	mkdir -p $(GNUTLS_BUILD)
	cd $(GNUTLS_BUILD) && ../../$(GNUTLS_SRC)/configure $(CONFIGURE_ARGS) \
		AUTOGEN=/bin/true \
		--disable-threads --disable-tests --without-zlib --disable-nls \
		--disable-doc --disable-openssl-compatibility --disable-cxx \
		--disable-openssl-compatibility --disable-ocsp \
		--disable-openpgp-authentication --disable-anon-authentication \
		--disable-psk-authentication --disable-srp-authentication \
		--disable-dtls-srtp-support  --enable-dhe --enable-ecdhe \
		--disable-rsa-export

$(GNUTLS_BUILD)/lib/libgnutls.la: $(GNUTLS_BUILD)/Makefile
	$(MAKE) -C $(GNUTLS_BUILD)

$(OC_SYSROOT)/lib/libgnutls.la: $(GNUTLS_BUILD)/lib/libgnutls.la
	$(MAKEINSTALL) -C $(GNUTLS_BUILD) install

GNUTLS_DEPS := $(OC_SYSROOT)/lib/libgnutls.la

gnutls: $(GNUTLS_DEPS)


#####################################################################
#
# Build libstoken
#
STOKEN_VER := 0.81
STOKEN_TAR := stoken-$(STOKEN_VER).tar.gz
STOKEN_SHA1 := db36aec5a8bd3f5f92deaebdea08cb639b78da73
STOKEN_SRC := sources/stoken-$(STOKEN_VER)
STOKEN_BUILD := $(TRIPLET)/stoken

$(STOKEN_TAR):
	$(FETCH) $@ $(STOKEN_SHA1)

$(STOKEN_SRC)/configure: $(STOKEN_TAR)
	mkdir -p sources
	tar xfz $< -C sources
	touch $@

$(STOKEN_BUILD)/Makefile: $(TOOLCHAIN_BUILT) $(STOKEN_SRC)/configure $(NETTLE_DEPS)
	mkdir -p $(STOKEN_BUILD)
	cd $(STOKEN_BUILD) && ../../$(STOKEN_SRC)/configure $(CONFIGURE_ARGS) \
		--without-gtk

$(STOKEN_BUILD)/libstoken.la: $(STOKEN_BUILD)/Makefile
	$(MAKE) -C $(STOKEN_BUILD)

$(OC_SYSROOT)/lib/libstoken.la: $(STOKEN_BUILD)/libstoken.la
	$(MAKEINSTALL) -C $(STOKEN_BUILD) install

STOKEN_DEPS := $(OC_SYSROOT)/lib/libstoken.la

stoken: $(STOKEN_DEPS)


#####################################################################
#
# Build liboath
#
OATH_VER := 2.4.1
OATH_TAR := oath-toolkit-$(OATH_VER).tar.gz
OATH_SHA1 := b0ca4c5f89c12c550f7227123c2f21f45b2bf969
OATH_SRC := sources/oath-toolkit-$(OATH_VER)
OATH_BUILD := $(TRIPLET)/oath

$(OATH_TAR):
	$(FETCH) $@ $(OATH_SHA1)

$(OATH_SRC)/configure: $(OATH_TAR)
	mkdir -p sources
	tar xfz $< -C sources
	cd $(OATH_SRC) && patch -p1 < ../../0001-fflush-freadahead-fseeko-Fix-for-Android.patch
	touch $@

$(OATH_BUILD)/Makefile: $(TOOLCHAIN_BUILT) $(OATH_SRC)/configure
	mkdir -p $(OATH_BUILD)
	cd $(OATH_BUILD) && ../../$(OATH_SRC)/configure $(CONFIGURE_ARGS) \
		--disable-pskc --disable-pam

$(OATH_BUILD)/liboath.la: $(OATH_BUILD)/Makefile
	$(MAKE) -C $(OATH_BUILD)

$(OC_SYSROOT)/lib/liboath.la: $(OATH_BUILD)/liboath.la
	$(MAKEINSTALL) -C $(OATH_BUILD) install

OATH_DEPS := $(OC_SYSROOT)/lib/liboath.la

oath: $(OATH_DEPS)


#####################################################################
#
# Build OpenConnect for Android
#
OPENCONNECT_SRC := ..
OPENCONNECT_BUILD := $(TRIPLET)/openconnect

$(OPENCONNECT_SRC)/configure:
	cd $(OPENCONNECT_SRC) && ./autogen.sh

$(OPENCONNECT_BUILD)/Makefile: $(TOOLCHAIN_BUILT) $(GNUTLS_DEPS) $(LIBXML_DEPS) $(STOKEN_DEPS) $(OATH_DEPS) $(OPENCONNECT_SRC)/configure
	mkdir -p $(OPENCONNECT_BUILD)
	cd $(OPENCONNECT_BUILD) && ../../../configure \
	--host=$(TRIPLET) --prefix=/ \
	CFLAGS="$(EXTRA_CFLAGS)" \
	LDFLAGS="$(EXTRA_LDFLAGS)" \
	GNUTLS_LIBS="$(shell $(PKG_CONFIG) --static --libs gnutls)" \
	LIBSTOKEN_LIBS="$(shell $(PKG_CONFIG) --static --libs stoken)" \
	--enable-shared --with-vpnc-script=/etc/vpnc/vpnc-script \
	--with-java=$(OC_SYSROOT)/include --enable-jni-standalone \
	--disable-symvers

openconnect: $(OPENCONNECT_BUILD)/Makefile
	make -C $(OPENCONNECT_BUILD)
	make -C $(OPENCONNECT_BUILD) install-strip DESTDIR=$(DESTDIR)


#####################################################################
#
# Special targets for maintainer use
#

# download + extract, but do not build
.PHONY: sources
sources: $(SOURCE_LIST)

.PHONY: $(MIRROR_TEST_TARGETS)
$(MIRROR_TEST_TARGETS) : mirror-test-% :
	$(FETCH) --mirror-test $($(*)_TAR) $($(*)_SHA1)

# (re)test all mirrors for all packages. safe for use with "make -jN"
.PHONY: mirror-test
mirror-test: $(MIRROR_TEST_TARGETS)
