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
GCCVER  := 4.7

# You should be able to just 'make ARCH=x86' and it should DTRT.
ifeq ($(ARCH),arm)
TRIPLET := arm-linux-androideabi
TOOLCHAIN := $(TRIPLET)-$(GCCVER)
OPENSSL_TARGET := android-armv7
endif
ifeq ($(ARCH),x86)
TRIPLET := i686-linux-android
TOOLCHAIN := x86-$(GCCVER)
OPENSSL_TARGET := android-x86
endif
ifeq ($(ARCH),mips)
TRIPLET := mipsel-linux-android
TOOLCHAIN := $(TRIPLET)-$(GCCVER)
OPENSSL_TARGET := android
endif

NDK_SYSROOT := $(NDK)/platforms/android-$(APIVER)/arch-$(ARCH)
OC_SYSROOT  := $(shell pwd)/sysroot-$(TRIPLET)

BINDIR := $(firstword $(wildcard $(NDK)/toolchains/$(TOOLCHAIN)/prebuilt/*/bin))
PATH := $(BINDIR):$(PATH)
PKG_CONFIG_LIBDIR=$(OC_SYSROOT)/lib/pkgconfig
export PATH PKG_CONFIG_LIBDIR


MAKEINSTALL=$(MAKE) INSTALL=$(shell pwd)/install_symlink.sh

CONFIGURE_ARGS := --host=$(TRIPLET) --prefix=$(OC_SYSROOT) \
		  --disable-shared --enable-static \
		  CFLAGS="--sysroot=$(NDK_SYSROOT) -I$(OC_SYSROOT)/include" \
		  LDFLAGS="-L$(OC_SYSROOT)/lib"

all: openconnect

#####################################################################
#
# Build libxml2 with minimal configuration for OpenConnect
#
LIBXML2_VER := 2.9.0
LIBXML2_SRC := sources/libxml2-$(LIBXML2_VER)
LIBXML2_BUILD := $(TRIPLET)/libxml2

libxml2-$(LIBXML2_VER).tar.gz:
	curl ftp://xmlsoft.org/libxml2/libxml2-$(LIBXML2_VER).tar.gz -o $@.tmp && mv $@.tmp $@

$(LIBXML2_SRC)/configure: libxml2-$(LIBXML2_VER).tar.gz
	mkdir -p sources
	tar xfz $<  -C sources
	touch $@

$(LIBXML2_BUILD)/Makefile: $(LIBXML2_SRC)/configure
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
OPENSSL_VER := 1.0.1e
OPENSSL_DIR := $(TRIPLET)/openssl-$(OPENSSL_VER)

openssl-$(OPENSSL_VER).tar.gz:
	curl http://www.openssl.org/source/openssl-$(OPENSSL_VER).tar.gz -o $@.tmp && mv $@.tmp $@

$(OPENSSL_DIR)/Configure: openssl-$(OPENSSL_VER).tar.gz
	mkdir -p $(TRIPLET)
	tar xfz $< -C $(TRIPLET)
	cd $(OPENSSL_DIR) && patch -p1 < ../../0001-Check-DTLS_BAD_VER-for-version-number.patch
	touch $(OPENSSL_DIR)/Configure # Make sure it's newer than Makefile and tarball

$(OPENSSL_DIR)/Makefile: $(OPENSSL_DIR)/Configure
	cd $(OPENSSL_DIR) && perl Configure --prefix=$(OC_SYSROOT) \
		--cross-compile-prefix=$(TRIPLET)- no-shared \
		$(OPENSSL_TARGET):"gcc --sysroot=$(NDK_SYSROOT)"

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
GMP_VER := 5.1.1
GMP_SRC := sources/gmp-$(GMP_VER)
GMP_BUILD := $(TRIPLET)/gmp

gmp-$(GMP_VER).tar.bz2:
	curl ftp://ftp.gmplib.org/pub/gmp/gmp-$(GMP_VER).tar.bz2 -o $@.tmp && mv $@.tmp $@

$(GMP_SRC)/configure: gmp-$(GMP_VER).tar.bz2
	mkdir -p sources
	tar xfj $< -C sources
	touch $@

$(GMP_BUILD)/Makefile: $(GMP_SRC)/configure
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
NETTLE_VER := 2.6
NETTLE_SRC := sources/nettle-$(NETTLE_VER)
NETTLE_BUILD := $(TRIPLET)/nettle
nettle-$(NETTLE_VER).tar.gz:
	curl http://www.lysator.liu.se/~nisse/archive/nettle-$(NETTLE_VER).tar.gz -o $@.tmp && mv $@.tmp $@

$(NETTLE_SRC)/configure: nettle-$(NETTLE_VER).tar.gz
	mkdir -p sources
	tar xfz $< -C sources
	touch $@

$(NETTLE_BUILD)/Makefile: $(NETTLE_SRC)/configure $(GMP_DEPS)
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
#GNUTLS_VER := 3.1.9
GNUTLS_SRC := sources/gnutls
GNUTLS_BUILD := $(TRIPLET)/gnutls

gnutls-$(GNUTLS_VER).tar.xz:
	curl ftp://ftp.gnutls.org/gcrypt/gnutls/v3.1/$@ -o $@.tmp && mv $@.tmp $@

#$(GNUTLS_SRC)/configure: gnutls-$(GNUTLS_VER).tar.xz
#	mkdir -p sources
#       xz -d < $< | tar xf - -C sources
#       touch $@

$(GNUTLS_SRC)/configure.ac:
	mkdir -p sources
	cd sources && git clone git://gitorious.org/gnutls/gnutls.git

$(GNUTLS_SRC)/configure: $(GNUTLS_SRC)/configure.ac
	touch $(GNUTLS_SRC)/ChangeLog
	cd $(GNUTLS_SRC) && autoreconf -fvi

$(GNUTLS_BUILD)/Makefile: $(GNUTLS_SRC)/configure $(NETTLE_DEPS)
	mkdir -p $(GNUTLS_BUILD)
	cd $(GNUTLS_BUILD) && ../../$(GNUTLS_SRC)/configure $(CONFIGURE_ARGS) \
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
# Build OpenConnect for Android
#
OPENCONNECT_SRC := ..
OPENCONNECT_BUILD := $(TRIPLET)/openconnect

$(OPENCONNECT_SRC)/configure:
	cd $(OPENCONNECT_SRC) && ./autogen.sh

$(OPENCONNECT_BUILD)/Makefile: $(GNUTLS_DEPS) $(LIBXML_DEPS) $(OPENCONNECT_SRC)/configure
	mkdir -p $(OPENCONNECT_BUILD)
	cd $(OPENCONNECT_BUILD) && ../../../configure $(CONFIGURE_ARGS) \
	CFLAGS="--sysroot=$(NDK_SYSROOT) -DNO_BROKEN_DTLS_CHECK" \
	GNUTLS_LIBS="$(shell PKG_CONFIG_LIBDIR=$(OC_SYSROOT)/lib/pkgconfig pkg-config --static --libs gnutls)" \
	--enable-shared --with-vpnc-script=/etc/vpnc/vpnc-script

openconnect: $(OPENCONNECT_BUILD)/Makefile
	make -C $(OPENCONNECT_BUILD)
