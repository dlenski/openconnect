AC_INIT(openconnect, 6.00)
AC_CONFIG_HEADERS([config.h])

PKG_PROG_PKG_CONFIG
AC_LANG_C
AC_CANONICAL_HOST
AM_MAINTAINER_MODE([enable])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PREREQ([2.62], [], [AC_SUBST([localedir], ['$(datadir)/locale'])])

# Upstream's pkg.m4 (since 0.27) offers this now, but define our own
# compatible version in case the local version of pkgconfig isn't new enough.
# https://bugs.freedesktop.org/show_bug.cgi?id=48743
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR],
	  [AC_ARG_WITH([pkgconfigdir],
		       [AS_HELP_STRING([--with-pkgconfigdir],
		       [install directory for openconnect.pc pkg-config file])],
			[],[with_pkgconfigdir='$(libdir)/pkgconfig'])
	   AC_SUBST([pkgconfigdir], [${with_pkgconfigdir}])])

use_openbsd_libtool=
symver_time=
symver_getline=
symver_asprintf=
symver_vasprintf=
symver_win32_strerror=

case $host_os in
 *linux* | *gnu*)
    AC_MSG_NOTICE([Applying feature macros for GNU build])
    AC_DEFINE(_POSIX_C_SOURCE, 200112L, [_POSIX_C_SOURCE])
    # For asprintf()
    AC_DEFINE(_GNU_SOURCE, 1, [_GNU_SOURCE])
    ;;
 *netbsd*)
    AC_MSG_NOTICE([Applying feature macros for NetBSD build])
    AC_DEFINE(_POSIX_C_SOURCE, 200112L, [_POSIX_C_SOURCE])
    AC_DEFINE(_NETBSD_SOURCE, 1, [_NETBSD_SOURCE])
    ;;
 *openbsd*)
    AC_MSG_NOTICE([Applying feature macros for OpenBSD build])
    use_openbsd_libtool=true
    ;;
 *solaris*|*sunos*)
    AC_MSG_NOTICE([Applying workaround for broken SunOS time() function])
    AC_DEFINE(HAVE_SUNOS_BROKEN_TIME, 1, [On SunOS time() can go backwards])
    symver_time="openconnect__time;"
    ;;
 *mingw32*|*mingw64*|*msys*)
    AC_MSG_NOTICE([Applying feature macros for MinGW/Windows build])
    # For GetVolumeInformationByHandleW() which is Vista+
    AC_DEFINE(_WIN32_WINNT, 0x600, [Windows API version])
    have_win=yes
    # For asprintf()
    AC_DEFINE(_GNU_SOURCE, 1, [_GNU_SOURCE])
    symver_win32_strerror="openconnect__win32_strerror;"
    ;;
 *)
    # On FreeBSD the only way to get vsyslog() visible is to define
    #  *nothing*, which makes absolutely everything visible.
    # On Darwin enabling _POSIX_C_SOURCE breaks <sys/mount.h> because
    # u_long and other types don't get defined. OpenBSD is similar.
    ;;
esac
AM_CONDITIONAL(OPENCONNECT_WIN32,  [ test "$have_win" = "yes" ])

AC_ARG_WITH([vpnc-script],
	[AS_HELP_STRING([--with-vpnc-script],
	  [default location of vpnc-script helper])])

if test "$with_vpnc_script" = "yes" || test "$with_vpnc_script" = ""; then
   if test "$have_win" = "yes"; then
      with_vpnc_script=vpnc-script-win.js
   else
      with_vpnc_script=/etc/vpnc/vpnc-script
      if ! test -x "$with_vpnc_script"; then
	 AC_MSG_ERROR([${with_vpnc_script} does not seem to be executable.]
 [OpenConnect will not function correctly without a vpnc-script.]
 [See http://www.infradead.org/openconnect/vpnc-script.html for more details.]
 []
 [If you are building a distribution package, please ensure that your]
 [packaging is correct, and that a vpnc-script will be installed when the]
 [user installs your package. You should provide a --with-vpnc-script=]
 [argument to this configure script, giving the full path where the script]
 [will be installed.]
 []
 [The standard location is ${with_vpnc_script}. To bypass this error and]
 [build OpenConnect to use the script from this location, even though it is]
 [not present at the time you are building OpenConnect, pass the argument]
 ["--with-vpnc-script=${with_vpnc_script}"])
     fi
   fi
elif test "$with_vpnc_script" = "no"; then
   AC_ERROR([You cannot disable vpnc-script.]
   [OpenConnect will not function correctly without it.]
   [See http://www.infradead.org/openconnect/vpnc-script.html])
elif test "$have_win" = "yes"; then
   # Oh Windows how we hate thee. If user specifies a vpnc-script and it contains
   # backslashes, double them all up to survive escaping.
   with_vpnc_script="$(echo "${with_vpnc_script}" | sed s/\\\\/\\\\\\\\/g)"
fi

AC_DEFINE_UNQUOTED(DEFAULT_VPNCSCRIPT, "${with_vpnc_script}", [Default vpnc-script locatin])
AC_SUBST(DEFAULT_VPNCSCRIPT, "${with_vpnc_script}")

AC_CHECK_FUNC(fdevname_r, [AC_DEFINE(HAVE_FDEVNAME_R, 1, [Have fdevname_r() function])], [])
AC_CHECK_FUNC(getline, [AC_DEFINE(HAVE_GETLINE, 1, [Have getline() function])],
    [symver_getline="openconnect__getline;"])
AC_CHECK_FUNC(strcasestr, [AC_DEFINE(HAVE_STRCASESTR, 1, [Have strcasestr() function])], [])
AC_CHECK_FUNC(strndup, [AC_DEFINE(HAVE_STRNDUP, 1, [Have strndup() function])], [])
AC_CHECK_FUNC(asprintf, [AC_DEFINE(HAVE_ASPRINTF, 1, [Have asprintf() function])],
    [symver_asprintf="openconnect__asprintf;"])
AC_CHECK_FUNC(vasprintf, [AC_DEFINE(HAVE_VASPRINTF, 1, [Have vasprintf() function])],
    [symver_vasprintf="openconnect__vasprintf;"])

if test -n "$symver_vasprintf"; then
  AC_MSG_CHECKING([for va_copy])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([
	#include <stdarg.h>
	va_list a;],[
	va_list b;
	va_copy(b,a);
	va_end(b);])],
	[AC_DEFINE(HAVE_VA_COPY, 1, [Have va_copy()])
	AC_MSG_RESULT(va_copy)],
	[AC_LINK_IFELSE([AC_LANG_PROGRAM([
		#include <stdarg.h>
		va_list a;],[
		va_list b;
		__va_copy(b,a);
		va_end(b);])],
		[AC_DEFINE(HAVE___VA_COPY, 1, [Have __va_copy()])
		AC_MSG_RESULT(__va_copy)],
		[AC_MSG_RESULT(no)
		AC_MSG_ERROR([Your system lacks vasprintf() and va_copy()])])
	])
fi
AC_SUBST(SYMVER_TIME, $symver_time)
AC_SUBST(SYMVER_GETLINE, $symver_getline)
AC_SUBST(SYMVER_ASPRINTF, $symver_asprintf)
AC_SUBST(SYMVER_VASPRINTF, $symver_vasprintf)
AC_SUBST(SYMVER_WIN32_STRERROR, $symver_win32_strerror)

AS_COMPILER_FLAGS(WFLAGS,
        "-Wall
         -Wextra
         -Wno-missing-field-initializers
         -Wno-sign-compare
         -Wno-unused-parameter
         -Werror=pointer-to-int-cast
         -Wdeclaration-after-statement
         -Werror-implicit-function-declaration
         -Wformat-nonliteral
         -Wformat-security
         -Winit-self
         -Wmissing-declarations
         -Wmissing-include-dirs
         -Wnested-externs
         -Wpointer-arith
         -Wwrite-strings")
AC_SUBST(WFLAGS, [$WFLAGS])

if test "$have_win" = yes; then
   # Checking "properly" for __attribute__((dllimport,stdcall)) functions is non-trivial
   LIBS="$LIBS -lws2_32 -lshlwapi -lsecur32"
else
   AC_CHECK_FUNC(socket, [], AC_CHECK_LIB(socket, socket, [], AC_ERROR(Cannot find socket() function)))
fi

have_inet_aton=yes
AC_CHECK_FUNC(inet_aton, [], AC_CHECK_LIB(nsl, inet_aton, [], have_inet_aton=no))
if test "$have_inet_aton" = "yes"; then
   AC_DEFINE(HAVE_INET_ATON, 1, [Have inet_aton()])
fi

AC_CHECK_FUNC(__android_log_vprint, [], AC_CHECK_LIB(log, __android_log_vprint, [], []))

AC_CHECK_FUNCS(setenv unsetenv)

AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CHECK_FUNC(nl_langinfo, [AC_DEFINE(HAVE_NL_LANGINFO, 1, [Have nl_langinfo() function])], [])

if test "$ac_cv_func_nl_langinfo" = "yes"; then
    AM_ICONV
    if test "$am_cv_func_iconv" = "yes"; then
	AC_SUBST(ICONV_LIBS, [$LTLIBICONV])
	AC_SUBST(ICONV_CFLAGS, [$INCICONV])
	AC_DEFINE(HAVE_ICONV, 1, [Have iconv() function])
    fi
fi
AM_CONDITIONAL(OPENCONNECT_ICONV, [test "$am_cv_func_iconv" = "yes"])

AC_ARG_ENABLE([nls],
	[  --disable-nls           do not use Native Language Support],
	[USE_NLS=$enableval], [USE_NLS=yes])
LIBINTL=
if test "$USE_NLS" = "yes"; then
   AC_PATH_PROG(MSGFMT, msgfmt)
   if test "$MSGFMT" = ""; then
      AC_ERROR([msgfmt could not be found. Try configuring with --disable-nls])
   fi
fi
LIBINTL=
if test "$USE_NLS" = "yes"; then
   AC_MSG_CHECKING([for functional NLS support])
   AC_LINK_IFELSE([AC_LANG_PROGRAM([
    #include <locale.h>
    #include <libintl.h>],[
    setlocale(LC_ALL, "");
    bindtextdomain("openconnect", "/tmp");
    (void)dgettext("openconnect", "foo");])],
    [AC_MSG_RESULT(yes)],
    [oldLIBS="$LIBS"
     LIBS="$LIBS -lintl"
     AC_LINK_IFELSE([AC_LANG_PROGRAM([
      #include <locale.h>
      #include <libintl.h>],[
      setlocale(LC_ALL, "");
      bindtextdomain("openconnect", "/tmp");
      (void)dgettext("openconnect", "foo");])],
      [AC_MSG_RESULT(yes (with -lintl))]
       LIBINTL="-lintl",
      [LIBS="$LIBS -liconv"
       AC_LINK_IFELSE([AC_LANG_PROGRAM([
        #include <locale.h>
        #include <libintl.h>],[
        setlocale(LC_ALL, "");
        bindtextdomain("openconnect", "/tmp");
        (void)dgettext("openconnect", "foo");])],
        [AC_MSG_RESULT(yes (with -lintl -liconv))]
         LIBINTL="-lintl",
        [AC_MSG_RESULT(no)
         USE_NLS=no])
     LIBS="$oldLIBS"])])
fi

if test "$USE_NLS" = "yes"; then
   AC_SUBST(LIBINTL)
   AC_DEFINE(ENABLE_NLS, 1, [Enable NLS support])
fi
AM_CONDITIONAL(USE_NLS, [test "$USE_NLS" = "yes"])

AC_ARG_WITH([system-cafile],
	    AS_HELP_STRING([--with-system-cafile],
			   [Location of the default system CA certificate file for old (<3.0.20) GnuTLS versions]))

# We will use GnuTLS by default if it's present, and if GnuTLS doesn't
# have DTLS support then we'll *also* use OpenSSL for that, but it
# appears *only* only in the openconnect executable and not the
# library (hence shouldn't be a problem for GPL'd programs using
# libopenconnect).
#
# If built with --without-openssl then we'll even eschew OpenSSL for
# DTLS support and will build without any DTLS support at all if
# GnuTLS cannot manage.
#
# You can build without GnuTLS, even if its pkg-config file is present
# on the system, by using '--without-gnutls'

AC_ARG_WITH([gnutls],
	AS_HELP_STRING([--without-gnutls],
		       [Do not attempt to use GnuTLS; use OpenSSL instead]))
AC_ARG_WITH([openssl],
            AS_HELP_STRING([--with-openssl],
                           [Location of OpenSSL build dir]))
ssl_library=

if test "$with_gnutls" = "yes" || test "$with_gnutls" = ""; then
    PKG_CHECK_MODULES(GNUTLS, gnutls, [found_gnutls=yes], [found_gnutls=no])
    if test "$found_gnutls" = "yes"; then
        if ! $PKG_CONFIG --atleast-version=2.12.16 gnutls; then
	    found_gnutls=old
        fi
	if test "$have_win" = "yes"; then
	   AC_MSG_CHECKING([for broken GnuTLS Windows versions])
	   if $PKG_CONFIG --atleast-version=3.2.0 gnutls &&
	      ! $PKG_CONFIG --atleast-version=3.2.10 gnutls; then
	      AC_MSG_RESULT([yes])
	      found_gnutls=winbroken
	   else
	      AC_MSG_RESULT([no])
	   fi
	fi
    fi
    case $with_gnutls$found_gnutls in
     yeswinbroken)
        AC_MSG_ERROR([GnuTLS v3.2.0-v3.2.9 are not functional on Windows])
	;;
     yesold)
        AC_MSG_ERROR([Your GnuTLS is too old. At least v2.12.16 is required])
	;;
     yesno)
	AC_MSG_ERROR([GnuTLS requested but no package 'gnutls' found])
	;;
     old)
        AC_MSG_WARN([GnuTLS is too old. At least v2.12.16 is required. Falling back to OpenSSL])
	;;
     yes)
        with_gnutls=yes
	;;
    esac
elif test "$with_gnutls" != "no"; then
    AC_MSG_ERROR([Values other than 'yes' or 'no' for --with-gnutls are not supported])
fi

if test "$with_gnutls" = "yes"; then
    oldlibs="$LIBS"
    LIBS="$LIBS $GNUTLS_LIBS"
    oldcflags="$CFLAGS"
    CFLAGS="$CFLAGS $GNUTLS_CFLAGS"
    AC_CHECK_FUNC(gnutls_dtls_set_data_mtu,
		 [AC_DEFINE(HAVE_GNUTLS_DTLS_SET_DATA_MTU, 1, [Have this function])], [])
    AC_CHECK_FUNC(gnutls_pkcs11_get_raw_issuer,
		 [AC_DEFINE(HAVE_GNUTLS_PKCS11_GET_RAW_ISSUER, 1, [Have this function])], [])
    AC_CHECK_FUNC(gnutls_certificate_set_x509_system_trust,
		 [AC_DEFINE(HAVE_GNUTLS_CERTIFICATE_SET_X509_SYSTEM_TRUST, 1, [I hate autoheader])], [])
    if test "$ac_cv_func_gnutls_certificate_set_x509_system_trust" != "yes"; then
	# We will need to tell GnuTLS the path to the system CA file.
	if test "$with_system_cafile" = "yes" || test "$with_system_cafile" = ""; then
	    unset with_system_cafile
	    AC_MSG_CHECKING([For location of system CA trust file])
	    for file in /etc/ssl/certs/ca-certificates.crt \
			/etc/pki/tls/cert.pem \
			/usr/local/share/certs/ca-root-nss.crt \
			/etc/ssl/cert.pem \
			/etc/ssl/ca-bundle.pem \
		; do
		if grep 'BEGIN CERTIFICATE-----' $file >/dev/null 2>&1; then
		    with_system_cafile=${file}
		    break
		fi
	    done
	    AC_MSG_RESULT([${with_system_cafile-NOT FOUND}])
	elif test "$with_system_cafile" = "no"; then
	    AC_MSG_ERROR([You cannot disable the system CA certificate file.])
	fi
	if test "$with_system_cafile" = ""; then
	    AC_MSG_ERROR([Unable to find a standard system CA certificate file.]
    [Your GnuTLS requires a path to a CA certificate store. This is a file]
    [which contains a list of the Certificate Authorities which are trusted.]
    [Most distributions ship with this file in a standard location, but none]
    [the known standard locations exist on your system. You should provide a]
    [--with-system-cafile= argument to this configure script, giving the full]
    [path to a default CA certificate file for GnuTLS to use. Also, please]
    [send full details of your system, including 'uname -a' output and the]
    [location of the system CA certificate store on your system, to the]
    [openconnect-devel@lists.infradead.org mailing list.])
	fi
	AC_DEFINE_UNQUOTED([DEFAULT_SYSTEM_CAFILE], ["$with_system_cafile"], [Location of System CA trust file])
    fi
    AC_CHECK_FUNC(gnutls_pkcs12_simple_parse,
		 [AC_DEFINE(HAVE_GNUTLS_PKCS12_SIMPLE_PARSE, 1, [This one was obvious too])], [])
    AC_CHECK_FUNC(gnutls_certificate_set_key,
		 [AC_DEFINE(HAVE_GNUTLS_CERTIFICATE_SET_KEY, 1, [stupid])], [])
    AC_CHECK_FUNC(gnutls_pk_to_sign,
		 [AC_DEFINE(HAVE_GNUTLS_PK_TO_SIGN, 1, [autoheader])], [])
    if test "$with_openssl" = "" || test "$with_openssl" = "no"; then
	AC_CHECK_FUNC(gnutls_session_set_premaster,
		 [have_gnutls_dtls=yes], [have_gnutls_dtls=no])
    else
	have_gnutls_dtls=no
    fi
    if test "$have_gnutls_dtls" = "yes"; then
	if test "$with_openssl" = "" || test "$with_openssl" = "no"; then
	    # They either said no OpenSSL or didn't specify, and GnuTLS can
	    # do DTLS, so just use GnuTLS.
            AC_DEFINE(HAVE_GNUTLS_SESSION_SET_PREMASTER, 1, [the fish are hungry tonight])
	    ssl_library=gnutls
	    with_openssl=no
	else
	    # They specifically asked for OpenSSL, so use it for DTLS even
	    # though GnuTLS could manage.
	    ssl_library=both
	fi
    else
	if test "$with_openssl" = "no"; then
	    # GnuTLS doesn't have DTLS, but they don't want OpenSSL. So build
	    # without DTLS support at all.
	    ssl_library=gnutls
	else
	    # GnuTLS doesn't have DTLS so use OpenSSL for it, but GnuTLS for
	    # the TCP connection (and thus in the library).
	    ssl_library=both
	fi
    fi
    AC_CHECK_FUNC(gnutls_pkcs11_add_provider,
		 [PKG_CHECK_MODULES(P11KIT, p11-kit-1, [AC_DEFINE(HAVE_P11KIT, 1, [Have. P11. Kit.])
    			      		  AC_SUBST(P11KIT_PC, p11-kit-1)], [:])], [])
    LIBS="$oldlibs -ltspi"
    AC_MSG_CHECKING([for tss library])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <trousers/tss.h>
		   #include <trousers/trousers.h>],[
		   int err = Tspi_Context_Create((void *)0);
		   Trspi_Error_String(err);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([TSS_LIBS], [-ltspi])
		   AC_SUBST([TSS_CFLAGS], [])
		   AC_DEFINE(HAVE_TROUSERS, 1, [Have Trousers TSS library])],
		  [AC_MSG_RESULT(no)])
    LIBS="$oldlibs"
    CFLAGS="$oldcflags"
fi
if test "$with_openssl" = "yes" || test "$with_openssl" = "" || test "$ssl_library" = "both"; then
    PKG_CHECK_MODULES(OPENSSL, openssl, [],
	[oldLIBS="$LIBS"
	 LIBS="$LIBS -lssl -lcrypto"
	 AC_MSG_CHECKING([for OpenSSL without pkg-config])
	 AC_LINK_IFELSE([AC_LANG_PROGRAM([
			        #include <openssl/ssl.h>
				#include <openssl/err.h>],[
				SSL_library_init();
				ERR_clear_error();
				SSL_load_error_strings();
				OpenSSL_add_all_algorithms();])],
			[AC_MSG_RESULT(yes)
			 AC_SUBST([OPENSSL_LIBS], ["-lssl -lcrypto"])
			 AC_SUBST([OPENSSL_CFLAGS], [])],
			[AC_MSG_RESULT(no)
			 if test "$ssl_library" = "both"; then
			     ssl_library="gnutls";
			 else
			     AC_ERROR([Could not build against OpenSSL]);
			 fi])
	 LIBS="$oldLIBS"])
    if test "$ssl_library" != "both" && test "$ssl_library" != "gnutls"; then
        ssl_library=openssl
    fi
elif test "$with_openssl" != "no" ; then
    OPENSSL_CFLAGS="-I${with_openssl}/include"
    OPENSSL_LIBS="${with_openssl}/libssl.a ${with_openssl}/libcrypto.a -ldl -lz"
    AC_SUBST(OPENSSL_CFLAGS)
    AC_SUBST(OPENSSL_LIBS)
    enable_static=yes
    enable_shared=no
    AC_DEFINE(DTLS_OPENSSL, 1, [Using OpenSSL for DTLS])
    if test "$ssl_library" != "both"; then
        ssl_library=openssl
    fi
fi

case "$ssl_library" in
    gnutls)
	AC_DEFINE(OPENCONNECT_GNUTLS, 1, [Using GnuTLS])
	AC_DEFINE(DTLS_GNUTLS, 1, [Using GnuTLS for DTLS])
	AC_SUBST(SSL_DTLS_PC, [gnutls])
	AC_SUBST(SSL_LIBS, ['$(GNUTLS_LIBS)'])
	AC_SUBST(SSL_CFLAGS, ['$(GNUTLS_CFLAGS)'])
	check_openssl_dtls=no
	;;
    openssl)
	AC_DEFINE(OPENCONNECT_OPENSSL, 1, [Using OpenSSL])
	AC_DEFINE(DTLS_OPENSSL, 1, [Using OpenSSL for DTLS])
	AC_SUBST(SSL_DTLS_PC, [openssl])
	AC_SUBST(SSL_LIBS, ['$(OPENSSL_LIBS)'])
	AC_SUBST(SSL_CFLAGS, ['$(OPENSSL_CFLAGS)'])
	check_openssl_dtls=yes
	;;
    both)
	# GnuTLS for TCP, OpenSSL for DTLS
	AC_DEFINE(OPENCONNECT_GNUTLS, 1, [Using GnuTLS])
	AC_DEFINE(DTLS_OPENSSL, 1, [Using OpenSSL for DTLS])
	AC_SUBST(SSL_DTLS_PC, [gnutls openssl])
	AC_SUBST(SSL_LIBS, ['$(GNUTLS_LIBS)'])
	AC_SUBST(SSL_CFLAGS, ['$(GNUTLS_CFLAGS)'])
	AC_SUBST(DTLS_SSL_LIBS, ['$(OPENSSL_LIBS)'])
	AC_SUBST(DTLS_SSL_CFLAGS, ['$(OPENSSL_CFLAGS)'])
	check_openssl_dtls=yes
	;;
    *)
	AC_MSG_ERROR([Neither OpenSSL nor GnuTLS selected for SSL.])
	;;
esac
AM_CONDITIONAL(OPENCONNECT_GNUTLS,  [ test "$ssl_library" != "openssl" ])
AM_CONDITIONAL(OPENCONNECT_OPENSSL, [ test "$ssl_library" = "openssl" ])

AC_ARG_WITH([openssl-version-check],
	AS_HELP_STRING([--without-openssl-version-check],
	[Do not check for known-broken OpenSSL versions]))
if test "$with_openssl_version_check" = "no"; then
   check_openssl_dtls=no
fi

if test "$check_openssl_dtls" = "yes"; then
	AC_MSG_CHECKING([for known-broken versions of OpenSSL])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <openssl/opensslv.h>],[#if \
				    (OPENSSL_VERSION_NUMBER == 0x10002000L || \
				    (OPENSSL_VERSION_NUMBER >= 0x100000b0L && OPENSSL_VERSION_NUMBER <= 0x100000c0L) || \
				    (OPENSSL_VERSION_NUMBER >= 0x10001040L && OPENSSL_VERSION_NUMBER <= 0x10001060L))
				#error Bad OpenSSL
				#endif
				])],
			  [AC_MSG_RESULT(no)],
			  [AC_MSG_RESULT(yes)
			   AC_ERROR([This version of OpenSSL is known to be broken with Cisco DTLS.
See http://rt.openssl.org/Ticket/Display.html?id=2984&user=guest&pass=guest
Add --without-openssl-version-check to configure args to avoid this check, or
perhaps consider building with GnuTLS instead.])])
fi

# Needs to happen after we default to static/shared libraries based on OpenSSL
AC_PROG_LIBTOOL
if test "$use_openbsd_libtool" = "true" && test -x /usr/bin/libtool; then
	echo using OpenBSD libtool
	LIBTOOL=/usr/bin/libtool
fi
AM_CONDITIONAL(OPENBSD_LIBTOOL, [ test "$use_openbsd_libtool" = "true" ])

# Ick. This seems like it's likely to be very fragile, but I can't see a better
# way. I shall console myself with the observation that the failure mode isn't
# particularly horrible — you just don't get symbol versioning if it fails.

AC_ARG_ENABLE([symvers],
	AS_HELP_STRING([--disable-symvers],
		       [disable library symbol versioning [default=auto]]),
	[want_symvers=$enableval],
	[want_symvers=yes])

symvers=no
if test "$enable_shared" = "yes" -a "$want_symvers" != "no" ; then
   AC_MSG_CHECKING([if library symbol versioning is available]);
   echo 'FOO { global: foo; local: *; };' > conftest.map
   echo 'int foo = 0;' > conftest.$ac_ext
   if AC_TRY_EVAL(ac_compile); then
      soname=conftest
      libobjs=conftest.$ac_objext
      if AC_TRY_EVAL(archive_cmds ${wl}--version-script ${wl}conftest.map); then
         AC_SUBST(VERSION_SCRIPT_ARG, [--version-script])
         symvers="yes (with --version-script)"
      elif AC_TRY_EVAL(archive_cmds ${wl}-M ${wl}conftest.map); then
         AC_SUBST(VERSION_SCRIPT_ARG, [-M])
         symvers="yes (with -M)"
      fi
   fi
   AC_MSG_RESULT(${symvers})
fi
AM_CONDITIONAL(HAVE_SYMBOL_VERSIONING, [test "${symvers}" != "no"])

PKG_CHECK_MODULES(LIBXML2, libxml-2.0)

PKG_CHECK_MODULES(ZLIB, zlib, [AC_SUBST(ZLIB_PC, [zlib])],
		  [oldLIBS="$LIBS"
		  LIBS="$LIBS -lz" 
		  AC_MSG_CHECKING([for zlib without pkg-config])
		  AC_LINK_IFELSE([AC_LANG_PROGRAM([
		   #include <zlib.h>],[
		   z_stream zs;
		   deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
		   		-12, 9, Z_DEFAULT_STRATEGY);])],
		  [AC_MSG_RESULT(yes)
		   AC_SUBST([ZLIB_LIBS], [-lz])
		   AC_SUBST([ZLIB_CFLAGS], [])],
  		  [AC_MSG_RESULT(no)
		   AC_ERROR([Could not build against zlib])])
		  LIBS="$oldLIBS"])

AC_ARG_WITH([libproxy],
	AS_HELP_STRING([--without-libproxy],
	[Build without libproxy library [default=auto]]))
AS_IF([test "x$with_libproxy" != "xno"], [
	PKG_CHECK_MODULES(LIBPROXY, libproxy-1.0,
			[AC_SUBST(LIBPROXY_PC, libproxy-1.0)
			 AC_DEFINE([LIBPROXY_HDR], ["proxy.h"], [libproxy header file])
			 libproxy_pkg=yes],
			 libproxy_pkg=no)
], [libproxy_pkg=disabled])

dnl Libproxy *can* exist without a .pc file, and its header may be called
dnl libproxy.h in that case.
if (test "$libproxy_pkg" = "no"); then
   AC_MSG_CHECKING([for libproxy])
   oldLIBS="$LIBS"
   LIBS="$LIBS -lproxy"
   AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <libproxy.h>],
			   [(void)px_proxy_factory_new();])],
	  [AC_MSG_RESULT(yes (with libproxy.h))
	   AC_DEFINE([LIBPROXY_HDR], ["libproxy.h"])
	   AC_SUBST([LIBPROXY_LIBS], [-lproxy])],
	  [AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <proxy.h>],
				  [(void)px_proxy_factory_new();])],
		  [AC_MSG_RESULT(yes (with proxy.h))
		   AC_DEFINE([LIBPROXY_HDR], ["proxy.h"])
		   AC_SUBST([LIBPROXY_LIBS], [-lproxy])],
		   [AC_MSG_RESULT(no)])])
   LIBS="$oldLIBS"
fi

AC_ARG_WITH([stoken],
	AS_HELP_STRING([--without-stoken],
	[Build without libstoken library [default=auto]]))
AS_IF([test "x$with_stoken" != "xno"], [
	PKG_CHECK_MODULES(LIBSTOKEN, stoken,
			[AC_SUBST(LIBSTOKEN_PC, stoken)
			 AC_DEFINE([HAVE_LIBSTOKEN], 1, [Have libstoken])
			 libstoken_pkg=yes],
			 libstoken_pkg=no)
], [libstoken_pkg=disabled])
AM_CONDITIONAL(OPENCONNECT_STOKEN, [test "$libstoken_pkg" = "yes"])

AC_ARG_WITH([liboath],
	AS_HELP_STRING([--without-liboath],
	[Build without liboath library [default=auto]]))
AS_IF([test "x$with_liboath" != "xno"], [
	PKG_CHECK_MODULES(LIBOATH, [liboath >= 1.12.0],
		[AC_SUBST(LIBOATH_PC, liboath)
		 AC_DEFINE([HAVE_LIBOATH], 1, [Have liboath])
		 liboath_pkg=yes],
		 liboath_pkg=no)
	if test "$liboath_pkg" = "yes"; then
	    PKG_CHECK_MODULES(LIBPSKC, [libpskc >= 2.2.0],
		[AC_SUBST(LIBPSKC_PC, libpskc)
		 AC_DEFINE([HAVE_LIBPSKC], 1, [Have libpskc])
		 libpskc_pkg=yes],
		 libpskc_pkg=no)
	fi
])
AM_CONDITIONAL(OPENCONNECT_OATH, [test "$liboath_pkg" = "yes"])

linked_gssapi=no
AC_ARG_WITH([gssapi],
	AS_HELP_STRING([--without-gssapi],
	[Build without GSSAPI support [default=auto]]))

AC_DEFUN([GSSAPI_CHECK_BUILD],[
	gss_old_libs="$LIBS"
	LIBS="$LIBS ${GSSAPI_LIBS}"
	AC_MSG_CHECKING([GSSAPI compilation with "${GSSAPI_LIBS}"])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([
			#include <stdlib.h>
			#include GSSAPI_HDR],[
			OM_uint32 major, minor;
			gss_buffer_desc b = GSS_C_EMPTY_BUFFER;
			gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
			gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctx, GSS_C_NO_NAME, GSS_C_NO_OID,
			    GSS_C_MUTUAL_FLAG, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL,
			    NULL, NULL, NULL);])],
	    [linked_gssapi=yes
	     AC_MSG_RESULT(yes)],
	    [linked_gssapi=no
	     AC_MSG_RESULT(no)])
	LIBS="$gss_old_libs"
])

# Attempt to work out how to build with GSSAPI. Mostly, krb5-config will
# exist and work. Tested on FreeBSD 9, OpenBSD 5.5, NetBSD 6.1.4. Solaris
# has krb5-config but it doesn't do GSSAPI so hard-code the results there.
# Older OpenBSD (I tested 5.2) lacks krb5-config so leave that as an example.
if test "$with_gssapi" != "no"; then
    found_gssapi=no

    if test "${with_gssapi}" != "yes" -a "${with_gssapi}" != "" ; then
	gssapi_root="${with_gssapi}"
    else
	gssapi_root=""
    fi

    # First: if they specify GSSAPI_LIBS and/or GSSAPI_CFLAGS then use them.
    if test "$GSSAPI_LIBS$GSSAPI_CFLAGS" != ""; then
	found_gssapi=yes
    fi
    # Second: try finding a viable krb5-config that supports gssapi
    if test "$found_gssapi" = "no"; then
        if test -n "${gssapi_root}"; then
	    krb5path="${gssapi_root}/bin:$PATH"
	else
	    krb5path="/usr/kerberos/bin:$PATH"
	fi

	if test -n "$host_alias"; then
	    AC_PATH_PROG(KRB5_CONFIG, [${host_alias}-krb5-config], [], [$krb5path])
	fi
	if test "$KRB5_CONFIG" = ""; then
	    AC_PATH_PROG(KRB5_CONFIG, [krb5-config], [], [$krb5path])
	fi
	if test "$KRB5_CONFIG" != ""; then
	    AC_MSG_CHECKING([whether $KRB5_CONFIG supports gssapi])
	    if "${KRB5_CONFIG}" --cflags gssapi > /dev/null 2>/dev/null; then
		AC_MSG_RESULT(yes)
		found_gssapi=yes
		GSSAPI_LIBS="`"${KRB5_CONFIG}" --libs gssapi`"
		GSSAPI_CFLAGS="`"${KRB5_CONFIG}" --cflags gssapi`"
	    else
		AC_MSG_RESULT(no)
	    fi
	fi
    fi
    # Third: look for <gssapi.h> or <gssapi/gssapi.h> in some likely places,
    #        and we'll worry about how to *link* it in a moment...
    if test "$found_gssapi" = "no"; then
	if test -n "${gssapi_root}"; then
	    if test -r "${with_gssapi}/include/gssapi.h" -o \
		    -r "${with_gssapi}/include/gssapi/gssapi.h"; then
		GSSAPI_CFLAGS="-I\"${with_gssapi}/include\""
	    fi
	else
	    if test -r /usr/kerberos/include/gssapi.h -o \
		      -r /usr/kerberos/include/gssapi/gssapi.h; then
		GSSAPI_CFLAGS=-I/usr/kerberos/include
	    elif test -r /usr/include/kerberosV/gssapi.h -o \
		      -r /usr/include/kerberosV/gssapi/gssapi.h; then
		# OpenBSD 5.2 puts it here
		GSSAPI_CFLAGS=-I/usr/include/kerberosV
	    else
		# Maybe it'll Just Work
		GSSAPI_CFLAGS=
	    fi
	fi
    fi

    oldcflags="$CFLAGS"
    CFLAGS="$CFLAGS ${GSSAPI_CFLAGS}"

    # OK, now see if we've correctly managed to find gssapi.h at least...
    gssapi_hdr=
    AC_CHECK_HEADER([gssapi/gssapi.h],
	[gssapi_hdr="<gssapi/gssapi.h>"],
	[AC_CHECK_HEADER([gssapi.h],
		[gssapi_hdr="<gssapi.h>"],
		[AC_MSG_WARN([Cannot find <gssapi/gssapi.h> or <gssapi.h>])])])

    # Finally, unless we've already failed, see if we can link it.
    linked_gssapi=no
    if test -n "${gssapi_hdr}"; then
	AC_DEFINE_UNQUOTED(GSSAPI_HDR, $gssapi_hdr, [GSSAPI header])
	if test "$found_gssapi" = "yes"; then
	    # We think we have GSSAPI_LIBS already so try it...
	    GSSAPI_CHECK_BUILD
	else
	    LFLAG=
	    if test -n "$gssapi_root"; then
		LFLAG="-L\"${gssapi_root}/lib$libsuff\""
	    fi
	    # Solaris, HPUX, etc.
	    GSSAPI_LIBS="$LFLAG -lgss"
	    GSSAPI_CHECK_BUILD
	    if test "$linked_gssapi" = "no"; then
		GSSAPI_LIBS="$LFLAG -lgssapi"
		GSSAPI_CHECK_BUILD
	    fi
	    if test "$linked_gssapi" = "no"; then
		GSSAPI_LIBS="$LFLAG -lgssapi_krb5"
		GSSAPI_CHECK_BUILD
	    fi
	    if test "$linked_gssapi" = "no"; then
		# OpenBSD 5.2 at least
		GSSAPI_LIBS="$LFLAG -lgssapi -lkrb5 -lcrypto"
		GSSAPI_CHECK_BUILD
	    fi
	    if test "$linked_gssapi" = "no"; then
		# MIT
		GSSAPI_LIBS="$LFLAG -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err"
		GSSAPI_CHECK_BUILD
	    fi
	    if test "$linked_gssapi" = "no"; then
		# Heimdal
		GSSAPI_LIBS="$LFLAG -lkrb5 -lcrypto -lasn1 -lcom_err -lroken -lgssapi"
		GSSAPI_CHECK_BUILD
	    fi
	    if test "$linked_gssapi" = "no"; then
		AC_MSG_WARN([Cannot find GSSAPI. Try setting GSSAPI_LIBS and GSSAPI_CFLAGS manually])
	    fi
	fi
    fi

    CFLAGS="$oldcflags"

    if test "$linked_gssapi" = "yes"; then
	AC_DEFINE([HAVE_GSSAPI], 1, [Have GSSAPI support])
	AC_SUBST(GSSAPI_CFLAGS)
	AC_SUBST(GSSAPI_LIBS)
    elif test "$with_gssapi" = ""; then
	AC_MSG_WARN([Building without GSSAPI support]);
	unset GSSAPI_CFLAGS
	unset GSSAPI_LIBS
    else
	AC_MSG_ERROR([GSSAPI support requested but not found. Try setting GSSAPI_LIBS/GSSAPI_CFLAGS])
    fi
fi
AM_CONDITIONAL(OPENCONNECT_GSSAPI, [test "$linked_gssapi" = "yes"])

AC_ARG_WITH([java],
	AS_HELP_STRING([--with-java(=DIR)],
		       [Build JNI bindings using jni.h from DIR [default=no]]),
	[], [with_java=no])

if test "$with_java" = "yes"; then
	AX_JNI_INCLUDE_DIR
	for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS; do
		  JNI_CFLAGS="$JNI_CFLAGS -I$JNI_INCLUDE_DIR"
	done
elif test "$with_java" = "no"; then
	JNI_CFLAGS=""
else
	JNI_CFLAGS="-I$with_java"
fi

if test "x$JNI_CFLAGS" != "x"; then
	oldCFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $JNI_CFLAGS"
	AC_MSG_CHECKING([jni.h usability])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <jni.h>],
		[jint foo = 0; (void)foo;])],
		AC_MSG_RESULT([yes]),
		[AC_MSG_RESULT([no])
		 AC_MSG_ERROR([unable to compile JNI test program])])
	CFLAGS="$oldCFLAGS"

	AC_SUBST(JNI_CFLAGS, [$JNI_CFLAGS])
fi

AM_CONDITIONAL(OPENCONNECT_JNI, [test "$JNI_CFLAGS" != ""])

AC_ARG_ENABLE([jni-standalone],
	AS_HELP_STRING([--enable-jni-standalone],
		       [build JNI stubs directly into libopenconnect.so [default=no]]),
	[jni_standalone=$enableval],
	[jni_standalone=no])
AM_CONDITIONAL(JNI_STANDALONE, [test $jni_standalone = yes])
symver_java=
if test "$jni_standalone" = "yes" ; then
   symver_java=$(sed -n '/JNIEXPORT/{s/^JNIEXPORT.*\(Java_.*\) *(/\1;/ p}' ${srcdir}/jni.c)
   # Remove the newlines between each item.
   symver_java=$(echo $symver_java)
fi
AC_SUBST(SYMVER_JAVA, $symver_java)

AC_CHECK_HEADER([if_tun.h],
    [AC_DEFINE([IF_TUN_HDR], ["if_tun.h"], [if_tun.h include path])],
    [AC_CHECK_HEADER([linux/if_tun.h],
        [AC_DEFINE([IF_TUN_HDR], ["linux/if_tun.h"])],
        [AC_CHECK_HEADER([net/if_tun.h],
            [AC_DEFINE([IF_TUN_HDR], ["net/if_tun.h"])],
            [AC_CHECK_HEADER([net/tun/if_tun.h],
                [AC_DEFINE([IF_TUN_HDR], ["net/tun/if_tun.h"])])])])])

AC_CHECK_HEADER([net/if_utun.h], AC_DEFINE([HAVE_NET_UTUN_H], 1, [Have net/utun.h]))
AC_CHECK_HEADER([alloca.h], AC_DEFINE([HAVE_ALLOCA_H], 1, [Have alloca.h]))

if test "$ssl_library" = "openssl" || test "$ssl_library" = "both"; then
    oldLIBS="$LIBS"
    LIBS="$LIBS $OPENSSL_LIBS"
    oldCFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $OPENSSL_CFLAGS"

    if test "$ssl_library" = "openssl"; then
	AC_MSG_CHECKING([for ENGINE_by_id() in OpenSSL])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <openssl/engine.h>],
				        [ENGINE_by_id("foo");])],
		       [AC_MSG_RESULT(yes)
			AC_DEFINE(HAVE_ENGINE, [1], [OpenSSL has ENGINE support])],
		       [AC_MSG_RESULT(no)
			AC_MSG_NOTICE([Building without OpenSSL TPM ENGINE support])])
    fi

    AC_MSG_CHECKING([for dtls1_stop_timer() in OpenSSL])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <openssl/ssl.h>
				     #include <stdlib.h>
				     extern void dtls1_stop_timer(SSL *);],
				    [dtls1_stop_timer(NULL);])],
		   [AC_MSG_RESULT(yes)
		    AC_DEFINE(HAVE_DTLS1_STOP_TIMER, [1], [OpenSSL has dtls1_stop_timer() function])],
		   [AC_MSG_RESULT(no)])
    LIBS="$oldLIBS"
    CFLAGS="$oldCFLAGS"
fi

build_www=yes
AC_PATH_PROGS(PYTHON, [python2 python], [], $PATH:/bin:/usr/bin)
if (test -n "${ac_cv_path_PYTHON}"); then
   AC_MSG_CHECKING([that python is version 2.x])
   if $PYTHON --version 2>&1 | grep "Python 2\." > /dev/null; then
      AC_MSG_RESULT([yes])
      AC_SUBST(PYTHON, ${ac_cv_path_PYTHON})
   else
      AC_MSG_RESULT([no])
      AC_MSG_NOTICE([Python is not v2.x; not building HTML pages])
      build_www=no
   fi
else
   AC_MSG_NOTICE([Python not found; not building HTML pages])
   build_www=no
fi
if test "${build_www}" = "yes"; then
   AC_MSG_CHECKING([if groff can create UTF-8 XHTML])
   AC_PATH_PROGS_FEATURE_CHECK([GROFF], [groff],
	[$ac_path_GROFF -t -K UTF-8 -mandoc -Txhtml /dev/null > /dev/null 2>&1 &&
	 ac_cv_path_GROFF=$ac_path_GROFF])
   if test -n "$ac_cv_path_GROFF"; then
      AC_MSG_RESULT(yes)
      AC_SUBST(GROFF, ${ac_cv_path_GROFF})
   else
      AC_MSG_RESULT([no. Not building HTML pages])
      build_www=no
   fi
fi
AM_CONDITIONAL(BUILD_WWW, [test "${build_www}" = "yes"])

AC_SUBST([CONFIG_STATUS_DEPENDENCIES], ['$(top_srcdir)/po/LINGUAS $(top_srcdir)/openconnect.h ${top_srcdir}/libopenconnect.map.in'])
RAWLINGUAS=`sed -e "/^#/d" -e "s/#.*//" "${srcdir}/po/LINGUAS"`
# Remove newlines
LINGUAS=`echo $RAWLINGUAS`
AC_SUBST(LINGUAS)

APIMAJOR="`sed -n 's/^#define OPENCONNECT_API_VERSION_MAJOR \(.*\)/\1/p' ${srcdir}/openconnect.h`"
APIMINOR="`sed -n 's/^#define OPENCONNECT_API_VERSION_MINOR \(.*\)/\1/p' ${srcdir}/openconnect.h`"
AC_SUBST(APIMAJOR)
AC_SUBST(APIMINOR)

# We want version.c to depend on the files that would affect the
# output of version.sh. But we cannot assume that they'll exist,
# and we cannot use $(wildcard) in a non-GNU makefile. So we just
# depend on the files which happen to exist at configure time.
GITVERSIONDEPS=
for a in ${srcdir}/.git/index ${srcdir}/.git/packed-refs \
         ${srcdir}/.git/refs/tags ${srcdir}/.git/HEAD; do
    if test -r $a ; then
       GITVERSIONDEPS="$GITVERSIONDEPS $a"
    fi
done
AC_SUBST(GITVERSIONDEPS)

AC_CONFIG_FILES(Makefile openconnect.pc po/Makefile www/Makefile \
		libopenconnect.map openconnect.8 www/styles/Makefile \
		www/inc/Makefile www/images/Makefile)
AC_OUTPUT
