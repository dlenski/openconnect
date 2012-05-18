AC_INIT(openconnect, 3.20)
PKG_PROG_PKG_CONFIG
AC_LANG_C
AC_CANONICAL_HOST
AM_MAINTAINER_MODE([enable])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Define htmldir and localedir for users of ancient autoconf building from git
AC_PREREQ([2.59c], [], [AC_SUBST([htmldir], [m4_ifset([AC_PACKAGE_TARNAME],
	  ['${datadir}/doc/${PACKAGE_TARNAME}'],
	  ['${datadir}/doc/${PACKAGE}'])
])])

AC_PREREQ([2.60], [], [AC_SUBST([localedir], ['$(datadir)/locale'])])

AC_ARG_WITH([vpnc-script],
	[AS_HELP_STRING([--with-vpnc-script],
	  [default location of vpnc-script helper])])

if test "$with_vpnc_script" = "yes" || test "$with_vpnc_script" = ""; then
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
    [build OpenConnect to use the script from this location, even though it's]
    [not present at the time you are building OpenConnect, pass the argument]
    ["--with-vpnc-script=${with_vpnc_script}"])
  fi
elif test "$with_vpnc_script" = "no"; then
   AC_ERROR([You cannot disable vpnc-script.]
   [OpenConnect will not function correctly without it.]
   [See http://www.infradead.org/openconnect/vpnc-script.html])
fi

AC_DEFINE_UNQUOTED(DEFAULT_VPNCSCRIPT, "${with_vpnc_script}")

case $host_os in
 *linux* | *gnu*)
    AC_MSG_NOTICE([Applying feature macros for GNU build])
    AC_DEFINE(_POSIX_C_SOURCE, 200112L)
    # For strcasecmp() 
    AC_DEFINE(_BSD_SOURCE)
    # For asprintf()
    AC_DEFINE(_GNU_SOURCE)
    ;;
 *netbsd*)
    AC_MSG_NOTICE([Applying feature macros for NetBSD build])
    AC_DEFINE(_POSIX_C_SOURCE, 200112L)
    AC_DEFINE(_NETBSD_SOURCE)
    ;;
 *)
    # On FreeBSD the only way to get vsyslog() visible is to define
    #  *nothing*, which makes absolutely everything visible.
    # On Darwin enabling _POSIX_C_SOURCE breaks <sys/mount.h> because
    # u_long and other types don't get defined. OpenBSD is similar.
    ;;
esac

symver_time=
symver_getline=
symver_asprintf=

case $host_os in
 *solaris*|*sunos*)
    symver_time="openconnect__time;"
    ;;
esac

AC_CHECK_FUNC(getline, [AC_DEFINE(HAVE_GETLINE, 1)], [symver_getline="openconnect__getline;"])
AC_CHECK_FUNC(strcasestr, [AC_DEFINE(HAVE_STRCASESTR, 1)], [])
AC_CHECK_FUNC(asprintf, [AC_DEFINE(HAVE_ASPRINTF, 1)], [symver_asprintf="openconnect__asprintf;"])
if test -n "$symver_asprintf"; then
  AC_MSG_CHECKING([for va_copy])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([
	#include <stdarg.h>
	va_list a;],[
	va_list b;
	va_copy(b,a);
	va_end(b);])],
	[AC_DEFINE(HAVE_VA_COPY, 1)
	AC_MSG_RESULT(va_copy)],
	[AC_LINK_IFELSE([AC_LANG_PROGRAM([
		#include <stdarg.h>
		va_list a;],[
		va_list b;
		__va_copy(b,a);
		va_end(b);])],
		[AC_DEFINE(HAVE___VA_COPY, 1)
		AC_MSG_RESULT(__va_copy)],
		[AC_MSG_RESULT(no)
		AC_MSG_ERROR([Your system lacks asprintf() and va_copy()])])
	])
fi
AC_SUBST(SYMVER_TIME, $symver_time)
AC_SUBST(SYMVER_GETLINE, $symver_getline)
AC_SUBST(SYMVER_ASPRINTF, $symver_asprintf)

AS_COMPILER_FLAGS(CFLAGS,
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

AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_ARG_ENABLE([nls],
	[ --disable-nls           do not use Native Language Support],
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
      [AC_MSG_RESULT(no)
       USE_NLS=no])
     LIBS="$oldLIBS"])
fi

if test "$USE_NLS" = "yes"; then
   AC_SUBST(LIBINTL)
   AC_DEFINE(ENABLE_NLS, 1)
fi
AM_CONDITIONAL(USE_NLS, [test "$USE_NLS" = "yes"])

AC_ARG_WITH([openssl],
            AS_HELP_STRING([--with-openssl],
                           [Location of OpenSSL build dir]),
            [OPENSSL_CFLAGS="-I${with_openssl}/include"
             OPENSSL_LIBS="${with_openssl}/libssl.a ${with_openssl}/libcrypto.a -ldl -lz"
	     AC_SUBST(OPENSSL_CFLAGS)
	     AC_SUBST(OPENSSL_LIBS)
	     enable_static=yes
	     enable_shared=no],
	    [PKG_CHECK_MODULES(OPENSSL, openssl, [],
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
				AC_ERROR([Could not build against OpenSSL])])
				LIBS="$oldLIBS"])])

# Needs to happen after we default to static/shared libraries based on OpenSSL
AC_PROG_LIBTOOL

# Ick. This seems like it's likely to be very fragile, but I can't see a better
# way. I shall console myself with the observation that the failure mode isn't
# particularly horrible — you just don't get symbol versioning if it fails.
symvers=no
if test "$enable_shared" = "yes" ; then
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

PKG_CHECK_MODULES(ZLIB, zlib, [],
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

PKG_CHECK_MODULES(LIBPROXY, libproxy-1.0,
		[AC_SUBST(LIBPROXY_PC, libproxy-1.0)
		 AC_DEFINE([LIBPROXY_HDR], ["proxy.h"])
		 libproxy_pkg=yes],
		 libproxy_pkg=no)
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

AC_CHECK_HEADER([if_tun.h],
    [AC_DEFINE([IF_TUN_HDR], ["if_tun.h"])],
    [AC_CHECK_HEADER([linux/if_tun.h],
        [AC_DEFINE([IF_TUN_HDR], ["linux/if_tun.h"])],
        [AC_CHECK_HEADER([net/if_tun.h],
            [AC_DEFINE([IF_TUN_HDR], ["net/if_tun.h"])],
            [AC_CHECK_HEADER([net/tun/if_tun.h],
                [AC_DEFINE([IF_TUN_HDR], ["net/tun/if_tun.h"])])])])])

oldLIBS="$LIBS"
LIBS="$LIBS $OPENSSL_LIBS"

AC_MSG_CHECKING([for ENGINE_by_id() in OpenSSL])
AC_LINK_IFELSE([AC_LANG_PROGRAM(
	[#include <openssl/engine.h>],
	[ENGINE_by_id("foo");])],
	[AC_MSG_RESULT(yes)
	 AC_DEFINE(HAVE_ENGINE, [1], [OpenSSL has ENGINE support])],
	[AC_MSG_RESULT(no)
	 AC_MSG_NOTICE([Building without OpenSSL TPM ENGINE support])])

AC_MSG_CHECKING([for dtls1_stop_timer() in OpenSSL])
AC_LINK_IFELSE([AC_LANG_PROGRAM(
	[#include <openssl/ssl.h>
	 #include <stdlib.h>
	 extern void dtls1_stop_timer(SSL *);],
	[dtls1_stop_timer(NULL);])],
	[AC_MSG_RESULT(yes)
	 AC_DEFINE(HAVE_DTLS1_STOP_TIMER, [1], [OpenSSL has dtls1_stop_timer() function])],
	[AC_MSG_RESULT(no)])
LIBS="$oldLIBS"

AC_PATH_PROG(PYTHON, [python], [], $PATH:/bin:/usr/bin)
if (test -n "${ac_cv_path_PYTHON}"); then
   AC_SUBST(PYTHON, ${ac_cv_path_PYTHON})
else
   AC_MSG_NOTICE([Python not found; not building HTML pages])
fi
AM_CONDITIONAL(BUILD_WWW, [test -n "${ac_cv_path_PYTHON}"])

AC_SUBST([CONFIG_STATUS_DEPENDENCIES], ['$(top_srcdir)/po/LINGUAS $(top_srcdir)/openconnect.h'])
RAWLINGUAS=`sed -e "/^#/d" -e "s/#.*//" "${srcdir}/po/LINGUAS"`
# Remove newlines
LINGUAS=`echo $RAWLINGUAS`
AC_SUBST(LINGUAS)

APIMAJOR="`sed -n 's/^#define OPENCONNECT_API_VERSION_MAJOR \(.*\)/\1/p' openconnect.h`"
APIMINOR="`sed -n 's/^#define OPENCONNECT_API_VERSION_MINOR \(.*\)/\1/p' openconnect.h`"
AC_SUBST(APIMAJOR)
AC_SUBST(APIMINOR)

# We want version.c to depend on the files that would affect the
# output of version.sh. But we cannot assume that they'll exist,
# and we cannot use $(wildcard) in a non-GNU makefile. So we just
# depend on the files which happen to exist at configure time.
GITVERSIONDEPS=
for a in .git/index .git/packed-refs .git/refs/tags .git/HEAD; do
    if test -r $a ; then
       GITVERSIONDEPS="$GITVERSIONDEPS $a"
    fi
done
AC_SUBST(GITVERSIONDEPS)

AC_OUTPUT(Makefile openconnect.pc po/Makefile www/Makefile libopenconnect.map \
	  www/styles/Makefile www/inc/Makefile www/images/Makefile)
