
AC_INIT(openconnect, 3.16)
PKG_PROG_PKG_CONFIG
AC_LANG_C
AC_CANONICAL_HOST
AM_MAINTAINER_MODE([enable])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

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

AC_ARG_WITH([openssl],
            AS_HELP_STRING([--with-openssl],
                           [Location of OpenSSL build dir]),
            [OPENSSL_CFLAGS="-I${with_openssl}/include"
             OPENSSL_LIBS="${with_openssl}/libssl.a ${with_openssl}/libcrypto.a -ldl -lz"
	     AC_SUBST(OPENSSL_CFLAGS)
	     AC_SUBST(OPENSSL_LIBS)
	     AC_ENABLE_STATIC
	     AC_DISABLE_SHARED],
	    [PKG_CHECK_MODULES(OPENSSL, openssl)
	     AC_ENABLE_SHARED
	     AC_DISABLE_STATIC])

# Needs to happen after we default to static/shared libraries based on OpenSSL
AC_PROG_LIBTOOL

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
		   AC_ERROR([Could not build against zlib])])])

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

AC_CHECK_LIB(ssl, ENGINE_by_id,
	     AC_DEFINE(HAVE_ENGINE, [1], [OpenSSL has ENGINE support]),
	     AC_MSG_NOTICE([Building without OpenSSL TPM ENGINE support]),
	     ${OPENSSL_LIBS})

AC_CHECK_LIB(ssl, dtls1_stop_timer,
		  AC_DEFINE(HAVE_DTLS1_STOP_TIMER, [1], [OpenSSL has dtls1_stop_timer() function]),
		  ,,${OPENSSL_LIBS})

AC_PATH_PROG(PYTHON, [python], [], $PATH:/bin:/usr/bin)
if (test -n "${ac_cv_path_PYTHON}"); then
   AC_SUBST(PYTHON, ${ac_cv_path_PYTHON})
else
   AC_MSG_NOTICE([Python not found; not building HTML pages])
fi
AM_CONDITIONAL(BUILD_WWW, [test -n "${ac_cv_path_PYTHON}"])

AC_SUBST([CONFIG_STATUS_DEPENDENCIES], ['$(top_srcdir)/po/LINGUAS'])
RAWLINGUAS=`sed -e "/^#/d" -e "s/#.*//" "${srcdir}/po/LINGUAS"`
# Remove newlines
LINGUAS=`echo $RAWLINGUAS`
AC_SUBST(LINGUAS)

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

AC_OUTPUT(Makefile openconnect.pc po/Makefile www/Makefile \
	  www/styles/Makefile www/inc/Makefile www/images/Makefile)
