
AC_INIT(openconnect, 3.12)
PKG_PROG_PKG_CONFIG
AC_LANG_C
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

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
         -Wmissing-noreturn
         -Wnested-externs
         -Wpointer-arith
         -Wundef
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

AC_PROG_LIBTOOL

PKG_CHECK_MODULES(LIBXML2, libxml-2.0)
PKG_CHECK_MODULES(ZLIB, zlib)

PKG_CHECK_MODULES(LIBPROXY, libproxy-1.0,
		[AC_SUBST(LIBPROXY_PC, libproxy-1.0)
		 AC_DEFINE([LIBPROXY_HDR], ["proxy.h"])
		 libproxy_pkg=yes],
		 libproxy_pkg=no)
dnl Libproxy *can* exist without a .pc file, and its header may be called
dnl libproxy.h in that case.
if (test "$libproxy_pkg" = "no"); then
   AC_CHECK_HEADER([proxy.h],
	[AC_DEFINE([LIBPROXY_HDR], ["proxy.h"])
	 AC_SUBST([LIBPROXY_LIBS], [-lproxy])],
    [AC_CHECK_HEADER([libproxy.h],
	[AC_DEFINE([LIBPROXY_HDR], ["libproxy.h"])
	 AC_SUBST([LIBPROXY_LIBS], [-lproxy])])])
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

AC_OUTPUT(Makefile openconnect.pc)
