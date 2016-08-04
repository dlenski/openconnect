EXTRA_DIST = certs/ca-key.pem certs/ca.pem certs/server-cert.pem certs/server-key.pem \
	certs/user-cert.pem certs/user-key.pem configs/test1.passwd \
	common.sh configs/test-user-cert.config configs/test-user-pass.config

dist_check_SCRIPTS = auth-username-pass auth-certificate

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"

if DTLS_OPENSSL
TESTS += bad_dtls_test

noinst_PROGRAMS = bad_dtls_test
bad_dtls_test_SOURCES = bad_dtls_test.c
bad_dtls_test_CFLAGS = $(OPENSSL_CFLAGS)
bad_dtls_test_LDADD = $(OPENSSL_LIBS)
endif
