USER_KEYS = \
	$(srcdir)/certs/user-key-pkcs1.pem $(srcdir)/certs/user-key-pkcs1.der \
	$(srcdir)/certs/user-key-pkcs1-aes128.pem \
	$(srcdir)/certs/user-key-pkcs8.pem $(srcdir)/certs/user-key-pkcs8.der \
	$(srcdir)/certs/user-key-pkcs8-pbes1-sha1-3des.pem $(srcdir)/certs/user-key-pkcs8-pbes1-sha1-3des.der \
	$(srcdir)/certs/user-key-pkcs8-pbes2-sha1.pem $(srcdir)/certs/user-key-pkcs8-pbes2-sha1.der \
	$(srcdir)/certs/user-cert-key.p12

# We know GnuTLS doesn't support these for now. https://bugzilla.redhat.com/1369484
if OPENCONNECT_OPENSSL
USER_KEYS += $(srcdir)/certs/user-key-pkcs8-pbes2-sha256.pem $(srcdir)/certs/user-key-pkcs8-pbes2-sha256.der
USER_KEYS += $(srcdir)/certs/user-key-pkcs8-pbes1-md5-des.pem $(srcdir)/certs/user-key-pkcs8-pbes1-md5-des.der
endif

EXTRA_DIST = certs/ca.pem certs/ca-key.pem certs/user-cert.pem $(USER_KEYS) \
	certs/server-cert.pem certs/server-key.pem configs/test1.passwd \
	common.sh configs/test-user-cert.config configs/test-user-pass.config

dist_check_SCRIPTS = auth-username-pass auth-certificate

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)" \
	key_list="$(USER_KEYS)"

if DTLS_OPENSSL
TESTS += bad_dtls_test

noinst_PROGRAMS = bad_dtls_test
bad_dtls_test_SOURCES = bad_dtls_test.c
bad_dtls_test_CFLAGS = $(OPENSSL_CFLAGS)
bad_dtls_test_LDADD = $(OPENSSL_LIBS)
endif

# Nothing actually *depends* on the cert files; they are created manually
# and considered part of the sources, committed to the git tree. But for
# reference, the commands used to generate them are here...

# certs/user-key-pkcs1.pem:
keyfiles: $(USER_KEYS)


OPENSSL = openssl
OSSLARGS = -in $< -out $@ -passout pass:password
OSSLARGSP12 = -inkey $< -out $@ -in $(srcdir)/certs/user-cert.pem -passout pass:password

# Even in OpenSSL 1.1, this creates the old encrypted PEM format.
$(srcdir)/certs/user-key-pkcs1-aes128.pem: certs/user-key-pkcs1.pem
	$(OPENSSL) rsa $(OSSLARGS) -aes128

# Plain unencrypted PKCS#8
$(srcdir)/certs/user-key-pkcs8.pem: certs/user-key-pkcs1.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -nocrypt

$(srcdir)/certs/user-key-pkcs8-pbes1-sha1-3des.pem: certs/user-key-pkcs1.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v1 pbeWithSHA1And3-KeyTripleDES-CBC

# This is the default created by OpenSSL 1.0.2 with -topk8
$(srcdir)/certs/user-key-pkcs8-pbes1-md5-des.pem: certs/user-key-pkcs1.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v1 pbeWithMD5AndDES-CBC

$(srcdir)/certs/user-key-pkcs8-pbes2-sha1.pem: certs/user-key-pkcs1.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v2 aes256 -v2prf hmacWithSHA1

# This is the default created by OpenSSL 1.1 with -topk8
$(srcdir)/certs/user-key-pkcs8-pbes2-sha256.pem: certs/user-key-pkcs1.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v2 aes256 -v2prf hmacWithSHA256

$(srcdir)/certs/user-cert-key.p12: certs/user-key-pkcs1.pem
	$(OPENSSL) pkcs12 $(OSSLARGSP12) -export

%.der: %.pem
	grep -v -- ^----- $< | base64 -d > $@
