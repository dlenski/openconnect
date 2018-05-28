FROM alpine:3.7

RUN echo "http://dl-4.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
  && apk add --update --no-cache --virtual=build-dependencies \
    automake \
    autoconf \
    gcc \
    g++ \
    gettext \
    git \
    linux-headers \
    libtool \
    libxml2-dev \
    make \
    openssl-dev \
    pkgconfig \
    vpnc \
  && git clone https://github.com/dlenski/openconnect.git /tmp/openconnect \
  && cd /tmp/openconnect \
  && git checkout bfaba1b2ba2777f2495251e3870e5e88b5275fcc \
  && ./autogen.sh \
  && ./configure --with-vpnc-script=/etc/vpnc/vpnc-script --without-openssl-version-check \
  && make install \
  && apk del --purge build-dependencies \
  && rm -rf /tmp/* \
  && apk add --no-cache \
    openssl \
    libxml2 \
    vpnc \
  && mkdir /var/run/vpnc

ENTRYPOINT ["/usr/local/sbin/openconnect"]
CMD ["--help"]