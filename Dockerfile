FROM alpine:edge
ENV BUILD_ENV="file \
                g++ \
                gnutls-dev \
                libnl3-dev \
                libseccomp-dev \
                linux-pam-dev\
                linux-headers \
                lz4-dev \
                make \
                readline-dev \
                vpnc \
                autoconf \
                automake \
                libtool \
                libxml2-dev \
                git"
COPY . /openconnect
WORKDIR /openconnect
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
    && apk add --no-cache --virtual .build-deps ${BUILD_ENV} \
    && ./autogen.sh \
    && ./configure \
    && make \
    && make install \
    && ldconfig . -v \
    && apk del .build-deps \
    && rm -rf /openconnect \
    && apk add --no-cache gnutls libxml2 lz4-dev gettext ca-certificates vpnc
WORKDIR /
ENTRYPOINT ["/usr/local/sbin/openconnect"]
