FROM debian:8-slim
WORKDIR /openconnect
RUN apt update \
    && apt install -y  \
	build-essential \
	gettext \
	autoconf \
	automake \
	libproxy-dev \
	libxml2-dev \
	libtool \
	vpnc-scripts \
	pkg-config \
	libgnutls28-dev \
	git
ADD . .
RUN ./autogen.sh
RUN ./configure
RUN make
RUN make install
RUN ldconfig
