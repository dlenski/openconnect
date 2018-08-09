#!/bin/sh

$(type glibtoolize >/dev/null 2>&1) && LIBTOOLIZE=${LIBTOOLIZE:-glibtoolize}
aclocal -I m4 && \
${LIBTOOLIZE:-libtoolize} --automake --force && \
autoheader --force &&
automake --foreign --add-missing --force && \
autoconf --force
