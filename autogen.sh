#!/bin/sh

aclocal -I m4 && \
${LIBTOOLIZE:-libtoolize} --automake --force && \
autoheader --force &&
automake --foreign --add-missing --force && \
autoconf --force
