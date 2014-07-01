#!/bin/sh

aclocal && \
${LIBTOOLIZE:-libtoolize} --automake --force && \
autoheader --force &&
automake --foreign --add-missing --force && \
autoconf --force
