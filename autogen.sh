#!/bin/sh

    aclocal && \
        libtoolize --automake --force && \
            automake --foreign --add-missing --force && \
                autoconf --force
