#!/bin/sh

    aclocal && \
        ${LIBTOOLIZE:-libtoolize} --automake --force && \
            automake --foreign --add-missing --force && \
                autoconf --force
