#!/bin/sh

intltoolize --force --copy --automake && \
    aclocal && \
        libtoolize --automake --copy --force && \
            automake --foreign --add-missing && \
                autoconf
