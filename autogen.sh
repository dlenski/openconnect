#!/bin/sh

    aclocal && \
        libtoolize --automake --copy --force && \
            automake --foreign --add-missing && \
                autoconf
