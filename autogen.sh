#!/bin/sh

intltoolize --force --copy --automake || \
    echo "*** Continuing without NLS support..."

    aclocal && \
        libtoolize --automake --copy --force && \
            automake --foreign --add-missing && \
                autoconf
