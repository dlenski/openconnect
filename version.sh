#!/bin/sh
#
# version.sh -- report a useful version for releases
#
# Copyright 2008, Aron Griffis <agriffis@n01se.net>
# Copyright 2008, Oracle
# Released under the GNU GPLv2

v="v1.40"

which git >/dev/null 2>/dev/null
if [ $? = 0 -a -d .git ]; then
    if head=`git rev-parse --verify HEAD 2>/dev/null`; then
        if tag=`git describe --tags 2>/dev/null`; then
            v="$tag"
        fi

        # Are there uncommitted changes?
        git update-index --refresh --unmerged > /dev/null
        if git diff-index --name-only HEAD | grep -v "^scripts/package" \
            | read dummy; then
            v="$v"-dirty
        fi
    fi
else
    v="$v"-unknown
fi

echo "char openconnect_version[] = \"$v\";" > version.c

