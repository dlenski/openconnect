#!/bin/sh

v="v3.16"

if [ -d .git ] && tag=`git describe --tags`; then
	v="$tag"

	# Update the index from working tree first
	git update-index --refresh --unmerged > /dev/null

	# Does the index show uncommitted changes?
	git diff-index --exit-code HEAD > /dev/null || \
		v="$v"-dirty
else
	v="$v"-unknown
fi

echo "char openconnect_version[] = \"$v\";" > $1
echo "New version: $v"
