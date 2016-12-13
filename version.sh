#!/bin/sh

v="v7.08"

if [ -d ${GIT_DIR:-.git} ] && tag=`git describe --tags`; then
	v="$tag"

	# Update the index from working tree first
	git update-index --refresh --unmerged > /dev/null

	# Does the index show uncommitted changes?
	git diff-index --exit-code HEAD > /dev/null || \
		v="$v"-dirty
elif [ -n "$RPM_PACKAGE_VERSION" ] && [ -n "$RPM_PACKAGE_RELEASE" ]; then
	v="v$RPM_PACKAGE_VERSION-$RPM_PACKAGE_RELEASE"
else # XXX: Equivalent for .deb packages?
	v="$v"-unknown
fi

echo "const char *openconnect_version_str = \"$v\";" > $1
echo "New version: $v"
