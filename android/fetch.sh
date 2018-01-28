#!/bin/bash

#
# OpenConnect (SSL + DTLS) VPN client
#
# Copyright © 2014 Kevin Cernekee <cernekee@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# version 2.1, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#

set -e

libxml2_MIRROR_0=ftp://xmlsoft.org/libxml2
libxml2_MIRROR_1=ftp://gd.tuwien.ac.at/pub/libxml
libxml2_MIRROR_2=http://distfiles.macports.org/libxml2

gmp_MIRROR_0=http://ftp.gnu.org/gnu/gmp
gmp_MIRROR_1=ftp://ftp.gmplib.org/pub/gmp
gmp_MIRROR_2=http://mirror.anl.gov/pub/gnu/gmp
gmp_MIRROR_3=http://www.mirrorservice.org/sites/ftp.gnu.org/gnu/gmp

nettle_MIRROR_0=http://www.lysator.liu.se/~nisse/archive
nettle_MIRROR_1=http://mirror.anl.gov/pub/gnu/nettle
nettle_MIRROR_2=http://ftp.gnu.org/gnu/nettle
nettle_MIRROR_3=http://gd.tuwien.ac.at/gnu/gnusrc/nettle

gnutls_MIRROR_0=https://www.gnupg.org/ftp/gcrypt/gnutls/v3.5
gnutls_MIRROR_1=http://ftp.heanet.ie/mirrors/ftp.gnupg.org/gcrypt/gnutls/v3.5
gnutls_MIRROR_2=http://gd.tuwien.ac.at/pub/gnupg/gnutls/v3.5
gnutls_MIRROR_3=http://thammuz.tchpc.tcd.ie/mirrors/gnupg/gnutls/v3.5

stoken_MIRROR_0=http://sourceforge.net/projects/stoken/files
stoken_SUFFIX_0=/download

oath_toolkit_MIRROR_0=http://download.savannah.gnu.org/releases/oath-toolkit
oath_toolkit_MIRROR_1=http://packetstorm.wowhacker.com/UNIX/utilities
oath_toolkit_MIRROR_2=ftp://ftp.netbsd.org/pub/pkgsrc/distfiles

lz4_MIRROR_0=https://github.com/lz4/lz4/archive

MAX_TRIES=5

function make_url
{
	local tarball="$1"
	local mirror_idx="$2"

	local pkg="${tarball%-*}"
	pkg="${pkg/-/_}"

	if [[ "$pkg" =~ [^[:alnum:]_] ]]; then
		echo ""
		return
	fi

	eval local mirror_base="\$${pkg}_MIRROR_${mirror_idx}"
	eval local mirror_suffix="\$${pkg}_SUFFIX_${mirror_idx}"

	if [ -z "$mirror_base" ]; then
		echo ""
		return
	fi

	if [[ "${mirror_base}" = *//github.com*/archive* ]]; then
		# typical format: https://github.com/USER/PKG/archive/TAG.tar.gz
		echo "${mirror_base}/${tarball#*-}"
	else
		# typical format: http://.../PKG-TAG.tar.gz
		echo "${mirror_base}/${tarball}${mirror_suffix}"
	fi

	return

}

function check_hash
{
	local tarball="$1"
	local good_hash="$2"
	local actual_hash

	if [ "${#good_hash}" = "40" ]; then
		actual_hash=$(sha1sum "$tarball")
		actual_hash=${actual_hash:0:40}
	elif [ "${#good_hash}" = "64" ]; then
		actual_hash=$(sha256sum "$tarball")
		actual_hash=${actual_hash:0:64}
	else
		echo "Unrecognized hash: $good_hash"
		exit 1
	fi

	if [ "$actual_hash" = "$good_hash" ]; then
		return 0
	else
		echo "$tarball: hash mismatch"
		echo "  expected: $good_hash"
		echo "  got instead: $actual_hash"
		return 1
	fi
}

function download_and_check
{
	local url="$1"
	local tmpfile="$2"
	local hash="$3"

	rm -f "$tmpfile"
	if curl --location --connect-timeout 30 --speed-limit 1024 \
			-o "$tmpfile" "$url"; then
		if [ -n "$hash" ]; then
			if ! check_hash "$tmpfile" "$hash"; then
				return 1
			fi
		fi
		return 0
	fi
	return 1
}

# iterate through all available mirrors and make sure they have a good copy
# of $tarball
function mirror_test
{
	local tarball="$1"
	local good_hash="$2"

	if [ -z "$good_hash" ]; then
		echo "ERROR: you must specify the hash for testing mirrors"
		exit 1
	fi

	local mirror_idx=0
	local tmpfile="${tarball}.mirror-test.tmp"

	while :; do
		local url=$(make_url "$tarball" "$mirror_idx")
		if [ -z "$url" ]; then
			break
		fi

		echo ""
		echo "Testing mirror $url"
		echo ""

		if download_and_check "$url" "$tmpfile" "$good_hash"; then
			echo ""
			echo "SHA $good_hash OK."
			echo ""
		else
			exit 1
		fi

		echo ""
		mirror_idx=$((mirror_idx + 1))
	done

	rm -f "$tmpfile"
	echo "Mirror test for $tarball PASSED"
	echo ""
	exit 0
}

#
# MAIN
#

if [ "$1" = "--mirror-test" ]; then
	mirror_test=1
	shift
else
	mirror_test=0
fi

if [ -z "$1" ]; then
	echo "usage: $0 [ --mirror-test ] <tarball_to_fetch> [ <sha1_hash> ]"
	exit 1
fi

tarball="$1"
hash="$2"

if [ $mirror_test = 1 ]; then
	mirror_test "$tarball" "$hash"
	exit 1
fi

if [ -e "$tarball" -a -n "$hash" ]; then
	if check_hash "$tarball" "$hash"; then
		echo "$tarball hash check passed. Done."
		echo ""
		exit 0
	fi
fi

tries=1
tmpfile="${tarball}.tmp"

while :; do
	mirror_idx=0
	while :; do
		url=$(make_url "$tarball" "$mirror_idx")
		if [ -z "$url" ]; then
			if [ $mirror_idx = 0 ]; then
				echo "No mirrors found for $tarball"
				exit 1
			else
				break
			fi
		fi

		echo ""
		echo "Attempt #$tries for mirror $url:"
		echo ""

		if download_and_check "$url" "$tmpfile" "$hash"; then
			mv "$tmpfile" "$tarball"
			exit 0
		fi

		echo ""
		mirror_idx=$((mirror_idx + 1))
	done

	tries=$((tries + 1))
	if [ $tries -gt $MAX_TRIES ]; then
		break
	fi

	echo "All mirrors failed; sleeping 10 seconds..."
	echo ""
	sleep 10
done

rm -f "$tarball" "$tmpfile"

echo "ERROR: Unable to download $tarball"
echo ""
exit 1
