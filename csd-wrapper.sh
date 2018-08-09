#!/bin/bash
# Cisco Anyconnect CSD wrapper for OpenConnect
#
# [05 May 2015] Written by Nikolay Panin <nick_panin@mail.ru>:
#   - source: https://gist.github.com/l0ki000/56845c00fd2a0e76d688
# [27 Oct 2017] Updated by Daniel Lenski <dlenski@gmail.com>:
#   - use -url argument
#   - kill cstub after timeout
#   - fix small typos:
# [31 May 2018] Updated by Daniel Lenski <dlenski@gmail.com>:
#   - use curl with --pinnedpubkey to rely on sha256 hash of peer cert passed by openconnect

TIMEOUT=30
URL="https://${CSD_HOSTNAME}/CACHE"
HOSTSCAN_DIR="$HOME/.cisco/hostscan"
LIB_DIR="$HOSTSCAN_DIR/lib"
BIN_DIR="$HOSTSCAN_DIR/bin"
PINNEDPUBKEY="-s ${CSD_SHA256:+"-k --pinnedpubkey sha256//$CSD_SHA256"}"

BINS=("cscan" "cstub" "cnotify")

# parsing command line
shift

URL=
TICKET=
STUB=
GROUP=
CERTHASH=
LANGSELEN=

while [ "$1" ]; do
    if [ "$1" == "-ticket" ];   then shift; TICKET=$1; fi
    if [ "$1" == "-stub" ];     then shift; STUB=$1; fi
    if [ "$1" == "-group" ];    then shift; GROUP=$1; fi
    if [ "$1" == "-certhash" ]; then shift; CERTHASH=$1; fi
    if [ "$1" == "-url" ];      then shift; URL=$(echo $1|tr -d '"'); fi # strip quotes
    if [ "$1" == "-langselen" ];then shift; LANGSELEN=$1; fi
    shift
done

ARCH=$(uname -m)

if [[ "$ARCH" == "x86_64" ]]
then
    ARCH="linux_x64"
else
    ARCH="linux_i386"
fi

# creating dirs
for dir in $HOSTSCAN_DIR $LIB_DIR $BIN_DIR ; do
    if [[ ! -f $dir ]]
    then
        mkdir -p $dir
    fi
done

# getting manifest, and checking binaries
curl $PINNEDPUBKEY "${URL}/sdesktop/hostscan/$ARCH/manifest" -o "$HOSTSCAN_DIR/manifest"

# generating md5.sum with full paths from manifest
export HOSTSCAN_DIR=$HOSTSCAN_DIR
while read HASHTYPE FILE EQU HASHVAL; do
    FILE="${FILE%*)}"
    FILE="${FILE#(}"
    if grep --extended-regexp --quiet --invert-match ".so|tables.dat" <<< "$FILE"; then
	PATHNAME="${BIN_DIR}/$FILE"
	IS_BIN=yes
    else
	PATHNAME="${LIB_DIR}/$FILE"
	IS_BIN=no
    fi
    DOWNLOAD=yes
    case $HASHTYPE in
	MD5)
	    if [ -r "$PATHNAME" ] && md5sum --status -c <<< "$HASHVAL $PATHNAME"; then
		DOWNLOAD=no
	    fi
	    ;;
	SHA1)
	    if [ -r "$PATHNAME" ] && sha1sum --status -c <<< "$HASHVAL $PATHNAME"; then
		DOWNLOAD=no
	    fi
	    ;;
	SHA256)
	    if [ -r "$PATHNAME" ] && sha256sum --status -c <<< "$HASHVAL $PATHNAME"; then
		DOWNLOAD=no
	    fi
	    ;;
	*)
	    echo "Unsupported hash type $HASHTYPE"
	    ;;
    esac
    if [ "$DOWNLOAD" = "yes" ]; then
	echo "Downloading: $FILE"
	TMPFILE="${PATHNAME}.tmp"

        curl $PINNEDPUBKEY "${URL}/sdesktop/hostscan/$ARCH/$FILE" -o "${TMPFILE}"

        # some files are in gz (don't understand logic here)
        if [[ ! -f "${TMPFILE}" || ! -s "${TMPFILE}" ]]
        then
            # remove 0 size files
            if [[ ! -s ${TMPFILE} ]]; then
                rm ${TMPFILE}
            fi

            echo "Failure on $FILE, trying gz"
            FILE_GZ="${TMPFILE}.gz"
            curl $PINNEDPUBKEY "${URL}/sdesktop/hostscan/$ARCH/$FILE_GZ" -o "${FILE_GZ}" &&
		gunzip --verbose --decompress "${FILE_GZ}"
        fi

	if [ -r "${TMPFILE}" ]; then
	    if [ "$IS_BIN" = "yes" ]; then
		chmod +x "${TMPFILE}"
	    fi
	    mv "${TMPFILE}" "${PATHNAME}"
	fi
    fi
done < $HOSTSCAN_DIR/manifest

# cstub doesn't care about logging options, sic!
#ARGS="-log debug -ticket $TICKET -stub $STUB -group $GROUP -host "$URL" -certhash $CERTHASH"
ARGS="-log error -ticket $TICKET -stub $STUB -group $GROUP -host \"$URL\" -certhash $CERTHASH"

echo "Launching: $BIN_DIR/cstub $ARGS"
$BIN_DIR/cstub $ARGS & CSTUB_PID=$!

sleep $TIMEOUT
if kill -0 $CSTUB_PID 2> /dev/null; then
    echo "Killing cstub process after $TIMEOUT seconds"
    kill $CSTUB_PID 2> /dev/null || kill -9 $CSTUB_PID 2> /dev/null
fi
