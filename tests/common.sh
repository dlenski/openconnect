#!/bin/sh
#
# Copyright 2013-2016 Nikos Mavrogiannopoulos
#
# This file is part of openconnect.
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

#this test can only be run as root

if ! test -x /usr/sbin/ocserv;then
	echo "You need ocserv to run this test"
	exit 77
fi

OCSERV=/usr/sbin/ocserv

SOCKDIR="./sockwrap.$$.tmp"
mkdir -p $SOCKDIR
export SOCKET_WRAPPER_DIR=$SOCKDIR
export SOCKET_WRAPPER_DEFAULT_IFACE=2
ADDRESS=127.0.0.$SOCKET_WRAPPER_DEFAULT_IFACE
OPENCONNECT="${top_builddir}/openconnect"

certdir="${srcdir}/certs"
confdir="${srcdir}/configs"

launch_simple_sr_server() {
       LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $OCSERV $* &
}

wait_server() {
	trap "kill $1" 1 15 2
	sleep 5
}

cleanup() {
	ret=0
	kill $PID
	if test $? != 0;then
		ret=1
	fi
	wait
	test -n "$SOCKDIR" && rm -rf $SOCKDIR
	return $ret
}

fail() {
	PID=$1
	shift;
	echo "Failure: $1" >&2
	kill $PID
	test -n "$SOCKDIR" && rm -rf $SOCKDIR
	exit 1
}

trap "fail \"Failed to launch the server, aborting test... \"" 10 
