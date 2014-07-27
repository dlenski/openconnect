#!/bin/bash

unset SRCS
unset DST

while [ $# -gt 1 ]; do
    case "$1" in
	-d)
	    MAKEDIR=1
	    shift
	    ;;
	-c|-C|-s)
	    shift
	    ;;
	-m|-g|-o)
	    shift 2;
	    ;;
	*)
	    SRCS="$SRCS $(readlink -f "$1")"
	    shift
	    ;;
    esac
done
if [ ! -z $MAKEDIR ]; then
    mkdir -p $1
fi
cp -f $SRCS "$1"

