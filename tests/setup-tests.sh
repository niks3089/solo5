#!/bin/sh
# Copyright (c) 2015-2018 Contributors as noted in the AUTHORS file
#
# This file is part of Solo5, a sandboxed execution environment.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#
# Set up test environment.
#
# Convention is: tap interface named 'tap100', host address of 10.0.0.1/24.
#

if [ $(id -u) -ne 0 ]; then
    echo "$0: must be root" 1>&2
    exit 1
fi

if [ "$#" -eq 0 ]; then
    print "$#"
    echo "Need to pass the number of NICs"
	exit 1
fi

if [ $1 -ge 10 ]; then
	echo "Number of nics cannot be greater than 10"
	exit 1
fi

if [ $# -eq 2 -a "$2" != "del" ]; then
    echo "Second argument needs to be del"
    exit 1
fi

case `uname -s` in
Linux)
    #set -xe
    if [ "$#" -eq 2 ]; then
        for var in $(seq 1 $1)
        do
            intf=$(expr "$var" - 1)
            ip tuntap del tap10$intf mode tap
        done
        exit 1
    fi
    for var in $(seq 1 $1)
    do
        intf=$(expr "$var" - 1)
		echo creating tap10$intf
        ip tuntap add tap10$intf mode tap
        ip addr add 10.0.$intf.1/24 dev tap10$intf
        ip link set dev tap10$intf up
    done
    ;;
FreeBSD)
    kldload vmm
    kldload if_tap
    kldload nmdm
    sysctl -w net.link.tap.up_on_open=1
    ifconfig tap100 create 10.0.0.1/24 link0 up
    ;;
OpenBSD)
    (
         cd /dev
         ./MAKEDEV tap100
    )
    ifconfig tap100 inet 10.0.0.1 netmask 255.255.255.0
    ;;
*)
    exit 1
    ;;
esac
