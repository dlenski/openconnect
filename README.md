# OpenConnect with PAN GlobalProtect support

[![Build Status](https://api.travis-ci.org/dlenski/openconnect.png)](https://travis-ci.org/dlenski/openconnect)

# Table of Contents

   * [What is this?](#what-is-this)
      * [Feedback and troubleshooting](#feedback-and-troubleshooting)
      * [Installation](#installation)
         * [Building from source on Linux](#building-from-source-on-linux)
         * [Building on the Mac](#building-on-the-mac)
      * [Connecting](#connecting)
      * [Docker](#docker)
      * [Portal vs. gateway servers](#portal-vs-gateway-servers)

# What is this?

This is a modified version of the fantastic open-source VPN client
[OpenConnect](https://www.infradead.org/openconnect) which supports the
PAN GlobalProtect VPN in its native modes (SSL and
[ESP](http://wikipedia.org/wiki/Encapsulating_Security_Payload))—with
no assistance or cooperation needed from your VPN administrators.

## Feedback and troubleshooting

This is a [work in progress](http://lists.infradead.org/pipermail/openconnect-devel/2016-October/004035.html).

That said, I've been using it for real work for many weeks, and it works very well for me.

Having other people test it would be awesome and I welcome your
feedback! Please report any problems here on Github rather than
bothering the OpenConnect mailing list, since this is *not part of any
official OpenConnect release*.

If you are having trouble
authenticating to your GlobalProtect server, please run OpenConnect
with the `--dump -vvv` flags to dump the authentication flow; please
compare the back-and-forth configuration requests to [this anonymized
transcript](PAN_GlobalProtect_protocol_doc.md)
and include information about relevant differences in your issue
report.

## Installation

Please refer to the [build requirements for the official releases of OpenConnect](https://www.infradead.org/openconnect/building.html). **This version has the exact same build dependencies as OpenConnect v7.06**; modern versions of `autoconf`, `automake`, `gcc`, `libxml`, etc.

### Building from source on Linux

Under Debian-based or Ubuntu-based distributions, this should install the requirements:

```sh
$ sudo apt-get install build-essential gettext autoconf automake libproxy-dev libxml2-dev libtool vpnc-scripts pkg-config \
                       libgnutls-dev # may be named libgnutls28-dev on some recent Debian/Ubuntu-based distros

```

Once you have all the build dependencies installed, checkout and build the `globalprotect` branch from this repository.

```sh
$ git clone https://github.com/dlenski/openconnect.git
$ cd openconnect
$ git checkout globalprotect
$ ./autogen.sh
$ ./configure
$ make
$ make install
```

### Building on the Mac

[Homebrew](https://brew.sh) is required. To build and install into `/usr/local`:

```sh
$ brew install pkg-config gettext gnutls lz4 automake
$ export LIBTOOLIZE=glibtoolize
$ ./autogen.sh
$ ./configure --prefix=/usr/local --with-vpnc-script=/usr/local/etc/vpnc-script --disable-nls
$ make
$ make install
```

Please see [this Gist](https://gist.github.com/moklett/3170636) on how to set up and use OpenConnect on the Mac. Don't forget to install `vpnc-script` into `/usr/local/etc`.

## Connecting

Run openconnect like this to test it with your GlobalProtect VPN
provider. (Include `--certificate cert_with_privkey.pem` if your VPN
requires a client certificate and/or private key.)

```sh
$ ./openconnect --protocol=gp server.company.com --dump -vvv
Please enter your username and password.
Username:
Password:
```

Currently it only supports username, password, and optionally client
certificate authentication… since that's the only example I have. But
I'd welcome feedback if there are other authentication methods in use
out there.

## Docker

Building an openconnect Docker image is as easy as:

```sh
$ docker build -t openconnect .
```

Then, you can run that docker image as a container:

```sh
$ docker run -ti openconnect
/openconnect# ./openconnect --protocol=gp server.company.com 
```

But that'll restrict the use of the tunnel to *inside* the container,
and maybe you want to use it system-wide. For that, you'll need a
privileged container making use of the host (you computer) network:

```sh
$ docker run -ti --rm --privileged --net=host openconnect
/openconnect# ./openconnect --protocol=gp server.company.com
```
Leave that container running, open another terminal, and you'll see a
newly created tun connection for your whole system to use.

## Portal vs. gateway servers

For my VPN, the VPN tunnel server is the *same* as the VPN "portal"
server, but your VPN may differ. Try using both the "Portal address"
and the "GlobalProtect Gateway IP" shown in the Windows client with
OpenConnect:

[![GlobalProtect Windows client](https://i.stack.imgur.com/2JC9T.png)]

You can also use [`get-globalprotect-config.py`](get-globalprotect-config.py) to list the available gateway servers:

```sh
$ ./get-globalprotect-config.py [--cert client_cert_with_privkey.pem] portal.company.com
        ...
        <gateways>
                <cutoff-time>5</cutoff-time>
                <external>
                        <list>
                                <entry name="gateway.company.com">
                                        <priority>1</priority>
                                        <manual>yes</manual>
                                        <description>WowSuchGateway</description>
                                </entry>
                        </list>
                </external>
        </gateways>
        ...
```
