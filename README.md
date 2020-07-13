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
        * [HIP report submission](#hip-report-submission)
      * [TODO](#todo)

# What is this?

This is a modified version of the fantastic open-source VPN client
[OpenConnect](https://www.infradead.org/openconnect) which supports the
PAN GlobalProtect VPN in its native modes (SSL and
[ESP](http://wikipedia.org/wiki/Encapsulating_Security_Payload))—with
no assistance or cooperation needed from your VPN administrators.

I began developing it [in October 2016](http://lists.infradead.org/pipermail/openconnect-devel/2016-October/004035.html),
and started using it for "real work" almost immediately. It has become
increasingly polished since then.

## Feedback and troubleshooting

GlobalProtect support is *not yet part of any official OpenConnect release*
(but see discussions on [official mailing list](https://lists.infradead.org/mailman/listinfo/openconnect-devel)).
Keep this in mind when discussing GlobalProtect issues on the mailing list.

Please report any problems as Github issues. If you are having trouble
authenticating to your GlobalProtect server, please run OpenConnect
with the `--dump -vvv` flags to dump the authentication flow; please
compare the back-and-forth configuration requests to [this anonymized
transcript](PAN_GlobalProtect_protocol_doc.md)
and include information about relevant differences in your issue
report.

**Bonus points:** If your VPN uses a weird authentication flow, please
check out the Gist where I wrote a [quick-and-dirty "GlobalProtect server
simulator"](https://gist.github.com/dlenski/08359391270337f7894b1e2a97d0d9a9) in
Python. It's fairly straightforward to understand, and if you can
modify it to reproduce the authentication flow used by your VPN, it'll
make it a whole lot easier to add support.

## Installation

Please refer to the [build requirements for the official releases of OpenConnect](https://www.infradead.org/openconnect/building.html). **This version has the exact same build dependencies as OpenConnect v7.06**; modern versions of `autoconf`, `automake`, `gcc`, `libxml`, etc.

### Building from source on Linux

Under Debian-based or Ubuntu-based distributions, this should install the requirements:

```sh
$ sudo apt-get install build-essential gettext autoconf automake libproxy-dev libxml2-dev libtool vpnc-scripts pkg-config \
                       libgnutils-dev # may be named libgnutils28-dev on some recent Debian/Ubuntu-based distros

```

Once you have all the build dependencies installed, checkout and build the `globalprotect` branch from this repository.

```sh
$ git clone https://github.com/dlenski/openconnect.git
$ cd openconnect
$ git checkout globalprotect
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install && sudo ldconfig
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
provider.

```sh
$ ./openconnect --protocol=gp server.company.com --dump -vvv
Please enter your username and password.
Username:
Password:
```

It currently supports the following authentication mechanisms:

* username and password
* "challenge"-based multi-factor authentication, wherein the server requests a secondary username and password after the first one
* TLS/SSL client certificate (include `--certificate cert_with_privkey.pem` if your VPN requires a _client_ certificate and private key)

I'd welcome feedback on how to support other authentication methods in use with GlobalProtect.

### Docker

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

### HIP report submission

The HIP ("Host Integrity Protection") mechanism is a security scanner
for PAN GlobalProtect VPNs, in the same vein as Cisco's CSD and
Juniper's Host Checker.

The server requests a "HIP report" upon client connection, then the
client generates a "HIP report" XML file, and then the client uploads
it to the server.

If all goes well, the client should have the expected level of access
to resources on the network after these steps are complete. At least
two things can go wrong:

* Many GlobalProtect servers report that they require HIP reports, but
  don't actually enforce this requirement. (For this reason,
  OpenConnect _does not currently fail_ if a HIP report is required
  but no HIP report script is provided.)
* Many GlobalProtect servers will claim that the HIP report was
  accepted successfully but silently fail to enable the expected
  network access, presumably because some aspect of the HIP report
  contents were not approved.

OpenConnect supports HIP report generation and submission by passing
the `--csd-wrapper=SCRIPT` argument with a shell script to generate a
HIP report in the format expected by the server. This shell script
must output the HIP report to standard output and exit successfully
(status code 0).

An example [`hipreport.sh`](hipreport.sh) script is included in the
repository.  Depending on how picky your GlobalProtect VPN is, it may
be necessary to spoof or alter some of the parameters of the HIP
report to match your GlobalProtect VPN's expectations as to its
contents.

### Portal vs. gateway servers

For some GlobalProtect VPNs, there is a distinction between "portal"
and "gateway" servers, although in many GlobalProtect VPNs they run on
the _same_ server. "Portal" application URLs are found under `/global-protect`,
while "gateway" application URLs are under `/ssl-vpn`.

Try using both the "Portal address" and the "GlobalProtect Gateway IP" shown in the Windows client with OpenConnect:

[![GlobalProtect Windows client](https://i.stack.imgur.com/2JC9T.png)]

The official GlobalProtect VPN clients _always_ connect first via the
portal. The portal then sends a choice of one or more
gateways. However, this behavior is unnecessary, and adds an
additional delay in establishing a connection.

Recent versions of `openconnect` can connect via _either_ the portal
endpoint _or_ the gateway endpoint:

* If unspecified, the gateway endpoint is tried first, then the portal endpoint.
* For the gateway, include a URL-path starting with `/ssl-vpn` or specify `--usergroup=gateway`
* For the portal, include a URL-path starting with `/global-protect` or specify `--usergroup=portal`
  * To choose a specific gateway from the portal without further prompting, add `--authgroup $GATEWAYNAME`

Example of connecting via the portal interface and getting a choice of gateway servers:

```sh
$ openconnect --protocol=gp --usergroup=portal server.company.com
Please enter your username and password.
Username:
Password:
..
Connected to HTTPS on server.company.com
3 gateway servers available:
  NorthAmerica (vpn-na.company.com)
  Europe (vpn-eu.company.com)
  Asia (vpn-asia.company.com)
Please select GlobalProtect gateway.
GATEWAY: [NorthAmerica|Europe|Asia]:
...
```

# TODO

* Support web-based/SAML-based authentication flows (see [pull #98](//github.com/dlenski/openconnect/issues/98) for preliminary work)
* Configure multi-stage build into the Dockerfile, to get a smaller Docker image
