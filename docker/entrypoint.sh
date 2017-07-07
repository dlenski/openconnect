#!/bin/sh -el

if [ -z "$VPN_PASSWORD" ]; then
  exec openconnect --protocol=gp $VPN_SERVER -u $VPN_USER "$@"
else
  exec openconnect --protocol=gp $VPN_SERVER -u $VPN_USER --passwd-on-stdin "$@" <<END
$VPN_PASSWORD
END
fi
