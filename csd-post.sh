#!/bin/bash
# Cisco Anyconnect CSD wrapper for OpenConnect
#
# Instead of actually downloading and spawning the hostscan trojan,
# this script posts results directly. Ideally we would work out how to
# interpret the DES-encrypted (yay Cisco!) tables.dat and basically
# reimplement the necessary parts hostscan itself. But prepackaged
# answers, tuned to match what the VPN server currently wants to see,
# will work for most people. Of course it's perfectly possible to make
# this tell the truth and not just give prepackaged answers, and most
# people should do that rather than deliberately circumventing their
# server's security policy with lies. This script exists as an example
# to work from.

if ! xmlstarlet --version > /dev/null; then
    echo "No xmlstarlet found"
    exit 1;
fi

DATA='endpoint.os.version="Linux";
endpoint.os.servicepack="4.17.9-200.fc28.x86_64";
endpoint.os.architecture="x64";
endpoint.policy.location="Default";
endpoint.device.protection="none";
endpoint.device.protection_version="3.1.03103";
endpoint.device.hostname="vpnclient.example.com";
endpoint.device.port["9217"]="true";
endpoint.device.port["139"]="true";
endpoint.device.port["53"]="true";
endpoint.device.port["22"]="true";
endpoint.device.port["631"]="true";
endpoint.device.port["445"]="true";
endpoint.device.port["9216"]="true";
endpoint.device.tcp4port["9217"]="true";
endpoint.device.tcp4port["139"]="true";
endpoint.device.tcp4port["53"]="true";
endpoint.device.tcp4port["22"]="true";
endpoint.device.tcp4port["631"]="true";
endpoint.device.tcp4port["445"]="true";
endpoint.device.tcp4port["9216"]="true";
endpoint.device.tcp6port["139"]="true";
endpoint.device.tcp6port["53"]="true";
endpoint.device.tcp6port["22"]="true";
endpoint.device.tcp6port["631"]="true";
endpoint.device.tcp6port["445"]="true";
endpoint.device.MAC["FFFF.FFFF.FFFF"]="true";
endpoint.device.protection_extension="3.6.4900.2";
endpoint.fw["IPTablesFW"]={};
endpoint.fw["IPTablesFW"].exists="true";
endpoint.fw["IPTablesFW"].description="IPTables (Linux)";
endpoint.fw["IPTablesFW"].version="1.6.1";
endpoint.fw["IPTablesFW"].enabled="ok";
'
shift

TICKET=
STUB=0

while [ "$1" ]; do
    if [ "$1" == "-ticket" ];   then shift; TICKET=${1//\"/}; fi
    if [ "$1" == "-stub" ];     then shift; STUB=${1//\"/}; fi
    shift
done

PINNEDPUBKEY="-s ${CSD_SHA256:+"-k --pinnedpubkey sha256//$CSD_SHA256"}"
URL="https://$CSD_HOSTNAME/+CSCOE+/sdesktop/token.xml?ticket=$TICKET&stub=$STUB"
COOKIE_HEADER="Cookie: sdesktop="$(curl $PINNEDPUBKEY -s "$URL"  | xmlstarlet sel -t -v /hostscan/token)
CONTENT_HEADER="Content-Type: text/xml"
URL="https://$CSD_HOSTNAME/+CSCOE+/sdesktop/scan.xml?reusebrowser=1"
curl $PINNEDPUBKEY -H "$CONTENT_HEADER" -H "$COOKIE_HEADER" --data "$DATA;type=text/xml" "$URL"
