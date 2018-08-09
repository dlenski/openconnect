#!/bin/sh

# openconnect will call this script with the follow command-line
# arguments, which are needed to populate the contents of the
# HIP report:
#
#   --cookie: a URL-encoded string, as output by openconnect
#             --authenticate --protocol=gp, which includes parameters
#             from the /ssl-vpn/login.esp response
#
#   --client-ip: IPv4 address allocated by the GlobalProtect VPN for
#                this client (included in /ssl-vpn/getconfig.esp
#                response)
#
#   --md5: The md5 digest to encode into this HIP report. I'm not sure
#          exactly what this is the md5 digest *of*, but all that
#          really matters is that the value in the HIP report
#          submission should match the value in the HIP report check.

# Read command line arguments into variables
COOKIE=
IP=
MD5=

while [ "$1" ]; do
    if [ "$1" = "--cookie" ];    then shift; COOKIE="$1"; fi
    if [ "$1" = "--client-ip" ]; then shift; IP="$1"; fi
    if [ "$1" = "--md5" ];       then shift; MD5="$1"; fi
    shift
done

if [ -z "$COOKIE" -o -z "$IP" -o -z "$MD5" ]; then
    echo "Parameters --cookie, --computer, --client-ip, and --md5 are required" >&2
    exit 1;
fi

# Extract username and domain and computer from cookie
USER=$(echo "$COOKIE" | sed -rn 's/(.+&|^)user=([^&]+)(&.+|$)/\2/p')
DOMAIN=$(echo "$COOKIE" | sed -rn 's/(.+&|^)domain=([^&]+)(&.+|$)/\2/p')
COMPUTER=$(echo "$COOKIE" | sed -rn 's/(.+&|^)computer=([^&]+)(&.+|$)/\2/p')

# Timestamp in the format expected by GlobalProtect server
NOW=$(date +'%m/%d/%Y %H:%M:%S')

# This value may need to be extracted from the official HIP report, if a made-up value is not accepted.
HOSTID="deadbeef-dead-beef-dead-beefdeadbeef"

cat <<EOF
<hip-report name="hip-report">
	<md5-sum>$MD5</md5-sum>
	<user-name>$USER</user-name>
	<domain>$DOMAIN</domain>
	<host-name>$COMPUTER</host-name>
	<host-id>$HOSTID</host-id>
	<ip-address>$IP</ip-address>
	<ipv6-address></ipv6-address>
	<generate-time>$NOW</generate-time>
	<categories>
		<entry name="host-info">
			<client-version>4.0.2-19</client-version>
			<os>Microsoft Windows 10 Pro , 64-bit</os>
			<os-vendor>Microsoft</os-vendor>
			<domain>$DOMAIN.internal</domain>
			<host-name>$COMPUTER</host-name>
			<host-id>$HOSTID</host-id>
			<network-interface>
				<entry name="{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}">
					<description>PANGP Virtual Ethernet Adapter #2</description>
					<mac-address>01-02-03-00-00-01</mac-address>
					<ip-address>
						<entry name="$IP"/>
					</ip-address>
					<ipv6-address>
						<entry name="dead::beef:dead:beef:dead"/>
					</ipv6-address>
				</entry>
			</network-interface>
		</entry>
		<entry name="antivirus">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="McAfee VirusScan Enterprise" version="8.8.0.1804" defver="8682.0" prodType="1" engver="5900.7806" osType="1" vendor="McAfee, Inc." dateday="12" dateyear="2017" datemon="10">
						</Prod>
						<real-time-protection>yes</real-time-protection>
						<last-full-scan-time>10/11/2017 15:23:41</last-full-scan-time>
					</ProductInfo>
				</entry>
				<entry>
					<ProductInfo>
						<Prod name="Windows Defender" version="4.11.15063.332" defver="1.245.683.0" prodType="1" engver="1.1.13804.0" osType="1" vendor="Microsoft Corp." dateday="8" dateyear="2017" datemon="6">
						</Prod>
						<real-time-protection>no</real-time-protection>
						<last-full-scan-time>n/a</last-full-scan-time>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="anti-spyware">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="McAfee VirusScan Enterprise" version="8.8.0.1804" defver="8682.0" prodType="2" engver="5900.7806" osType="1" vendor="McAfee, Inc." dateday="12" dateyear="2017" datemon="10">
						</Prod>
						<real-time-protection>yes</real-time-protection>
						<last-full-scan-time>10/11/2017 15:23:41</last-full-scan-time>
					</ProductInfo>
				</entry>
				<entry>
					<ProductInfo>
						<Prod name="Windows Defender" version="4.11.15063.332" defver="1.245.683.0" prodType="2" engver="1.1.13804.0" osType="1" vendor="Microsoft Corp." dateday="8" dateyear="2017" datemon="6">
						</Prod>
						<real-time-protection>no</real-time-protection>
						<last-full-scan-time>n/a</last-full-scan-time>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="disk-backup">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="Windows Backup and Restore" version="10.0.15063.0" vendor="Microsoft Corp.">
						</Prod>
						<last-backup-time>n/a</last-backup-time>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="disk-encryption">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="Windows Drive Encryption" version="10.0.15063.0" vendor="Microsoft Corp.">
						</Prod>
						<drives>
							<entry>
								<drive-name>C:</drive-name>
								<enc-state>full</enc-state>
							</entry>
						</drives>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="firewall">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="Microsoft Windows Firewall" version="10.0" vendor="Microsoft Corp.">
						</Prod>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="patch-management">
			<list>
				<entry>
					<ProductInfo>
						<Prod name="McAfee ePolicy Orchestrator Agent" version="5.0.5.658" vendor="McAfee, Inc.">
						</Prod>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
				<entry>
					<ProductInfo>
						<Prod name="Microsoft Windows Update Agent" version="10.0.15063.0" vendor="Microsoft Corp.">
						</Prod>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
			</list>
			<missing-patches/>
		</entry>
		<entry name="data-loss-prevention">
			<list/>
		</entry>
	</categories>
</hip-report>
EOF
