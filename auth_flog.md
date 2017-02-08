This is an anonymized log of the authentication and connection process between a GlobalProtect VPN client and server.

The correct user-agent (`User-Agent: PAN Globalprotect`) is **required** for all HTTP interactions with the GlobalProtect VPN. It treats any other user-agent as a web browser, not a VPN client.

Request #1
==========

Some of the form fields are required (user and password
obviously, ok=Login inexplicably) while others can apparently be
omitted.

```
POST https://gateway.company.com/ssl-vpn/login.esp

Connection:      Keep-Alive
Content-Type:    application/x-www-form-urlencoded
User-Agent:      PAN GlobalProtect
Host:            gateway.company.com

URLEncoded form:

prot:                           https:
server:                         gateway.company.com
inputStr:                       
jnlpReady:                      jnlpReady
user:                           Myusername
passwd:                         DEADBEEF
computer:                       DEADBEEF01
ok:                             Login
direct:                         yes
clientVer:                      4100
os-version:                     Microsoft Windows Server 2012, 64-bit
preferred-ip:                   12.34.56.78
clientos:                       Windows
clientgpversion:                3.0.1-10
portal-userauthcookie:          empty
portal-prelogonuserauthcookie:  empty
host-id:                        deadbeef-dead-beef-dead-beefdeadbeef
```

Response #1
===========

Nothing in this response seems interesting or useful, except for the delicious 32-digit cookie. The second hexadecimal blob is a persistent identifier associated with the combination of user account and gateway (probably the `sha1` hash of something, since it's 40 digits long).

```xml
<?xml version='1.0' encoding='utf-8'?>
<jnlp>
  <application-desc>
    <argument>(null)</argument>
    <argument>delicious 32 digits hex cookie</argument>
    <argument>another 40 mysterious hexadecimal digits</argument>
    <argument>Gateway-Name</argument>
    <argument>username provided above</argument>
    <argument>LDAP-auth</argument>
    <argument>vsys1</argument>
    <argument>company domain name</argument>
    <argument>(null)</argument>
    <argument/>
    <argument/>
    <argument/>
    <argument>tunnel</argument>
    <argument>-1</argument>
    <argument>4100</argument>
    <argument>preferred ip address as provided above</argument>
  </application-desc>
</jnlp>
```

Request #2
==========

Similar to above, some of the parameters are
required, others are not. `addr1` seems to be the current IPv4 subnet
of the client machine, and is apparently optional.

```
POST https://gateway.company.com/ssl-vpn/getconfig.esp

Connection:      Keep-Alive
Content-Type:    application/x-www-form-urlencoded
User-Agent:      PAN GlobalProtect
Host:            gateway.company.com

URLEncoded form

user:              Myusername
addr1:             4.5.6.78/24 (current IPv4 network, I think?)
preferred-ip:      12.34.56.78
portal:            Gateway-Name
authcookie:        cookie (32 hex digits from above))
client-type:       1
os-version:        Microsoft Windows Server 2012, 64-bit
app-version:       3.0.1-10
protocol-version:  p1
clientos:          Windows
enc-algo:          aes-256-gcm,aes-128-gcm,aes-128-cbc,
hmac-algo:         sha1,
```

Response #2
===========

Here's the interesting part:
* Routing information seems almost identical to what Cisco AnyConnect provides, except in XML form
* IPsec configuration specifies the exist SPI indexes to use, as well
  as the client-to-server (c2s) and server-to-client (s2c) encryption
  keys and authentication keys. Note that the upstream and downstream
  keys and SPIs do **not** match; this is intentional.

```xml
<?xml version='1.0' encoding='UTF-8'?>
<response status="success">
  <need-tunnel>yes</need-tunnel>
  <ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>
  <portal>Gateway-Name</portal>
  <user>Myusername</user>
  <lifetime>86400</lifetime>
  <timeout>3600</timeout>
  <disconnect-on-idle>3600</disconnect-on-idle>
  <bw-c2s>1000</bw-c2s>
  <bw-s2c>1000</bw-s2c>
  <gw-address>IP address of gateway.company.com in my case</gw-address>
  <ip-address>the preferred IP address from above</ip-address>
  <netmask>255.255.255.255</netmask>
  <dns>
    <member>8.8.8.8</member>
    <member>4.4.4.4</member>
  </dns>
  <wins>
    <member>8.8.8.9</member>
    <member>4.4.4.5</member>
  </wins>
  <default-gateway>gateway for default internal route</default-gateway>
  <mtu>0</mtu>
  <dns-suffix>
    <member>company.com</member>
    <member>company.internal</member>
    <member>stuff.company.com</member>
  </dns-suffix>
  <no-direct-access-to-local-network>no</no-direct-access-to-local-network>
  <access-routes>
    <member>10.0.0.0/8</member>
    <member>192.168.0.0/16</member>
  </access-routes>
  <ipsec>
    <udp-port>4501</udp-port>
    <ipsec-mode>esp-tunnel</ipsec-mode>
    <enc-algo>aes-128-cbc</enc-algo>
    <hmac-algo>sha1</hmac-algo>
    <c2s-spi>0xDEADBEEF</c2s-spi>
    <s2c-spi>0xFEEDBACC</s2c-spi>
    <akey-s2c>
      <bits>160</bits>
      <val>deadbeefdeadbeefdeadbeefdeadbeefdeadbeef</val>
    </akey-s2c>
    <ekey-s2c>
      <bits>128</bits>
      <val>feedbaccfeedbaccfeedbaccfeedbacc</val>
    </ekey-s2c>
    <akey-c2s>
      <bits>160</bits>
      <val>deadbeefdeadbeefdeadbeefdeadbeefdeadbeef</val>
    </akey-c2s>
    <ekey-c2s>
      <bits>128</bits>
      <val>feedbaccfeedbaccfeedbaccfeedbacc</val>
    </ekey-c2s>
  </ipsec>
</response>
```

Tunnel
======

In the back-and-forth flows shown below, `<` means sent by the gateway, `>` means sent by the client.
 
### ESP-over-UDP

Uses the keying information obtained in response to the `getconfig` request. In order to initiate the connection, the client sends 3 ESP-encapsulated ping packets to the gateway. They are sent _from_ the client's in-VPN IP address _to_ the gateway's public IP address, and they include the following magic payload:

    "monitor\x00\x00pan ha 0123456789:;<=>? !\"#$%&\'()*+,-./\x10\x11\x12\x13\x14\x15\x16\x18"

Only the first 16 bytes of the payload appear to be necessary to elicit a response from the gateway. Once the gateway has responded, the client and server send and receive arbitrary ESP-encapsulated traffic. The client continues to periodically send the "magic ping" packets as a keepalive.

### SSL vpn tunnel

The tunnel starts when the client issues a `CONNECT`-disguised-as-`GET` command, to the tunnel URL path specified in the `getconfig` response. The gateway responds with the ASCII string `START_TUNNEL` **instead of** a standard HTTP response code:

    > 'GET /ssl-tunnel-connect.sslvpn?user=Myusername&authcookie=deadbeef HTTP/1.1\r\n\r\n'
    < 'START_TUNNEL'

Now the client and gateway proceed to communicate by sending encapsulated IPv4 packets back and forth. Here is an example snippet of the IP-over-TLS stream format, as initiated by the client's `GET` command:

    > 'GET /ssl-tunnel-connect.sslvpn?user=Myusername&authcookie=deadbeef HTTP/1.1\r\n\r\n' 
    < 'START_TUNNEL'
    < 1a2b3c4d0800005401000000000000004500005461e400007e11f5520a100f030a12c23d[...]
    > 1a2b3c4d08000034010000000000000045000034038f0000011108df0a12c23de00000fc[...]
    ...

Here is the packet format:

  1. 4 magic bytes: `1a2b3c4d`
  2. Next 2 bytes are probably the Ethertype (as uint16_be): `0800` is IPv4
  3. Next 2 bytes are the packet length (as uint16_be) excluding this header
  4. Next 8 bytes always seem to be `0100000000000000` in my testing (1 as an uint64_le?)
  5. Remaining bytes are the actual Layer 3 packet (IPv4 packets starting with `45` in the examples above)

Logout request
==============

```
POST https://gateway.company.com/ssl-vpn/logout.esp

Accept:          */*
Content-Type:    application/x-www-form-urlencoded
Host:            gateway.company.com

URLEncoded form:

user:        Myusername
portal:      Gateway-Name
authcookie:  as above
domain:      company domain name
computer:    DEADBEEF01
os-version:  Microsoft Windows Server 2012, 64-bit
```

Logout response
===============

```xml
<?xml version='1.0' encoding='UTF-8'?>
<response status="success">
  <portal>Gateway-Name</portal>
  <domain>company domain name</domain>
  <user>Myusername</user>
  <computer>DEADBEEF01</computer>
</response>
```