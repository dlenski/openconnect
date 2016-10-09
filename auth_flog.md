Request #1
==========

The correct user-agent is required to produce the desired
response. Some of the form fields are required (user and password
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

Nothing in this response seems interesting or useful, except for the delicious 32-digit cookie:

```
Headers:
Connection:       keep-alive
Server:           PanWeb Server/ -
<various cache-related headers like ETag>

XML-like data:

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

```
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

Finally...
==========

* IPsec-over-UDP using the keys shown above (I have yet tested this "manually" but I feel fairly confident in this interpretation).
* and/or IP-over-TLS via a `CONNECT`-disguised-as-`GET` to the tunnel URL from the configuration above

Here is the IP-over-TLS stream format, initiated by the client's `GET /ssl-tunnel-connect.sslvpn` command (`<` means sent by the gateway, `>` means sent by the client):

    < 'GET /ssl-tunnel-connect.sslvpn?user=Myusername&authcookie=deadbeef HTTP/1.1\r\n\r\n' 
    > 'START_TUNNEL'
    < 1a2b3c4d0800005401000000000000004500005461e400007e11f5520a100f030a12c23d[...]
    > 1a2b3c4d08000034010000000000000045000034038f0000011108df0a12c23de00000fc[...]
    ...

In other words:

1. The gateway sends the 12 ASCII bytes `START_TUNNEL` to indicate the tunnel is up
2. Packets in both directions follow. They are formatted as:
  1. 4 magic bytes: `1a2b3c4d`
  2. Next 2 bytes are probably the Ethertype: `0800` (= IPv4)
  3. Next 2 bytes are the packet size (as int16_be)
  4. Next 8 bytes always seem to be `0100000000000000` in my testing (1 as an int64_le?)
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

```
Server:           PanWeb Server/ -
<various cache headers>

<?xml version='1.0' encoding='UTF-8'?>
<response status="success">
  <portal>Gateway-Name</portal>
  <domain>company domain name</domain>
  <user>Myusername</user>
  <computer>DEADBEEF01</computer>
</response>
```