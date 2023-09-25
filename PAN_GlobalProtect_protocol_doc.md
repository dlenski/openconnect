This is an anonymized log of the authentication, configuration, tunnel data transfer, and logout interactions between a
[PAN](http://www.paloaltonetworks.com) GlobalProtect VPN server and client. The logs below are based on the official Windows
client, v3.0.1-10, with some updates from v4.0.5-8.

   * [Updates](#updates)
   * [Common features across requests](#common-features-across-requests)
   * [Pre-login request](#pre-login-request)
   * [Pre-login response](#pre-login-response)
   * [Login request](#login-request)
   * [Successful login response](#successful-login-response)
   * [getconfig request](#getconfig-request)
   * [getconfig response](#getconfig-response)
      * [getconfig response failures](#getconfig-response-failures)
         * [Portal errors (/global-protect/getconfig.esp)](#portal-errors-global-protectgetconfigesp)
         * [Gateway errors (/ssl-vpn/getconfig.esp)](#gateway-errors-ssl-vpngetconfigesp)
   * [Data transfer over the tunnel](#data-transfer-over-the-tunnel)
      * [ESP-over-UDP](#esp-over-udp)
      * [SSL vpn tunnel](#ssl-vpn-tunnel)
      * [ESP and SSL tunnels are mutually exclusive](#esp-and-ssl-tunnels-are-mutually-exclusive)
   * [Logout request](#logout-request)
   * [Successful logout response](#successful-logout-response)

-------

Updates
=======

Client version 4.0 [adds IPv6 support](https://live.paloaltonetworks.com/t5/Colossal-Event-Blog/New-GlobalProtect-4-0-announced-with-IPv6-support/ba-p/141593) and SAML authentication support.

PanOS 8.0 [adds server-side IPv6 support and split-excludes](https://www.paloaltonetworks.com/documentation/80/pan-os/newfeaturesguide/globalprotect-features).

Common features across requests
===============================

Some older GlobalProtect servers may **require** the header `User-Agent: PAN GlobalProtect` to be set for all HTTP(S)
requests. These servers treat any other user-agent as a web browser, not a VPN client, and usually redirect to a client
software download page, or something similar.

Pre-login request
=================

This request is submitted as a `POST`, but has `GET`-style URL parameters:

```
POST https://gateway.company.com/ssl-vpn/?prelogin.esp?tmp=tmp&clientVer=4100&clientos=Windows

Connection:      Keep-Alive
Content-Type:    application/x-www-form-urlencoded
User-Agent:      PAN GlobalProtect
Host:            gateway.company.com
```

Very recent GlobalProtect clients send `cas-support=yes` in the `POST` body
(see [OpenConnect issue #651](https://gitlab.com/openconnect/openconnect/-/issues/651)), but
older clients send nothing in the body.

Pre-login response
==================

Useful things we learn from this response:

* Whether this server is running a "gateway" (`/ssl-vpn/*`) or only a "portal" (`/global-protect/*`) — 
  official clients begin their login process only via portal
* What labels to use in the login form
* Whether [SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) is being used, or
  whether we should do a "normal" login using username, password, and (perhaps) client certificate.

```xml
<?xml version='1.0' encoding='utf-8'?>
<prelogin-response>
  <status>Success</status>      <!-- or "Error", when this is a portal-only server -->
  <ccusername/>                 <!-- Subject name from just-submitted client cert, in some cases -->
  <autosubmit>false</autosubmit>
  <msg/>                        <!-- Only for errors, e.g. "GlobalProtect gateway does not exist" -->
  <newmsg/>
  <license>yes</license>        <!-- Not always present -->
  <license-v6>yes</license-v6>  <!-- Only recent versions -->
  <authentication-message>Enter login credentials</authentication-message>
  <username-label>Username</username-label>
  <password-label>Password</password-label>
  <panos-version>1</panos-version>
	
  <!-- These are only when SAML is used; known methods are REDIRECT and POST,
       and the request is a b64-encoded URL -->
  <saml-auth-status>0</saml-auth-status>
  <saml-auth-method>REDIRECT</saml-auth-method>
  <saml-request>aHR0cHM6Ly9zYW1sLm9rdGEuY29tL2xvZ2luL3Zwbg==</saml-request>

  <region>US</region>
</prelogin-response>
```

Login request
=============

Some of the form fields are required (user and password
obviously, `ok=Login` inexplicably) while others can apparently be
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

New parameters sent by Windows client v4.0.5-8:

```
clientgpversion:                4.0.5-8
prelogin-cookie:
ipv6-support:                   yes
client-ip:                      34.56.78.90
client-ipv6:                    .
preferred-ipv6:
```

The `client-ip{,v6}` parameters refer to the client's _external_ internet-facing IP address, while `preferred-ip{,v6}` parameters
refer to the expected/desired addresses within the VPN.

Successful login response
=========================

This response contains a delicious 32-digit cookie. The second hexadecimal blob is a persistent identifier associated with the combination of user account and gateway (probably the `sha1` hash of something, since it's 40 digits long).

In order to handle the getconfig, tunnel-connect, and logon requests properly (described below), the client needs to save some other parts of this response besides the cookie:

* username: the server may return a slightly modified version of the username provided upon login (e.g. `steve.JoNes` transformed into the canonical `steve.jones`)
* domain name and portal name: the correct values for these are—inexplicably—required to log out of the VPN session successfully ¯\\\_(ツ)\_/¯
* authentication type is something like `LDAP-auth` or `AUTH-RADIUS_RSA_OTP`, and appears to reflect the mechanism by which the user was authenticated
* preferred IP address is set by some VPN gateways _even if_ it was omitted from the login request; if it is not empty or `(null)`, its value should be used in the subsequent getconfig request
* `4100` appears to identify the VPN protocol version. I've never seen another value.

The value `(null)` can be treated identically to a missing value.

The domain name is sometimes observed to be URL-escaped (`(empty_domain)` represented literally as `%28empty_domain%29`); 
this value needs to be unescaped in order for the [Logout Request](#logout-request) to succeed. I've never seen another
value containing `%` or `+`, but it's probably safe to assume that all values should be URL-unescaped.

```xml
<?xml version='1.0' encoding='utf-8'?>
<jnlp>
  <application-desc>
    <argument>(null)</argument>
    <argument>delicious 32 digits hex cookie</argument>
    <argument>another 40 mysterious hexadecimal digits</argument>
    <argument>Gateway-Name</argument>
    <argument>username provided above</argument>
    <argument>authentication type</argument>
    <argument>vsys1</argument>
    <argument>company domain name</argument>
    <argument>(null)</argument>
    <argument/>
    <argument/>
    <argument/>
    <argument>tunnel</argument>
    <argument>-1</argument>
    <argument>4100</argument>
    <argument>preferred IP address as sent in request</argument>
  </application-desc>
</jnlp>
```

Windows client v4.0.5-8 receives additional input-parroting arguments at the end:

```xml
    <argument>portal-userauthcookie as sent in request</argument>
    <argument>prelogon-userauthcookie as sent in request</argument>
    <argument>preferred IPv6 address as sent in request</argument>
```


getconfig request
=================

Similar to above, some of the parameters are
required, others are not. `addr1` seems to be the current IPv4 subnet
of the client machine, and is apparently optional.

If a client has obtained a valid and unexpired authcookie, it's possible to re-run the getconfig request/response flow. This can be used to reconnect the tunnel after a network outage, without reauthenticating.

```
POST https://gateway.company.com/ssl-vpn/getconfig.esp

Connection:      Keep-Alive
Content-Type:    application/x-www-form-urlencoded
User-Agent:      PAN GlobalProtect
Host:            gateway.company.com

URLEncoded form

user:              Myusername
addr1:             4.5.6.78/24     (current IPv4 network, I think?)
preferred-ip:      12.34.56.78     (use value from login response)
portal:            Gateway-Name    (use value from login response)
authcookie:        cookie          (32 hex digits from above)
client-type:       1
os-version:        Microsoft Windows Server 2012, 64-bit
app-version:       3.0.1-10
protocol-version:  p1
clientos:          Windows
enc-algo:          aes-256-gcm,aes-128-gcm,aes-128-cbc,
hmac-algo:         sha1,
```

Windows client v4.0.5-8 adds additional parameters at the end:

```xml
app-version:       4.0.5-8
addr1-v6-1:        f00f::/16
addr1-v6-2:        f00f:dead:beef::dead:beef/128
preferred-ipv6:
hmac-algo:         sha1,.
```


getconfig response
==================

Here's where it gets interesting:

* Routing information seems almost identical to what Cisco AnyConnect provides, except in XML form
* IPsec configuration specifies the exist SPI indexes to use, as well
  as the client-to-server (c2s) and server-to-client (s2c) encryption
  keys and authentication keys. Note that the upstream and downstream
  keys and SPIs do **not** match; this is intentional.
* SSL tunnel URL (`<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>`) is the same on all servers I've seen
* MTU is sent as zero (`<mtu>0</mtu>`) on all servers I've seen. This seems broken and useless.

**Currently unknown:** what tags are included in the response to specify IPv6 configuration info, for a VPN which
hands out IPv6 internal addresses?

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
    <!-- Normally, the DNS servers are explicitly listed here as /32 routes.
         0.0.0.0/0 is often included as the first member -->
  </access-routes>
  <exclude-access-routes>
    <!-- this was added in PanOS 8.0 -->
    <member>10.0.0.47/24</member>
    <member>10.0.0.48/24</member>
  </exclude-access-routes>
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

## getconfig response failures

On some servers you may receive a failure response from the `getconfig` call. It can
originate from the portal _or_ from the gateway. There is no known documentation explaining these errors
or their causes. Below are some examples found by users:

### Portal errors (`/global-protect/getconfig.esp`)

```
<?xml version="1.0" encoding="UTF-8" ?>
 <policy>
 <has-config>no</has-config>
 <user-group-loaded>yes</user-group-loaded>
 <portal-userauthcookie>empty</portal-userauthcookie>
 <portal-prelogonuserauthcookie>empty</portal-prelogonuserauthcookie>
</policy>
```

Possible causes:
* The server did not accept the client OS that openconnect sent in the request.
  Try to test with different values for the `--os` parameter.

### Gateway errors (`/ssl-vpn/getconfig.esp`)

```
<response status="error">
	<portal>GW_VPN_EXTERNAL-N</portal>
	<user>xxXXXXX</user>
	<error>Assign private IP address failed</error>
</response>
```

Possible causes:
* The server did not accept the client OS that openconnect sent in the request.
  Try to test with different values for the `--os` parameter.


Data transfer over the tunnel
=============================

In the back-and-forth flows shown below, `<` means sent by the gateway, `>` means sent by the client.

### ESP-over-UDP

Uses the ciphersuite and keying information obtained in response to the `getconfig` request.
Recent official clients state support for `sha1` hash and `aes-256-gcm,aes-128-gcm,aes-128-cbc` encryption in their
`getconfig` request; the _only_ combinations I've ever seen a server return are `aes-128-cbc` with `sha1`. Some
servers return `aes128` as the encryption algorithm, but mean `aes-128-cbc`.

In order to initiate the connection, the client sends 3 ICMP request ("ping") packets to the gateway.

* These packets are ESP-encapsulated
* These packets are sent _from_ **the client's in-VPN IP address** _to_ **the IP address specified by the `<gw-address>` from
  the `getconfig` response**.
  * The destination address is usually the same as the gateway's **public** internet-facing IP address, but sometimes it is a
    VPN-internal address ¯\\\_(ツ)\_/¯
* These ICMP request packets include the following magic payload — though only the first 16 bytes of the payload appear
  to be necessary to elicit a response from the gateway.

      "monitor\x00\x00pan ha 0123456789:;<=>? !\"#$%&\'()*+,-./\x10\x11\x12\x13\x14\x15\x16\x18"
      "monitor\x00\x00pan ha " (first 16 bytes)

* Once the gateway has responded with a corresponding ICMP reply, the client and server send and receive arbitrary
  ESP-encapsulated traffic.
* The client continues to periodically send the same "magic ping" packets as a keepalive.

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
  3. Next 2 bytes are the packet length (as uint16_be) excluding this header, or `0000` for a keepalive packet
  4. Next 8 bytes are always `0100000000000000` for a real IP packet, or `0000000000000000` for a keepalive packet
  5. Remaining bytes are the actual Layer 3 packet (IPv4 packets starting with `45` in the examples above)

The DPD/keepalive packets can be sent by _either_ the client or the server, and the other should immediately respond with an _identical_ packet.

The server will drop the client connection if it doesn't receive anything from the client (after about 120 seconds in my testing) and the client should send the DPD/keepalive if it hasn't received anything from the server in a while. The official client appears to always send keepalive packets every 10 seconds.

### ESP and SSL tunnels are mutually exclusive

If/when the SSL tunnel is connected, the ESP tunnel _cannot_ be used any longer. The VPN server appears to invalidate the SPIs/keys that it sent, and will not respond to ESP-over-UDP packets. The only way to re-enable the ESP connection is to disconnect the SSL tunnel, re-run the getconfig request, and start over with new ESP keys sent in the new getconfig response.

This means that a client that prefers to use ESP **must not** try to connect the SSL tunnel until after an ESP connection has failed. (The official Windows client waits 10 seconds for ICMP reply packets over ESP, before failing over to the SSL tunnel.)

### Rekeying

The `getconfig` response returns a `<timeout>` value, which is the lifetime (in seconds) of both the SSL tunnel
and the ESP keys.

Before the expiration of this key lifetime, the client must re-issue the `getconfig` request with the same authcookie
(this necessarily implies a new SSL/HTTPS connection).  It can then re-open the SSL tunnel or the ESP tunnel, with new
keys, and continue sending traffic as above.

(The `<timeout>` value should not be confused with the `<disconnect-on-idle>` value, which is the period after which
the server will disconnect the client (and invalidate its authcookie) if it doesn't receive any traffic besides
keepalives.)

Logout request
==============

The client **must** send the exact domain, computer name, portal, and OS version from the login request or response…
otherwise the logout request will _fail open_ and the tunnel can be reconnected using the same authcookie.

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

Successful logout response
==========================

```xml
<?xml version='1.0' encoding='UTF-8'?>
<response status="success">
  <portal>Gateway-Name</portal>
  <domain>company domain name</domain>
  <user>Myusername</user>
  <computer>DEADBEEF01</computer>

  <!-- newer servers include these, older ones don't: -->
  <saml-session-index></saml-session-index>
  <saml-name-id></saml-name-id>
</response>
```
