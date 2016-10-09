#!/usr/bin/python

from __future__ import print_function
import requests
import argparse
import getpass
import xml.etree.ElementTree as ET
import os
from sys import stderr
from collections import namedtuple

LoginArgs = namedtuple('LoginArgs', ('authcookie','portal','username','authtype','domain','client_version','preferred_ip'))

p = argparse.ArgumentParser()
p.add_argument('-v','--verbose', default=0, action='count')
p.add_argument('gateway', help='Hostname of GlobalProtect gateway')
g = p.add_argument_group('Login credentials')
g.add_argument('--user', help='Username (will prompt if unspecified)')
g.add_argument('--password', help='Password (will prompt if unspecified)')
g.add_argument('--cert', help='PEM file containing client certificate (and optionally private key)')
g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
args = p.parse_args()

if args.cert and args.key:
    cert = (args.cert, args.key)
elif args.cert:
    cert = (args.cert)
elif args.key:
    p.error('--key specified without --cert')
else:
    cert = None

if not args.user:
    args.user = input('Username: ')
if not args.password:
    args.password = getpass.getpass('Password: ')

s = requests.Session()
s.headers['User-Agent'] = 'PAN GlobalProtect'
s.cert = cert

# login request
login = 'https://{}/ssl-vpn/login.esp'.format(args.gateway)
res = s.post(login, data=dict(user=args.user, passwd=args.password,
                              # required
                              jnlpReady='jnlpReady', ok='Login', direct='yes',
                              # optional but might affect behavior
                              clientVer=4100, server=args.gateway, prot='https:',
                              computer='localhost'))
res.raise_for_status()

la = [a.text for a in ET.fromstring(res.text).findall('./application-desc/argument')]
la = LoginArgs(
    authcookie = la[1],
    portal = la[3],
    username = la[4],
    authtype = la[5],
    domain = la[7],
    client_version = la[14],
    preferred_ip = la[15],
)

if args.verbose:
    print("Arguments returned by login request:", file=stderr)
    print("\t", la, file=stderr)

# getconfig request
getconfig = 'https://{}/ssl-vpn/getconfig.esp'.format(args.gateway)
res = s.post(getconfig, data={
    'user':la.username, 'authcookie':la.authcookie, 'portal':la.portal,

    # these are required
    'client-type': 1, 'protocol-version': 'p1',
    'app-version': '3.0.1-10',
    'os-version': 'Microsoft Windows Server 2012, 64-bit',

    # these seem like they should be required, but are optional:
    'enc-algo':','.join(('aes-256-gcm','aes-128-gcm','aes-128-cbc')), # optional
    'hmac-algo':','.join(('sha1','sha256')),                          # optional

    # these seem to be optional:
    #clientos, preferred-ip, addr1
})

res.raise_for_status()
res = ET.fromstring(res.text)
assert res.attrib['status']=='success'

user, ip, tunnel, mtu = (res.find(x).text for x in ('user', 'ip-address', 'ssl-tunnel-url', 'mtu'))

cookie = 'USER={};AUTH={};IP={}'.format(user, la.authcookie, ip, tunnel)
if tunnel != '/ssl-tunnel-connect.sslvpn':
    cookie += ';TUNNEL={}'.format(tunnel)
if mtu and int(mtu)>0:
    cookie += ';MTU={}'.format(mtu)

dns = (d.text for d in res.findall('dns/member'))
search_domains = (d.text for d in res.findall('dns-suffix/member'))
routes = (d.text for d in res.findall('access-routes/member'))

# explain what to do with the cookie
print(cookie)
if args.verbose:
    print('''Authentication cookie obtained. Connect with:

    $ openconnect --globalprotect --cookie "{}" {}
    '''.format(cookie, args.gateway), file=stderr)
    print("DNS servers: {}".format(', '.join(dns)), file=stderr)
    print("Search domains: {}".format(', '.join(search_domains)), file=stderr)
    print("Routes: {}".format(', '.join(routes)), file=stderr)
