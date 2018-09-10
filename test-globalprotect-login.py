#!/usr/bin/python

from __future__ import print_function
from sys import stderr, version_info
if (version_info > (3, 0)):
    from urllib.parse import urlparse, urlencode
else:
    from urlparse import urlparse
    from urllib import urlencode
import requests
import argparse
import getpass
import os
import xml.etree.ElementTree as ET

p = argparse.ArgumentParser()
p.add_argument('-v','--verbose', default=0, action='count')
p.add_argument('endpoint', help='GlobalProtect server; can append /ssl-vpn/login.esp (default) or /global-protect/getconfig.esp')
p.add_argument('extra', nargs='*', help='Extra field to pass to include in the login query string (e.g. "portal-userauthcookie=deadbeef01234567")')
g = p.add_argument_group('Login credentials')
g.add_argument('-u','--user', help='Username (will prompt if unspecified)')
g.add_argument('-p','--password', help='Password (will prompt if unspecified)')
g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
g.add_argument('--computer', default=os.uname()[1], help="Computer name (default is `hostname`)")
g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
g.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
args = p.parse_args()

extra = dict(x.split('=', 1) for x in args.extra)
endpoint = urlparse(('https://' if '//' not in args.endpoint else '') + args.endpoint, 'https:')
if not endpoint.path:
    print("Endpoint path unspecified: defaulting to /ssl-vpn/login.esp", file=stderr)
    endpoint = endpoint._replace(path = '/ssl-vpn/login.esp')

if args.cert and args.key:
    cert = (args.cert, args.key)
elif args.cert:
    cert = (args.cert, None)
elif args.key:
    p.error('--key specified without --cert')
else:
    cert = None

if not args.user:
    args.user = raw_input('Username: ')
if not args.password:
    args.password = getpass.getpass('Password: ')

s = requests.Session()
s.headers['User-Agent'] = 'PAN GlobalProtect'
s.cert = cert

# same request params work for /global-protect/getconfig.esp as for /ssl-vpn/login.esp
res = s.post(endpoint.geturl(), verify=args.verify,
             data=dict(user=args.user, passwd=args.password,
                       # required
                       jnlpReady='jnlpReady', ok='Login', direct='yes',
                       # optional but might affect behavior
                       clientVer=4100, server=endpoint.netloc, prot='https:',
                       computer=args.computer,
                       **extra))

if args.verbose:
    if (version_info > (3, 0)):
        print("Request body:\n", res.request.body, file=stderr)
    else:
        print("Request body:\n", res.request.content, file=stderr)

res.raise_for_status()
print(res.headers)
print(res.text)

# build openconnect "cookie" if the result is a <jnlp>

try:
    xml = ET.fromstring(res.text)
except Exception:
    xml = None

if xml.tag == 'jnlp':
    arguments = [(t.text or '') for t in xml.iter('argument')]
    cookie = urlencode({'authcookie': arguments[1], 'portal': arguments[3], 'user': arguments[4], 'domain': arguments[7],
                        'computer': args.computer, 'preferred-ip': arguments[15] if len(arguments)>=16 else ''})
    if cert:
        cert_and_key = ' \\\n        ' + ' '.join('%s "%s"' % (opt, fn) for opt, fn in zip(('-c','-k'), cert) if fn)
    else:
        cert_and_key = ''

    print('''

Extracted connection cookie from <jnlp>. Use this to connect:

    openconnect --protocol=gp --usergroup=gateway %s \\
        --cookie "%s"%s
''' % (endpoint.netloc, cookie, cert_and_key))
