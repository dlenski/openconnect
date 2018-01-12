#!/usr/bin/python

from __future__ import print_function
from urlparse import urlparse
import requests
import argparse
import getpass
import os
from sys import stderr

p = argparse.ArgumentParser()
p.add_argument('-v','--verbose', default=0, action='count')
p.add_argument('endpoint', help='GlobalProtect server; can append /ssl-vpn/login.esp (default) or /global-protect/getconfig.esp')
g = p.add_argument_group('Login credentials')
g.add_argument('-u','--user', help='Username (will prompt if unspecified)')
g.add_argument('-p','--password', help='Password (will prompt if unspecified)')
g.add_argument('-c','--cert', help='PEM file containing client certificate (and optionally private key)')
g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
g.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
args = p.parse_args()

endpoint = urlparse(('https://' if '//' not in args.endpoint else '') + args.endpoint, 'https:')
if not endpoint.path:
    print("Endpoint path unspecified: defaulting to /ssl-vpn/login.esp", file=stderr)
    endpoint = endpoint._replace(path = '/ssl-vpn/login.esp')

if args.cert and args.key:
    cert = (args.cert, args.key)
elif args.cert:
    cert = (args.cert)
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
res = s.post(endpoint.geturl(), verify=args.verify, data=dict(user=args.user, passwd=args.password,
                              # required
                              jnlpReady='jnlpReady', ok='Login', direct='yes',
                              # optional but might affect behavior
                              clientVer=4100, server=args.portal, prot='https:',
                              computer=os.uname()[1]))

if args.verbose:
    print("Request body:\n", res.request.content, file=stderr)

res.raise_for_status()
print(res.text)
