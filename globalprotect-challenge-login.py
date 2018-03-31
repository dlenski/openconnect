#!/usr/bin/python

from __future__ import print_function
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
    input = raw_input

import requests
import argparse
import getpass
import os, re
import xml.etree.ElementTree as ET
from sys import stderr

p = argparse.ArgumentParser()
p.add_argument('-v','--verbose', default=0, action='count')
p.add_argument('gateway', help='Hostname of GlobalProtect gateway')
g = p.add_argument_group('Login credentials')
g.add_argument('-l', '--preloginCookie', help='Prelogin cookie (replaces password)')
g.add_argument('-u', '--user', help='Username (will prompt if unspecified)')
g.add_argument('-p', '--password', help='Password (will prompt if unspecified, unless using a prelogin cookie)')
g.add_argument('--cert', help='PEM file containing client certificate (and optionally private key)')
g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
g.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
args = p.parse_args()

if args.cert and args.key:
    cert = (args.cert, args.key)
elif args.cert:
    cert = (args.cert)
elif args.key:
    p.error('--key specified without --cert')
else:
    cert = None

if not args.verify:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)    
    
s = requests.Session()
s.headers['User-Agent'] = 'PAN GlobalProtect'
s.cert = cert

if args.verbose:
    http_client.HTTPConnection.debuglevel = 1

user, password, preloginCookie, inputStr = args.user, args.password, args.preloginCookie, ''
login = 'https://{}/ssl-vpn/login.esp'.format(args.gateway)
hostname = os.uname()[1]
jnlp = None

while True:
    if not user:
        user = input('Username: ')
    if not password and not preloginCookie:
        password = getpass.getpass('Password: ')

    print("Posting login request to: %s" % login)
    form = dict(user=user, passwd=password, inputStr=inputStr,
                jnlpReady='jnlpReady', ok='Login', direct='yes', # required
                clientVer=4100, server=args.gateway, prot='https:', computer=hostname # optional but might affect behavior
    )
    if preloginCookie:
        form['prelogin-cookie'] = preloginCookie
    res = s.post(login, form, verify=args.verify)

    unknown = False
    if res.headers['Content-Type']=='text/html':
        # parse JavaScript-y bits
        m = re.match(r'''\n*var respStatus = "(.*)";\nvar respMsg = "(.*)";\n*thisForm.inputStr.value = "(.*)";\n*''', res.text)
        if m:
            respStatus, respMsg, value = m.groups()
            if respStatus=='Challenge':
                print('=> Challenge with inputStr=%r: %s' % (value, respMsg))
                password = None
                inputStr = value
            else:
                print('=> %s with inputStr=%r: %s' % (respStatus, inputStr, respMsg))
                break
        else:
            unknown = True
    elif res.status_code == 200:
        print('=> Success')
        jnlp = res.text
        break
    else:
        unknown = True

    if unknown:
        print('Got unknown response: %r', res.text)
        res.raise_for_status()

if jnlp:
    jnlp = [x.text for x in ET.fromstring(jnlp).findall('.//argument')]
    authcookie = 'user={4}&authcookie={1}&portal={3}&domain={7}'.format(*jnlp)
    print('''
Start openconnect with:

    openconnect --protocol=gp %s --cookie "%s"
''' % (args.gateway, authcookie), file=stderr)
