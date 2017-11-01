#!/usr/bin/python

from __future__ import print_function
import requests
import argparse
import os
from sys import stderr, exit

p = argparse.ArgumentParser()
#p.add_argument('-v','--verbose', default=0, action='count')
#g = p.add_argument_group('Login credentials')
p.add_argument('--no-verify', action='store_true', dest='verify', default=True, help="Don't verify server certificates.")
p.add_argument('-m','--md5', help='Check if HIP report is needed by submitting MD5 digest last HIP file.')
p.add_argument('-c','--cookie', required=True, help='Cookie value(32 characters).')
p.add_argument('-u','--user', required=True, help='User.')
p.add_argument('-i','--ip', required=True, help='IP.')
p.add_argument('-n','--hostname', required=True, help='Local hostname.')
p.add_argument('-d','--domain', required=True, help='Domain.')
p.add_argument('-p','--portal', required=True, help='Portal name.')
p.add_argument('-g','--gateway', required=True, help='Gateway.')
p.add_argument('-H','--hip', type=argparse.FileType('rb'), required=True, help='HIP file.')
args = p.parse_args()

s = requests.Session()
s.headers['User-Agent'] = 'PAN GlobalProtect'

data = {
    'user': args.user,
    'domain' : args.domain,
    'portal' : args.portal,
    'authcookie' : args.cookie,
    'client-ip' : args.ip,
    'computer' : args.hostname,
    'client-role' : 'global-protect-full',
    'md5' : args.md5,
}

if not args.md5:
    needed = True
else:
    r = s.post('https://%s/ssl-vpn/hipreportcheck.esp' % args.gateway, data=data, verify=args.verify)
    if 'success' in r.text and '<hip-report-needed>no</hip-report-needed>' in r.text:
        print("No HIP report needed.", file=stderr)
        needed = False
    elif 'success' in r.text and '<hip-report-needed>yes</hip-report-needed>' in r.text:
        print("Updated HIP report is needed.", file=stderr)
        needed = True
    else:
        print("HIP report check failed:", file=stderr)
        print(r.text, file=stderr)
        exit(1)

if needed:
    with args.hip:
        report = args.hip.read()
    data['report'] = report
    del data['md5'] # official client doesn't resubmit MD5
    r = s.post('https://%s/ssl-vpn/hipreport.esp' % args.gateway, data=data, verify=args.verify)

    if 'success' in r.text:
        print("HIP report submitted successfully.", file=stderr)
    else:
        print("HIP report submission failed:", file=stderr)
        print(r.text, file=stderr)
        exit(1)
