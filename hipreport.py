#!/usr/bin/python

from __future__ import print_function
from urlparse import parse_qsl
from datetime import datetime
import hashlib
import requests
import argparse
import os
from sys import stdin, stderr, exit

class FingerprintChecker(requests.adapters.HTTPAdapter):
    def __init__(self, fingerprint, algorithm='md5', **kwargs):
        self.fingerprint = fingerprint
        self.algorithm = algorithm
        super(FingerprintChecker, self).__init__(**kwargs)
    def build_response(self, request, resp):
        response = super(FingerprintChecker, self).build_response(request, resp)
        try:
            self.peercert = resp._connection.sock.getpeercert(binary_form=True)
            self.peercertinfo = resp._connection.sock.getpeercert(binary_form=False)
        except AttributeError:
            pass
        else:
            checkfp = hashlib.new(self.algorithm, self.peercert).hexdigest()
            if checkfp.strip().lower() != self.fingerprint.strip().lower():
                raise requests.exceptions.SSLError("Server certificate fingerprint does not match expected %s:%s" % (self.algorithm, self.fingerprint))
        return response
    def cert_verify(self, conn, url, verify, cert):
        super(FingerprintChecker, self).cert_verify(conn, url, False, cert)

p = argparse.ArgumentParser()
p.add_argument('-q','--querystring', type=lambda s: dict(parse_qsl(s)),
               help='URL-escaped query string with HIP parameters. It should contain these fields: user, domain, portal, authcookie, client-ip, computer.')
p.add_argument('--servercert', help="Server's certificate MD5 fingerprint")
p.add_argument('-r','--raw', action='store_true', help="Don't interpolate format strings in HIP file ({__NOW__}, {md5}, {user}, {domain}, {portal}, {client-ip}, {computer})")
p.add_argument('-g','--gateway', required=True, help='GlobalProtect gateway server.')
p.add_argument('-H','--hip', type=argparse.FileType('r'), default=stdin, help='HIP report file (default is stdin)')
p.add_argument('-m','--md5', help='Check if HIP report is needed by submitting MD5 digest last HIP file.')
args = p.parse_args()

s = requests.Session()
s.headers['User-Agent'] = 'PAN GlobalProtect'
if args.servercert:
    s.mount('https://' + args.gateway, FingerprintChecker(args.servercert))

data = args.querystring
data['client-role'] = 'global-protect-full'
data['md5'] = args.md5

with args.hip:
    report = args.hip.read()
    if not args.raw:
        report = report.format(__NOW__=datetime.now().strftime('%d/%m/%Y %H:%M:%S'), **data)
data['report'] = report
del data['md5'] # official client doesn't resubmit MD5
r = s.post('https://%s/ssl-vpn/hipreport.esp' % args.gateway, data=data)

if 'success' in r.text:
    print("HIP report submitted successfully.", file=stderr)
else:
    print("HIP report submission failed:", file=stderr)
    print(r.text, file=stderr)
    exit(1)
