#!/usr/bin/python

# Lifted from Russ Dill's juniper-vpn-wrap.py, thus:
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import subprocess
import mechanize
import cookielib
import getpass
import sys
import os
import zipfile
import urllib
import socket
import ssl
import errno
import argparse
import atexit
import signal
import ConfigParser
import time
import binascii
import hmac
import hashlib

def mkdir_p(path):
    try:
        os.mkdir(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

class Tncc:
    def __init__(self, vpn_host):
        self.vpn_host = vpn_host;
        self.plugin_jar = '/usr/share/icedtea-web/plugin.jar'

        if not os.path.isfile(self.plugin_jar):
            raise Exception(self.plugin_jar + ' not found')
        self.user_agent = 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'
        
    def tncc_init(self):
        class_names = ('net.juniper.tnc.NARPlatform.linux.LinuxHttpNAR',
                       'net.juniper.tnc.HttpNAR.HttpNAR')
        self.class_name = None

        self.tncc_jar = os.path.expanduser('~/.juniper_networks/tncc.jar')
        try:
            if zipfile.ZipFile(self.tncc_jar, 'r').testzip() is not None:
                raise Exception()
        except:
            print 'Downloading tncc.jar...'
            mkdir_p(os.path.expanduser('~/.juniper_networks'))
            urllib.urlretrieve('https://' + self.vpn_host
                               + '/dana-cached/hc/tncc.jar', self.tncc_jar)

        with zipfile.ZipFile(self.tncc_jar, 'r') as jar:
            for name in class_names:
                try:
                    jar.getinfo(name.replace('.', '/') + '.class')
                    self.class_name = name
                    break
                except:
                    pass

        if self.class_name is None:
            raise Exception('Could not find class name for', self.tncc_jar)

        self.tncc_preload = \
            os.path.expanduser('~/.juniper_networks/tncc_preload.so')
        if not os.path.isfile(self.tncc_preload):
            raise Exception('Missing', self.tncc_preload)

    def tncc_start(self):
        # tncc is the host checker app. It can check different
        # security policies of the host and report back. We have
        # to send it a preauth key (from the DSPREAUTH cookie)
        # and it sends back a new cookie value we submit.
        # After logging in, we send back another cookie to tncc.
        # Subsequently, it contacts https://<vpn_host:443 every
        # 10 minutes.

        if not self.tncc_jar:
            self.tncc_init()

        null = open(os.devnull, 'w')

        self.tncc_process = subprocess.Popen(['java',
            '-classpath', self.tncc_jar + ':' + self.plugin_jar,
            self.class_name,
            'log_level', '100',
            'postRetries', '6',
            'ivehost', self.vpn_host,
            'home_dir', os.path.expanduser('~'),
            'Parameter0', '',
            'user_agent', self.user_agent,
            ], env={'LD_PRELOAD': self.tncc_preload})


        
if __name__ == "__main__":
    if len(sys.argv) <= 1:
        raise Exception("Usage: ...")
        
    tncc = Tncc(sys.argv[1])
    tncc.tncc_init()
    tncc.tncc_start()
