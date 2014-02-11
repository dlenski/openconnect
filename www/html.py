#!/usr/bin/env python
#
# Simple XML to HTML converter.
# 
# (C) 2005 Thomas Gleixner <tglx@linutronix.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#

import os
import sys
import getopt
import pprint
import shutil
import string
import smtplib
import socket
import time
import xml.sax
import commands
import codecs

reload(sys)
sys.setdefaultencoding('utf-8')

lookupdir = ''

# Print the usage information
def usage():
	print "USAGE:"
	print "html.py <-f -h file.xml>"
	print "  -d DIR    use DIR as base directory for opening files"
	print "  -f        write output to file.html (default is stdout)"
	print "  -h        help"
	return


# Headerfields
header = [
"Mime-Version: 1.0\r\n",
"Content-Type: text/plain; charset=utf-8\r\n",
"Content-Transfer-Encoding: 8bit\r\n",
"Content-Disposition: inline\r\n",
]

html = []
replace = []
fdout = sys.stdout

def replaceVars(line):
	cnt = 0
	while cnt < len(replace):
		if line.find(replace[cnt]) >= 0:
			line = line.replace(replace[cnt], replace[cnt+1])
		cnt = cnt + 2
	return line

def writeHtml(line):
	fdout.write(replaceVars(line))

def startMenu(level):
	writeHtml("<div id=\"menu%s\">\n" %(level))

def placeMenu(topic, link, mode):

	topic = replaceVars(topic)
	mode = replaceVars(mode)
	
	if mode == 'text':
		writeHtml("<p>%s</p>\n" %(topic))
		return
	if mode == 'selected':
		writeHtml("<span class=\"sel\">\n")
	else:
		writeHtml("<span class=\"nonsel\">\n")
		
	writeHtml("<a href=\"%s\"><span>%s</span></a>\n" %(link, topic))
	writeHtml("</span>\n")
	

# configuration parser
class docHandler(xml.sax.ContentHandler):

	def __init__(self):
		self.content = ""
		return
    
	def startElement(self, name, attrs):
		self.element = name
				
		if len(self.content) > 0:
			writeHtml(self.content)
		self.content = ""
		
		if name == "PAGE":
			return
		elif name == "INCLUDE":
			try:
				fd = open(attrs.get('file'), 'r')
			except:
				fd = open(lookupdir + attrs.get('file'), 'r')
			lines = fd.readlines()
			fd.close()
			for line in lines:
				writeHtml(line)
		elif name == "PARSE":
			parseConfig(attrs.get('file'))
			
		elif name == 'STARTMENU':
			startMenu(attrs.get('level'))
			
		elif name == 'MENU':
			placeMenu(attrs.get('topic'), attrs.get('link'), attrs.get('mode'))
			
		elif name == 'ENDMENU':
			writeHtml("</div>\n")
			
		elif name == 'VAR':
			match = attrs.get('match')
			repl = attrs.get('replace')
			idx = len(replace)
			replace[idx:] = [match]
			idx = len(replace)
			replace[idx:] = [repl]
		
		elif name == "br":
			writeHtml("<br")
			if attrs.getLength > 0:
				names = attrs.getNames()
				for name in names:
					writeHtml(" " + name + "=\"" + attrs.get(name) + "\"")
			writeHtml(" />")
			
		else:
			writeHtml("<" + name)
			if attrs.getLength > 0:
				names = attrs.getNames()
				for name in names:
					writeHtml(" " + name + "=\"" + attrs.get(name) + "\"")
			writeHtml(">")

	def characters(self, ch):
		self.content = self.content + ch

	def endElement(self, name):

		if name == "PAGE":
			return
		elif name == 'INCLUDE':
			return
		elif name == 'PARSE':
			return
		elif name == 'PAGE':
			return
		elif name == 'STARTMENU':
			return
		elif name == 'ENDMENU':
			return
		elif name == 'MENU':
			return
		elif name == 'VAR':
			return
		elif name == 'br':
			return

		if len(self.content) > 0:
			writeHtml(self.content)
		self.content = ""
		writeHtml("</" + name + ">")
	

# error handler
class errHandler(xml.sax.ErrorHandler):
	def __init__(self):
		return

	def error(self, exception):
		sys.stderr.write("%s\n" % exception)

	def fatalError(self, exception):
		sys.stderr.write("Fatal error while parsing configuration\n")
		sys.stderr.write("%s\n" % exception)
		sys.exit(1)

# parse the configuration file
def parseConfig(file):
	# handlers
	dh = docHandler()
	eh = errHandler()

	# Create an XML parser
	parser = xml.sax.make_parser()

	# Set the handlers
	parser.setContentHandler(dh)
	parser.setErrorHandler(eh)

	try:
		fd = open(file, 'r')
	except:
		fd = open(lookupdir + file, 'r')

	# Parse the file
	parser.parse(fd)
	fd.close()


# Here we go
# Parse the commandline

writefile = 0

try:
	(options, arguments) = getopt.getopt(sys.argv[1:],'fhd:')
except getopt.GetoptError, ex:
	print
	print "ERROR:"
	print ex.msg
	usage()
	sys.exit(1)
	pass

for option, value in options:
	if option == '-d':
		lookupdir = value + '/'
	if option == '-f':
		writefile = 1
	elif option == '-h':
		usage()
		sys.exit(0)
		pass
	pass

# Handle special case VAR_ORIGIN
idx = len(replace)
replace[idx:] = ['VAR_ORIGIN']
idx = len(replace)
replace[idx:] = [lookupdir]

if not arguments:
	print "No source file specified"
	usage()
	sys.exit(1)
	pass

if writefile > 0:
	fname = arguments[0].split('.')[0]
	fname = fname + ".html"
	fdout = codecs.open(fname, 'w', 'utf-8')	

parseConfig(arguments[0])

if writefile > 0:
	fdout.close()

