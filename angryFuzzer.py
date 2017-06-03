#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
'''
AngryFuzz3r is a collection of tools for pentesting to gather information about the targets based on Fuzzedb https://github.com/fuzzdb-project/fuzzdb
this tool fuzzing and find some pages in the server .  
'''
__author__ = "Iheb Ben Salem (S0ld1er)"
__copyright__ = "Copyright 2017, Bugs_Bunny Team | Pentesting Tools"
__version__ = "0.5"
__email__ = "ihebbensalem.dev@gmail.com"
__status__ = "Development"
__codename__ = 'urlfuzzer'
__source__ ="https://github.com/ihebski/angryFuzzer"
__info__ ="URL Fuzzing"

from lib.colors import colors as c	
try: 
	import re
	import requests 
	import sys
	import os
	import getopt
	import argparse
	from urlparse import urlparse
	import time
	import optparse
except Exception as err:
	print "[!] "+str(err)
	sys.exit(0)

wordlists ={"dict":"fuzzdb/discovery/predictable-filepaths/dicc.txt",
		"wp":"fuzzdb/discovery/predictable-filepaths/cms/wordpress.txt",
		"dp":"fuzzdb/discovery/predictable-filepaths/cms/drupal_plugins.txt",
		"jm":"fuzzdb/discovery/predictable-filepaths/cms/joomla_plugins.txt",
		}

def banner():
	print c.BLUE+ 	 "   _____                               ___________                    ________        " 
	print c.LIGHTRED+"  /  _  \   ____    ___________ ___.__.\_   _____/_ __________________\_____  \______ "
	print 			 " /  /_\  \ /    \  / ___\_  __ <   |  | |    __)|  |  \___   /\___   /  _(__  <_  __ \""
	print 			 "/    |    \   |  \/ /_/  >  | \/\___  | |     \ |  |  //    /  /    /  /       \  | \/"
	print 		 	 "\____|__  /___|  /\___  /|__|   / ____| \___  / |____//_____ \/_____ \/______  /__|   "
	print c.BLUE+ 	 "        \/     \//_____/        \/          \/              \/      \/       \/       \n"
	print c.CYAN+    "============>"+__source__
	print c.BLUE +	 "===========================================> by Sold1er \n"+c.RESET		

def start():
	banner()
	pars = optparse.OptionParser(description="[*] Discover hidden files and directories")
	pars.add_option('-q', '--quiet',action="store_true", dest="verbose", help="Silent mode ,only repport", default=False)
	pars.add_option('-u', '--url',action="store", dest="url", type="string", help=" URL of the Target",default=None)
	pars.add_option('-c', '--cms',action="store", type="string", dest="cms", help="scan CMS ==> wp ,dp",default=None)
	pars.add_option('-w', '--wordlist',action="store", type="string", dest="wordlist", help="Custom wordlist",default=None)

	opts, args = pars.parse_args()

	if not opts.url :
		print "usage : python angryFuzzer.py -h"
	if opts.url:
		o = urlparse(opts.url)
		if o[0] not in ['http','https', 'www']:
			print c.RED+"[!] Please checkout your URL http://, https:// or www.[site]"
			sys.exit(0)		
	if opts.cms:
		if opts.cms not in ["wp","dp","jm"]:
			print c.RED+"[!] Please chose the cms name {wp,dp,jm}"
			sys.exit(0)
	if opts.wordlist:
		if not os.path.isfile(str(opts.wordlist)):
			print c.RED+"[!] Please checkout your Custom wordlist path"					
			sys.exit(0)
	fuzz(opts.url,opts.cms,opts.wordlist)	

def Report(results):
	'''
	Final Results of the Valides URLs with status code = 200 ok
	'''
	print c.WHITE +"=== Report ==== "
	for x in results:
		print c.MAGANTA+"[+] -[200] -"+x

def fuzz(url,cmsType,CustomWordlist):
	'''
	All the logic of the application goes here .
	'''
	results = []
	if cmsType :
		words = [w.strip() for w in open(wordlists[cmsType], "rb").readlines()] #parse wordlist
	elif CustomWordlist :
		words = [w.strip() for w in open(str(CustomWordlist), "rb").readlines()] #parse wordlist
	else :
		words = [w.strip() for w in open(wordlists["dict"], "rb").readlines()] #parse wordlist
	try:
		for paths in words:
			if "/" not in paths[0]:  # Correct path from c99.php to /c99.php/
				paths ="/"+paths
			if "/" not in paths[-1:]:
				paths = paths+"/"			
			fullPath = url+paths  # Full path
			r = requests.get(fullPath) # Interact with server
			code = str(r.status_code)   # Get status code 200,301,404 ....
			if code == "200":
				print c.GREEN+"[+] [{time}] - [{code}] - [{paths}] -> {fullPath}".format(time=time.strftime("%H:%M:%S"),code=code,paths=paths,fullPath=fullPath)      
				results.append(fullPath)
			elif code == "301":
				print c.YELLOW+"[+] [{time}] - [{code}] - [{paths}] -> {fullPath}".format(time=time.strftime("%H:%M:%S"),code=code,paths=paths,fullPath=fullPath)      
			else:
				print c.LIGHTRED+"[+] [{time}] - [{code}] - [{paths}] -> {fullPath}".format(time=time.strftime("%H:%M:%S"),code=code,paths=paths,fullPath=fullPath)      
			#time.sleep(0.5)	
		Report(results)		
	except Exception as e:
		print ""
		#print "ERROR =>",e


if __name__ == '__main__':
	try:
		start()
	except KeyboardInterrupt as err:
		print "\n[!] By... :)"
		sys.exit(0)
