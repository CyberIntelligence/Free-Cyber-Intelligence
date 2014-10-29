#!/usr/bin/python
#################################################################################
#    CyberIntel - OSINT Cyber Threat Intelligence Feed for ArcSight				#
#    freecyberintel at gmail.com												#
#-------------------------------------------------------------------------------#
#    Copyright (C) 2013  Cyber Intel											#
#																				#
#    This program is free software: you can redistribute it and/or modify		#
#    it under the terms of the GNU General Public License as published by		#
#    the Free Software Foundation, either version 3 of the License, or			#
#    (at your option) any later version.										#
#																				#
#    This program is distributed in the hope that it will be useful,			#
#    but WITHOUT ANY WARRANTY; without even the implied warranty of				#
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the				#
#    GNU General Public License for more details.								#
#																				#
#    You should have received a copy of the GNU General Public License			#
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.		#
#################################################################################

## Version 0.3
## 
## New Features:
## 		Proxy User Authentication
##		Updated Sources

import urllib2, time, re, syslog, socket, sys, select
from optparse import OptionParser


socket.setdefaulttimeout(10)

cyberIntelVersion = "0.3"
proxyEnabled = "no"
syslogServer = "localhost"
writeOutFileName = ""
syslogPort = 514
#proxyUser = ""



ipAddressRegex = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
domainNameRegex = re.compile(r"([\w\.][-\w\.]{0,253}[\w\.]+\.)+([a-zA-Z]{2,9})")
commentString1 = re.compile("#.*?\n")
commentString2 = re.compile("\.in-addr\.arpa\.?")
commentString3 = re.compile(r"^[a-z0-9].*")


badIpSources = {
	'http://www.mtc.sri.com/live_data/attackers/':'SRI', 
	'http://isc.sans.edu/reports.html':'SANS',
	'http://www.projecthoneypot.org/list_of_ips.php':'Project Honeypot',
	'http://www.openbl.org/lists/base.txt':'Open Block List',
	'http://www.nothink.org/blacklist/blacklist_malware_http.txt':'nothink.org',
	'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist':'Zeus',
	'https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist':'Spy Eye', 
	'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist':'Palevo',
	'http://www.malwaredomainlist.com/hostslist/ip.txt':'Malware Domain',
	'http://rules.emergingthreats.net/blockrules/compromised-ips.txt':'Emerging Compromised Host',
	'http://rules.emergingthreats.net/blockrules/emerging-botcc.rules':'BotNet C&C Servers',
	'http://rules.emergingthreats.net/fwrules/emerging-PF-CC.rules':'Shadowserver Botnet C&C',
	'http://rules.emergingthreats.net/open/suricata/rules/tor.rules':'Emerging TOR Network',
	'http://rules.emergingthreats.net/blockrules/emerging-ciarmy.rules':'CiArmy Top Attackers',
	'http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/emerging-rbn-malvertisers.txt':'RBN Malvertisers',
}


badDomainSources = {
	'http://www.nothink.org/blacklist/blacklist_malware_dns.txt':'nothink.org',
	'http://secure.mayhemiclabs.com/malhosts/malhosts.txt':'Mayhamic Labs',
	'http://mirror1.malwaredomains.com/files/justdomains':'Malware Domains',
	'http://www.malwaredomainlist.com/hostslist/hosts.txt':'Malware Domain List',
	'http://isc.sans.edu/feeds/suspiciousdomains_Low.txt':'SANS Low',
	'http://isc.sans.edu/feeds/suspiciousdomains_Medium.txt':'SANS Medium',
	'http://isc.sans.edu/feeds/suspiciousdomains_High.txt':'SANS Hi',
	'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist':'Zeus',
	'https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist':'Spy Eye',
    'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist':'Palevo',
}



def syslog(message,host,port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	data = '<29>%s' + message
	sock.sendto(data, (host, port))
	sock.close()


def writeOutput(source,data,outputMethod,dataType):
	if outputMethod == "syslog":
		for line in data:
			if dataType == "Domain":
				line = line[0]+ line[1]
				res = re.match(r"^[a-z0-9].*", line)
				if res is not None:
					line = res.group(0)
					if not line.startswith("iFrame"):
#						line = res.group(0) + "," + source + "\n"
						cef = 'CEF:0|CyberIntel|MalDomain|0.1|100|Known Malicious '+dataType+'|5|dhost='+line+' msg='+source
			elif dataType == "IP":
				cef = 'CEF:0|CyberIntel|MalIP|0.1|100|Known Malicious '+dataType+'|5|dst='+line+' msg='+source
			syslog(cef,syslogServer,syslogPort)

	elif outputMethod == "file":
		f = open(writeOutFileName, 'a')
		for line in data:
			if dataType == "Domain":
				line = line[0]+ line[1]
				res = re.match(r"^[a-z0-9].*", line)
				if res is not None:
					line = res.group(0)
					if not line.startswith("iFrame"):
						line = res.group(0) + "," + source + "\n"
						f.write(line)
			if dataType == "IP":
				line = line + "," + source + "\n"
				f.write(line)
		f.close()


def compileOutput(site,regex):
		result = re.sub(commentString1,"", site)
		result = re.sub(commentString2,"", result)
		return re.findall(regex, result)



def scrapeIntel(url,regex):
	try:
		if proxyEnabled == "yes":
			proxy_url = "http://%s:%s" % (options.proxy, options.proxy_port)
			https_url = "https://%s:%s" % (options.proxy, options.proxy_port)
			proxy_support = urllib2.ProxyHandler({'http': proxy_url, 'https':https_url})
			if options.proxy_user:
				password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
				password_mgr.add_password(None, proxy_url, options.proxy_user, options.proxy_pass)
				proxy_auth_handler = urllib2.ProxyBasicAuthHandler(password_mgr)
				opener = urllib2.build_opener(proxy_support, proxy_auth_handler)
				urllib2.install_opener(opener)
			else:
				opener = urllib2.build_opener(proxy_support)
				urllib2.install_opener(opener)

		print "Grabbing data from: "+url
		webSite = urllib2.urlopen(url).read()
		return compileOutput(webSite, regex)
	except:
		print 'Connection Failed: '+url
		return "false"


def processData(output):
	if options.badip:
		for URL,Name in badIpSources.iteritems():
			result = scrapeIntel(URL,ipAddressRegex)
			if result != "false":
				writeOutput(Name,result,options.output,"IP")
	elif options.baddomain:
		for URL,Name in badDomainSources.iteritems():
			result = scrapeIntel(URL,domainNameRegex)
			if result != "false":
				writeOutput(Name,result,options.output,"Domain")
	else:
		print "no input source defined"
		sys.exit()



if __name__ == "__main__":
	usage = "usage: %prog [options]"
	parser = OptionParser(usage=usage)
	parser.add_option(	"-v", "--version",
	                  	action="store_true", dest="version",
	                  	default=False,
	                  	help="show version")
	parser.add_option(	"--badip", dest="badip", action="store_true", 
				help="Get bad IP addresses")
	parser.add_option(	"--baddomain", dest="baddomain", action="store_true",
				help="Get bad domain names")
	parser.add_option(	"-o", "--output",
				action="store", dest="output",
	                  	metavar="METHOD", help="select output method syslog/file")
	parser.add_option(	"-s", "--syslog",
				action="store", dest="syslog_server",
	                  	metavar="SERVER", help="select syslog server SERVER")
	parser.add_option(	"-p", "--port",
				action="store", type=int, dest="syslog_port",
	                  	metavar="PORT", help="syslog PORT")
	parser.add_option(	"-f", "--file",
				action="store", dest="file_name",
	                  	metavar="FILE", help="select filename to write to")
	parser.add_option(	"--proxy",
				action="store", dest="proxy",
				metavar="PROXY", help="connect via proxy PROXY")
	parser.add_option(	"--proxy_port", action="store", dest="proxy_port",
				metavar="PROXY_PORT", help="proxy server port")
	parser.add_option(	"--proxy_user", action="store", dest="proxy_user",
				metavar="PROXY_USER", help="proxy username")
	parser.add_option(	"--proxy_pass", action="store", dest="proxy_pass",
				metavar="PROXY_PASS", help="proxy password")


	(options, args) = parser.parse_args()


	if options.version:
		print "CyberIntel", cyberIntelVersion
		sys.exit()

	if options.proxy:
		proxyEnabled = "yes"

	if not options.output:
		parser.print_help()
		sys.exit()

	if options.output == "syslog":
		if not options.syslog_server:
			print "syslog server required\n"
			sys.exit()
		else:
			syslogServer = options.syslog_server
			if options.syslog_port:
				syslogPort = options.syslog_port
			processData(options.output)
	elif options.output == "file":
		if not options.file_name:
			print "please select filename to write to\n"
			sys.exit()
		else:
			writeOutFileName = options.file_name
			processData(options.output)
	else:
		print "select a correct output method\n"
		parser.print_help()
		sys.exit()


