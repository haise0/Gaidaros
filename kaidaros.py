#!/usr/bin/env python3

import os
import sys
import atexit
import importlib.util
import platform
import argparse
import datetime


# Colors
R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


fail = False

# Check platform and privilege
if platform.system() == 'Linux':
	if os.geteuid() != 0:
		print('\n' + R + '[-]' + C + ' Please Run as Root!' + '\n')
		sys.exit()
	else:
		pass
else:
	pass

# Check and Install Packages
path_to_script = os.path.dirname(os.path.realpath(__file__))

with open(path_to_script + '/requirements.txt', 'r') as rqr:
	pkg_list = rqr.read().strip().split('\n')

print('\n' + G + '[+]' + C + ' Checking Dependencies...' + W + '\n')

for pkg in pkg_list:
	spec = importlib.util.find_spec(pkg)
	if spec is None:
		print(R + '[-]' + W + ' {}'.format(pkg) + C + ' is not Installed!' + W)
		fail = True
	else:
		pass
if fail == True:
	print('\n' + R + '[-]' + C + ' Please Execute ' + W + 'sudo pip3 install -r requirements.txt' + C + ' to Install Missing Packages' + W + '\n')
	exit()

# Code version
version = '1.0.1'

# parser
parser = argparse.ArgumentParser(description='Kaidaros, forked from Gaidaros - | v{}'.format(version))
parser.add_argument('url', help='Target URL')
parser.add_argument('--trace', help='Traceroute', action='store_true')

# Recon parser
recon_help = parser.add_argument_group('Recon Options')
recon_help.add_argument('--geo', help='Geography IP', action='store_true')
recon_help.add_argument('--headers', help='Header Information', action='store_true')
recon_help.add_argument('--sslinfo', help='SSL Certificate Information', action='store_true')
recon_help.add_argument('--whois', help='Whois Lookup', action='store_true')
recon_help.add_argument('--ps', help='Fast Port Scan', action='store_true')
recon_help.add_argument('--dns', help='DNS Enumeration', action='store_true')
recon_help.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
recon_help.add_argument('--crawl', help='Crawl Target', action='store_true')
recon_help.add_argument('--dir', help='Directory Search', action='store_true')
recon_help.add_argument('--recon', help='Full Recon', action='store_true')

# Light Scan parser
light_help = parser.add_argument_group('Light Scan Options')
light_help.add_argument('--cve', help='Potential Apache CVE', action='store_true')
light_help.add_argument('--cms', help='Content Management System CMS Detector', action='store_true')
light_help.add_argument('--site', help='Site Vulnerabilities Scanner', action='store_true')
light_help.add_argument('--virus', help='Malware URL Scanner', action='store_true')
light_help.add_argument('--light', help='Full Web Light Scan', action='store_true')

# OWASP Scan parser
owasp_help = parser.add_argument_group('OWASP Scan Options')
owasp_help.add_argument('--xss', help='Cross Site Scripting', action='store_true')
owasp_help.add_argument('--csrf', help='Cross Site Request Forgery', action='store_true')
owasp_help.add_argument('--sqli', help='SQL Injection Scripting', action='store_true')
owasp_help.add_argument('--cmdi', help='OS Command Injection', action='store_true')
owasp_help.add_argument('--htmli', help='HTML Injection', action='store_true')
owasp_help.add_argument('--owasp', help='Full OWASP Scan', action='store_true')

# Full Scan parser
full_help = parser.add_argument_group('Full Scan Options')
full_help.add_argument('--full', help='Full Scan', action='store_true')

# Report parser
report_help = parser.add_argument_group('Report Options')
report_help.add_argument('--report', help='Post-scan Reporting', action='store_true')

# Extra Options parser
ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-pm', help='Port Scan Mode [ Default : fast ] [ Available : full ]')
ext_help.add_argument('-t', type=int, help='Number of Threads [ Default : 30 ]')
ext_help.add_argument('-T', type=float, help='Request Timeout [ Default : 20.0 ]')
ext_help.add_argument('-w', help='Path to Wordlist [ Default : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Allow Redirect [ Default : False ]')
ext_help.add_argument('-s', action='store_false', help='Toggle SSL Verification [ Default : True ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Default : 1.1.1.1 ]')
ext_help.add_argument('-e', help='File Extensions [ Example : txt, xml, php ]')
ext_help.add_argument('-m', help='Traceroute Mode [ Default : TCP ] [ Available : TCP, UDP, ICMP ]')
ext_help.add_argument('-p', type=int, help='Port for Traceroute [ Default : 80 / 33434 ]')
ext_help.add_argument('-tt', type=float, help='Traceroute Timeout [ Default : 5.0 ]')
ext_help.add_argument('-o', help='Export Output [ Default : txt ] [ Available : xml, csv ]')
ext_help.set_defaults(
	t=30,
	T=20.0,
	w='wordlists/dirb_common.txt',
	r=False,
	s=True,
	d='1.1.1.1',
	e='',
	m='TCP',
	p=33434,
	tt=5.0,
	o='txt',
    pm='fast')

args = parser.parse_args()

# Recon args
target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
dns = args.dns
trace = args.trace
dirrec = args.dir
pscan = args.ps
geo = args.geo
recon = args.recon

# Light Scan args
cve = args.cve
cms = args.cms
site = args.site
virus = args.virus
light = args.light

# OWASP Scan args
xss = args.xss
sqli = args.sqli
cmdi = args.cmdi
htmli = args.htmli
csrf = args.csrf
owasp = args.owasp

# Full Scan args
full = args.full

# Reports args
report = args.report

threads = args.t
tout = args.T
wdlist = args.w
redir = args.r
sslv = args.s
dserv = args.d
filext = args.e
subd = args.sub
mode = args.m
port = args.p
tr_tout = args.tt
output = args.o
ps_mode = args.pm

import socket
import requests
import datetime
import ipaddress
import tldextract

type_ip = False
data = {}
meta = {}

def banner():
	banner = r'''
██   ██  █████  ██ ██████   █████  ██████   ██████  ███████ 
██  ██  ██   ██ ██ ██   ██ ██   ██ ██   ██ ██    ██ ██      
█████   ███████ ██ ██   ██ ███████ ██████  ██    ██ ███████ 
██  ██  ██   ██ ██ ██   ██ ██   ██ ██   ██ ██    ██      ██ 
██   ██ ██   ██ ██ ██████  ██   ██ ██   ██  ██████  ███████ 
                                                            
                                                            
'''
	print (R + banner + W)
	print (R + '[>]' + Y + ' Created By : ' + W + 'Gaidaros Team' + R + ' [<]\t[>]' + Y + ' Version : ' + W + version + R +' [<]' + W + '\n\n')

def ver_check():
	print(G + '[+]' + C + ' Checking for Updates...', end='')
	ver_url = 'https://raw.githubusercontent.com/haise0/Kaidaros/main/version.txt'
	try:
		ver_rqst = requests.get(ver_url, timeout=5)
		ver_sc = ver_rqst.status_code
		if ver_sc == 200:
			github_ver = ver_rqst.text
			github_ver = github_ver.strip()
			if version == github_ver:
				print(C + '[' + G + ' Up-To-Date ' + C +']' + '\n')
			else:
				print(C + '[' + G + ' Available : {} '.format(github_ver) + C + ']' + '\n')
		else:
			print(C + '[' + R + ' Status : {} '.format(ver_sc) + C + ']' + '\n')
	except Exception as e:
		print('\n\n' + R + '[-]' + C + ' Exception : ' + W + str(e))
		sys.exit()

# Full Recon
def full_recon():
	from modules.recons.geo import geoip
	from modules.recons.headers import headers
	from modules.recons.sslinfo import cert
	from modules.recons.whois import whois_lookup
	from modules.recons.portscan import ps
	from modules.recons.dns import dnsrec
	from modules.recons.subdom import subdomains
	from modules.recons.crawler import crawler
	from modules.recons.dirrec import hammer
	# 1. Geo-IP
	geoip(ip, output, data)
	# 2. HTTP Headers
	headers(target, output, data)
	# 3. SSL Cert Information
	if target.startswith('https://'):
		cert(hostname, output, data)
	else:
		print('\n' + Y + '[!]' + ' Skipping SSL Certification Scan ' + W)
		pass
	# 4. Whois Lookup
	whois_lookup(ip, output, data)
	# 5. Port Scan
	ps(ip, output, data, ps_mode)
	# 6. DNS Enumeration
	dnsrec(domain, output, data)
	# 7. Sub-Domain Enumeration
	if type_ip == False:
		subdomains(domain, tout, output, data)
	else:
		print('\n' + Y + '[!]' + ' Skipping Sub-Domain Enumeration ' + W)
		pass
	# 8. Web Crawling
	crawler(target, output, data)
	# 9. Directory Traversing
	hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)

# Light Scan
def light_scan():
	from modules.lights.apacheScan_CVE import checkVulns
	from modules.lights.cms import cms
	from modules.lights.site import scanSite
	from modules.lights.virus import scanVirus
	# 1. CVE Checkers
	checkVulns(target, output, data)
	# 2. CMS Detector
	cms(target, output, data)
	# 3. Site Vulnerabilities Scan
	scanSite(target, output, data)
	# 4. Virus Scan
	scanVirus(target, output, data)

# OWASP Scan
def owasp_scan():
	from modules.owasps.xss import xss
	from modules.owasps.sqli import sqli
	from modules.owasps.cmdi import cmdi
	from modules.owasps.htmli import htmli
	from modules.owasps.csrf import csrf
	# 1. XSS
	xss(target, output, data)
	# 2. SQLi
	sqli(target, output, data)
	# 2. CMDi
	cmdi(target, output, data)
	# 3. HTMLi
	htmli(target, output, data)
	# 4. CSRF
	csrf(target, output, data)

# Full Scan
def full_scan():
	# 1. Reconnaisance
	full_recon()
	# 2. Light Vuln Scan
	light_scan()
	# 3. OWASP Scan
	owasp_scan()
	# 4. Reports


try:
	banner()
	ver_check()

	if target.startswith(('http://', 'https://')) == False:
		print(R + '[-]' + C + ' Protocol missing - please include ' + W + 'http://' + C + ' or ' + W + 'https://' + '\n')
		sys.exit()
	else:
		pass

	if target.endswith('/') == True:
		target = target[:-1]
	else:
		pass

	print (G + '[+]' + C + ' Target : ' + W + target)
	ext = tldextract.extract(target)
	domain = ext.registered_domain
	hostname = '.'.join(part for part in ext if part)

	try:
		ipaddress.ip_address(hostname)
		type_ip = True
		ip = hostname
	except:
		try:
			ip = socket.gethostbyname(hostname)
			print ('\n' + G + '[+]' + C + 'IP address: ' + W + str(ip))
		except Exception as e:
			print ('\n' + R + '[+]' + C + 'Unable to retrieve IP: ' + W + str(e))
			if '[Errno -2]' in str(e):
				sys.exit()
			else:
				pass
	
	start_time = datetime.datetime.now()

	meta.update({'Version': str(version)})
	meta.update({'Date': str(datetime.date.today())})
	meta.update({'Target': str(target)})
	meta.update({'IP Address': str(ip)})
	meta.update({'Start Time': str(start_time.strftime('%I:%M:%S %p'))})
	data['module-Gaidaros'] = meta
	
	if any([recon, geo, headinfo, sslinfo, whois, crawl, dns, subd, trace, pscan, dirrec, cve, cms, site, virus, light, xss, cmdi, htmli, csrf, owasp, report, full]) != True:
		print ('\n' + R + '[-] Error : ' + C + 'At least one argument is required with URL' + W)
		output = 'None'
		sys.exit()
		
	from modules.supports.rich_table import table_checklist
	table_checklist(recon, geo, headinfo, sslinfo, whois, crawl, dns, subd, pscan, dirrec, light, cve, cms, site, virus, owasp, xss, csrf, sqli, cmdi, htmli, report, output, full, trace)
	user_confirm = input(G + '\n[?]' + C + ' Please confirm the options with Y/N: ' + W)
	if user_confirm.lower().startswith("y"):
		pass
	else:
		print(G + '\n[+]' + C + 'Going back - you may proceed again after adjusting your options. \n')
		sys.exit()
	
	if output == 'txt':
		already_text = True
	else: already_text = False
	
	if output != 'None':
		fname = os.getcwd() + '/dumps/' + hostname + datetime.datetime.now().strftime("_%d%m%Y_%H%M") + '.' + output
		output = {
			'format': output,
			'file': fname,
			'export': False
			}

	from modules.supports.export import export
	
	if recon == True:
		full_recon()
	
	if geo == True:
		from modules.recons.geo import geoip
		geoip(ip, output, data)
	
	if headinfo == True:
		from modules.recons.headers import headers
		headers(target, output, data)

	if sslinfo == True and target.startswith('https://'):
		from modules.recons.sslinfo import cert
		cert(hostname, output, data)
	elif sslinfo == True and not target.startswith('https://'):
		print('\n' + R + '[-]' + C + 'SSL Certification Scan is not supported for HTTP protocols.' + W + '\n')
		sys.exit()
	else:
		pass

	if whois == True:
		from modules.recons.whois import whois_lookup
		whois_lookup(ip, output, data)

	if crawl == True:
		from modules.recons.crawler import crawler
		crawler(target, output, data)

	if dns == True:
		from modules.recons.dns import dnsrec
		dnsrec(domain, output, data)

	if subd == True and type_ip == False:
		from modules.recons.subdom import subdomains
		subdomains(domain, tout, output, data)
	elif subd == True and type_ip == True:
		print(R + '[-]' + C + ' Sub-Domain Enumeration is not supported for IP Addresses.' + W + '\n')
		sys.exit()
	else:
		pass

	if trace == True:
		from modules.supports.traceroute import troute
		if mode == 'TCP' and port == 33434:
			port = 80
			troute(ip, mode, port, tr_tout, output, data)
		else:
			troute(ip, mode, port, tr_tout, output, data)

	if pscan == True:
		from modules.recons.portscan import ps
		ps(ip, output, data, ps_mode)

	if dirrec == True:
		from modules.recons.dirrec import hammer
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)
	
	if cve == True:	
		from modules.lights.apacheScan_CVE import checkVulns
		checkVulns(target, output, data)
	
	if cms == True:
		from modules.lights.cms import cms
		cms(target, output, data)
	
	if site == True:
		from modules.lights.site import scanSite
		scanSite(target, output, data)
	
	if virus == True:
		from modules.lights.virus import scanVirus
		scanVirus(target, output, data)
		
	if light == True:
		light_scan()
	
	if xss == True:
		from modules.owasps.xss import xss
		xss(target, output, data)
		
	if sqli == True:
		from modules.owasps.sqli import sqli
		sqli(target, output, data)
		
	if cmdi == True:
		from modules.owasps.cmdi import cmdi
		cmdi(target, output, data)
	
	if htmli == True:
		from modules.owasps.htmli import htmli
		htmli(target, output, data)
		
	if csrf == True:
		from modules.owasps.csrf import csrf
		csrf(target, output, data)
		
	if owasp == True:
		owasp_scan()

	if full == True:
		full_scan()
	
	end_time = datetime.datetime.now() - start_time
	print ('\n' + G + '[+]' + C + 'Scan completed in ' + W + str(end_time) + '\n')

	meta.update({'End Time': str(datetime.datetime.now().strftime('%I:%M:%S %p'))})
	meta.update({'Completion Time': str(end_time)})
	if output != 'None':
		output['export'] = True
		export(output, data)
			
	if report == True:
		if not already_text:
			output = 'txt'
			fname = os.getcwd() + '/dumps/' + hostname + datetime.datetime.now().strftime("_%d%m%Y_%H%M") + '.' + output
			output = {
				'format': output,
				'file': fname,
				'export': True
				}
			export(output, data)
		else: pass
		from modules.reports.report import report
		report(target, fname)
		
	sys.exit()
except KeyboardInterrupt:
	print (R + '[-]' + C + 'Keyboard interrupt!' + W + '\n')
	sys.exit()
