#!/usr/bin/python

import sys
import os
import requests
import re


class bcolors:
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    NEUTRAL = '\033[94m'
    FAIL = '\033[91m'
    ENDC = '\033[0m' 
    BOLD = '\033[1m'


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


def cve_details(target, cve_code):
    target = 'https://www.cvedetails.com/cve/' + cve_code

    user_agent = {
        'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'
    }
    # get soup
    rqst = requests.get(target, headers=user_agent, verify=False)

    sc = rqst.status_code
    if sc == 200:
            page = rqst.content
            
            soup = bs4.BeautifulSoup(page, 'lxml')

            content = soup.text
            if 'Unknown CVE ID' in content:
                print(R + '[-]' + C + ' Unknown CVE ID' + W)
                exit()
            else:
                pass

            cvedetailssummary = soup.find("div", {"class": "cvedetailssummary"})
            str = cvedetailssummary.text.strip()
            str = str.replace('\t', '\n')
            while '\n\n' in str:
                str = str.replace('\n\n', '\n')
            str = R + 'CVE Description : ' + W + str 
            str = str + '\n' + R + 'CVE Details Url : ' + W + target
            str = str.replace('Last Update Date :', R + 'Last Update Date :' + W)
            str = str.replace('Publish Date :', R + 'Publish Date :' + W)
            print(str)
    else:
        print('\n' + R + '[-]' + C + ' Could not found  ' + W + '\n')


def checkVulns(target, output, data):
    result = {}
    try:
        print ('\n\n' + G + '[+]' + Y + ' Apache CVE :' + W + '\n')
        
        responds = requests.get(target)
        server_name = responds.headers.get('Server')
        if server_name != None:
            if not (server_name.strip().startswith('Apache')):
                print(R + '[-]' + C + ' Server does not seem to be an Apache Server : ' + W + server_name + '\n')
                return
            else:
                print(G + '[+]' + C + ' Apache Server detected : ' + W + server_name + '\n')
                apache_version = re.search('Apache/(.*) ', server_name).group(1)
                x = re.search("[0-3].\\d+.?", apache_version)
                if x:
                    print(G + '[+]' + C + ' Apache Version detected : ' + W + apache_version + '\n')
                else:
                    print(R + '[-]' + C + ' Could not retrieve Apache Version : ' + W + apache_version + '\n')
                    return
        else:
            print(R + '[-]' + C + ' Could not retrieve Server Type, please recheck your url' + W + '\n')
            return
        
        cve_path = './dictionary/apache_CVE.txt'
              
        print(G + '[+]' + C + ' CVE Path : ' + W + cve_path)
        
        vulns = []
        vulns_rp = []
        start = False
        f = open(cve_path, 'r')
        for line in f.readlines():
            if start == True:
                if line != "\n":
                    vulns.append(line)
                    vulns_rp.append(line.replace('\t', ''))
                if not line.startswith('\t'):
                    start = False
                    break
            if line.strip("\n") == apache_version:
                start = True

        if (len(vulns) != 0):
            varVuln = 'vulnerabilities!'
            if (len(vulns) == 1):
                varVuln = 'vulnerability!'
            print(G + '\n[+]' + C + ' Found' + bcolors.FAIL + bcolors.BOLD, len(vulns), bcolors.ENDC + varVuln)
            print(G + '\n[+]' + C + ' Apache ' + bcolors.NEUTRAL + bcolors.BOLD + apache_version + bcolors.ENDC + ' is vulnerable to the following:' + '\n')
            print(bcolors.FAIL + "".join(vulns))
        else:
            print(bcolors.FAIL + '\n[-]' + ' We could\'t find any vulnerabilities in our database for ' + bcolors.NEUTRAL + bcolors.BOLD + 'Apache ' + apache_version + bcolors.ENDC + '.')
        
        # cve details
        for cve_code in vulns_rp:
            print(G + '\n[+]' + C + cve_code + W)
            print('-'*60)
            cve_details(target, cve_code)
            print('-'*60)

        if output != 'None':
            result['CVE-ID'] = vulns_rp
        
    except Exception as e:
        print('\n' + R + '[-]' + C + ' Exception : ' + W + str(e) + '\n')
        if output != 'None':
            result.update({'Exception':str(e)})

    if output != 'None':
        CVE_output(output, data, result)

def CVE_output(output, data, result):
    data['module-Apache CVE'] = result
