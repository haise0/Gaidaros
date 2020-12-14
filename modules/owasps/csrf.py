import tldextract
import argparse
import sys
import bs4
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    try:
        # get all the input details such as type and name
        inputs = []
        for input_tag in form.find_all("input"):
            if input_tag.attrs.get("type") != "hidden":
                 continue
            input_name = input_tag.attrs.get("name")
            inputs.append(input_name)
        if not inputs:
            return None
        return inputs
    except AttributeError as N:
        print(G + "[+]" + C + f" No action form detected on this site" + W)
        return None
    except Exception as e:
        print('\n' + R + '[-] Exception : ' + C + str(e) + W)

def cookie_info(url, attributes):
    try:
        r = requests.get(url)
        for cookie in r.cookies:
            if cookie in attributes:
                continue
            else:
                attributes.append(cookie.name)
    except Exception as e:
        return

def scan_csrf(url, value_forms_malforms, csrf_data):
    """
    Given a `url`, it prints all csrf vulnerable forms and
    returns True if any is vulnerable, False otherwise
    """
    try:
        # get all the forms from the URL
        forms = get_all_forms(url)
        print(G + "[+]" + C + f" Detected {len(forms)} forms on {url}" + W)
        csrf_data.append(f"Detected {len(forms)} forms on {url}")
        value_forms_malforms[0] = value_forms_malforms[0] + len(forms)
        # returning value
        is_vulnerable = True
        # iterate over all forms
        CSRFtokens_path = "./dictionary/CSRFtokens.txt"
        COMMON_CSRF_ATTRIBUTES = open(CSRFtokens_path, "r")
        for form in forms:
            form_details = get_form_details(form)
            cookie_info(url, form_details)
            if form_details == None:
                print(G + "[+]" + " No hidden values detected!" + W)
                break
            for attributes in COMMON_CSRF_ATTRIBUTES:
                for i in form_details:
                    if attributes.rstrip() == i:
                        is_vulnerable = False
                        print(G + "[+]" + f" CSRF not detected on {url}" + W)
                        csrf_data.append(f"CSRF not detected on {url}\n")
                        break
            if is_vulnerable == True:
                print(R + "[-]" + C + " Hidden attributes details:" + W)
                for i in form_details:
                    print(C + "[.] " + W + i)
                print(R + "[-] CSRF Tokens not found!" + W)
                print(R + f"[-] Potential CSRF Detected on {url}" + W)
                csrf_data.append(f"Cross Site Request Forgery detected on {url}\n")
                break

    except Exception as e:
        print(R + '[-] Exception : ' + C + str(e) + W)


def csrf(target, output, data):
    result = {}
    csrf_data = []

    try:
        print ('\n\n' + G + '[+]' + Y + ' Cross Site Request Forgery (csrf) :' + W + '\n')

        user_agent = {
            'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'
        }
        # get soup
        try:
            rqst = requests.get(target, headers=user_agent, verify=False)
        except Exception as e:
            print(R + '[-] Exception : ' + C + str(e) + W)
            exit()

        sc = rqst.status_code
        if sc == 200:
            int_total = []
            value_forms_malforms = [0,0]

            page = rqst.content
            soup = bs4.BeautifulSoup(page, 'lxml')

            ext =  tldextract.extract(target)
            domain = ext.registered_domain

            links = soup.find_all('a')
            for link in links:
                url = link.get('href')
                if url != None:
                    if not ("http://" in url or "https://" in url):
                        url = target +  "/" + url
                    if not '#' in url:
                        if domain in url:
                            int_total.append(url)

            int_total = set(int_total)

            scan_csrf(target, value_forms_malforms, csrf_data)
            for int in int_total:
                scan_csrf(int, value_forms_malforms, csrf_data)

            print("\n" + G + "[+] " + str(len(int_total) + 1) + C + " total urls tested" + W)
            print(G + "[+] " + str(value_forms_malforms[0]) + C + " total forms detected" + W)
            if value_forms_malforms[1] == 0:
                print(G + "[+] " + str(value_forms_malforms[1]) + C + " total malicious forms detected" + W)
            else:
                print(R + "[-] " + str(value_forms_malforms[1]) + C + " total malicious forms detected" + W)

        else:
            print(R + '[-]' + C + ' Response code returned is not 200' + W)

        if output != 'None':
            result['csrf'] = csrf_data

    except Exception as e:
        print(R + '[-] Exception : ' + C + str(e) + W)
        if output != 'None':
            result.update({'Exception':str(e)})

    if output != 'None':
        csrf_output(output, data, result)
        print()


def csrf_output(output, data, result):
    data['module-Cross Site Request Forgery'] = result
