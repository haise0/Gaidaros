## Kaidaros
[![GitHub last commit](https://img.shields.io/github/last-commit/haise0/Kaidaros?logo=github)](#)
[![GitHub repo size](https://img.shields.io/github/repo-size/haise0/Kaidaros?color=red&logo=github)](#)
[![GitHub top language](https://img.shields.io/github/languages/top/haise0/Kaidaros?logo=python&logoColor=yellow)](https://www.python.org/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/icmplib?color=purple&label=version&logo=python&logoColor=yellow)](https://www.python.org/downloads/)
[![GitHub issues](https://img.shields.io/github/issues-raw/haise0/Kaidaros?logo=github)](#)


## Summary
Gaidaros was designed to be a fast and simple open-source vulnerability security scanner and penetration testing tool concentrated on Apache Web Servers. The tool follows the rule of pentesting checklist that automates the process of detecting and exploiting the target Web Server and its Web Applications' vulnerabilities, helping minimizing the time and effort of anyone looking forward to test the security of a particular web server, and finally providing well-designed afterward reports. It comes with a powerful detection engine, numerous niche features for the ultimate penetration tester.

Kaidaros is the evolution and continuation of this unfortunately not-well-known utility. As with any tools designed to aid penetration testers and security analysts, it is not intended as a replacement, but only as a 

## Features

- Reconnaissance
- Apache vulnerability parsing from version information
- Common web application vulnerability scanning
- OWASP's vulnerability scanner
- Post-scan report generation

## Installation

Kaidaros is a Python script so you need [Python](https://www.python.org/downloads/) to run this program
```bash
sudo apt install python3
```
Also, pip3 is needed for the essential python packages
```bash
sudo apt install python3-pip
```
Preferably, you can download Gaidaros by cloning the Git repository:
```bash
git clone https://github.com/haise0/Kaidaros.git 
```
Install the necessary pip3 requirements for the project
```bash
cd Gaidaros
pip install -r requirements.txt
```
Kaidaros should function out of the box with Python version 3.x on any platform. No OS-specific modules are currently in use, although it is worth mentioning that the original project was intended for use on linux-based operating systems. Development is currently based on Ubuntu 20.10 and Arch linux on kernel 5.10, with python 3.9 and 3.10.

## Usage

Using help command for a list of usage
```bash
sudo python kaidaros.py -h
```
Supply with your own apikeys in order to use some modules
```bash
nano ./conf/keys.json
```
To generate reports, you'll need the `python-docx` pip package. 
```bash
pip install python-docx
```

## Roadmap
- [] Add optional shodan information gathering options for IPs and domains
- [] more here 
- 
## Todo
- [] Add to roadmap
- [] Fix having to run script as sudo



