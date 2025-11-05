# selenium-abuser

A security testing tool for detecting and exploiting misconfigured Selenium Grid/Node instances to access cloud metadata endpoints.

## ⚠️ Legal Notice

**This tool is intended for authorized security testing only.** Use this tool only on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

## Description

This tool detects whether a Selenium Grid instance is running on AWS or Google Cloud Platform, then attempts to access cloud metadata endpoints through the browser automation interface. This can reveal:

**AWS:**
- IAM role credentials (AccessKeyId, SecretAccessKey, Token)
- SSH public keys
- User data scripts

**Google Cloud:**
- SSH public keys

## Requirements

Python 3.6 or higher is required.

### Installation

```bash
pip3 install selenium requests urllib3
```

Or install from requirements file:
```bash
pip3 install -r requirements.txt
```

Note: You'll also need Chrome/Chromium WebDriver accessible to Selenium.

## Usage

### Test a single URL

```bash
python3 sel.py -u http://myserver:5555
```

### Test multiple URLs from a file

```bash
python3 sel.py -f targets.txt
```

The file should contain one URL per line. Lines starting with `#` are treated as comments and ignored.

### Command-line Options

```
-u, --url URL      Target Selenium Grid URL (default: http://localhost)
-f, --file FILE    File containing list of URLs to test
```

## Output

Successful targets with SSH keys are logged to `output/server.txt`.

### Example Output

```
[*] Testing: http://myserver:5555 [*]

[*] Amazon Host found
  {"ip":"1.2.3.4","hostname":"ec2-1-2-3-4.compute.amazonaws.com",...} [*]

[*] IAM Role Name: AmazonLightsailInstanceRole [*]
[*] IAM Role Key: {
  "Code" : "Success",
  "LastUpdated" : "2018-02-15T11:00:18Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA...",
  "SecretAccessKey" : "...",
  "Token" : "...",
  "Expiration" : "2018-07-15T17:13:56Z"
}
[*]

[*] AWS Public SSH Key:
  ssh-rsa AAAAB3NzaC1... LightsailDefaultKeyPair
[*]

[*] User Data:
#!/bin/bash
echo "Hello World"
[*]
```

## How It Works

1. The tool connects to the Selenium Grid endpoint
2. Uses Selenium to navigate to `ipinfo.io` to detect cloud provider
3. If AWS or GCP is detected, attempts to access metadata endpoints:
   - AWS: `http://169.254.169.254/latest/meta-data/`
   - GCP: `http://metadata.google.internal/computeMetadata/v1beta1/`
4. Extracts and displays available metadata

## Security Considerations

- This tool demonstrates SSRF (Server-Side Request Forgery) vulnerabilities in exposed Selenium Grid instances
- Always ensure Selenium Grid is properly secured and not exposed to untrusted networks
- Use authentication and network segmentation to protect Selenium Grid deployments
- Consider using IMDSv2 on AWS which requires headers that cannot be set through this attack vector

## Author

@random_robbie

## License

This is free and unencumbered software released into the public domain. See LICENSE for details.
