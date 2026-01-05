# DIY CTF Suite (GCE-friendly)

A small, self-contained Capture The Flag (CTF) environment with beginner and medium web challenges, an advanced container breakout, and a central portal. Designed to run locally via Docker Desktop and deploy easily on Google Cloud Compute Engine (GCE) using the GUI.

> Strictly for learning in isolated environments. Do not expose to the public Internet without strong network isolation and rate limits.

IMPORTANT: On Google Cloud, you must allow network access to the ports you plan to use (HTTP/HTTPS and challenge ports 8001–8007 plus SSH 2222). See "Networking on GCP (Required)" below.

## What's inside

- Portal (port 80): links to all challenges
- login-sqli (port 8001): intentionally vulnerable login (SQL injection)
- jwt-weak (port 8002): weak HS256 secret; escalate role to admin
- static-secrets (port 8003): discover hidden files via robots.txt
- command-injection (port 8004): OS command injection via ping
- ssrf-internal (port 8005): SSRF to internal-only endpoints
- xxe-injection (port 8006): XML External Entity file read
- container-breakout (port 8007): SSRF to Docker Remote API (dind)
- brute-ssh (port 2222): weak SSH password

Each service exposes `/healthz` for quick checks. Flags are set via environment variables with safe defaults in `docker-compose.yml`.

## Networking on GCP (Required)

To reach your apps from your browser, configure VPC Firewall rules and instance tags.

1) During VM creation
- Check "Allow HTTP traffic" and "Allow HTTPS traffic". This attaches tags that match the default allow-http/https rules. These cover ports 80 and 443 only.

2) Create a firewall rule for challenge ports
- Console → VPC network → Firewall → Create firewall rule
- Name: `allow-ctf-ports`
- Direction: Ingress
- Targets: All instances in the network
- Source IPv4 ranges: your IP(s) or team CIDR (e.g., `203.0.113.10/32, 198.51.100.0/24`). Avoid `0.0.0.0/0` unless this is a throwaway lab.
- Protocols and ports: `tcp:80,443,8001-8007,2222`

After this, you can open:
- `http://35.210.32.202/` (portal)
- `http://35.210.32.202:8001` (login-sqli)
- `http://35.210.32.202:8002` (jwt-weak)
- `http://35.210.32.202:8003` (static-secrets)
- `http://35.210.32.202:8004` (command-injection)
- `http://35.210.32.202:8005` (ssrf-internal)
- `http://35.210.32.202:8006` (xxe-injection)
- `http://35.210.32.202:8007` (container-breakout)
- SSH: `ssh ctfuser@35.210.32.202 -p 2222` (brute-ssh)

Tip: If you prefer to expose only 80/443, place an Nginx reverse proxy in front and proxy to internal ports 8000–8003.

## Quick start (local)

Requirements:
- Docker Desktop (Windows/macOS/Linux)

Run:

```powershell
# In the ctf-suite folder
docker compose up -d --build

# Open the apps in your browser
# Portal:               http://localhost/
# Insecure Login:       http://localhost:8001
# Weak JWT:             http://localhost:8002
# Static Secrets:       http://localhost:8003
# Command Injection:    http://localhost:8004
# SSRF Internal:        http://localhost:8005
# XML XXE:              http://localhost:8006
# Container Breakout:   http://localhost:8007
# SSH (brute-ssh):      ssh ctfuser@localhost -p 2222
```

Stop and clean up:

```powershell
docker compose down -v
```

## Deploy to Google Cloud (GUI only)

There are two easy GUI-friendly flows. Pick one.

### Option A: Push this folder to your GitHub and auto-deploy via Startup Script

1) Create a new public or private GitHub repo, then push the contents of `ctf-suite/` to it.
2) In Google Cloud Console:
   - Compute Engine → VM instances → Create instance
   - Series: E2, Machine type: e2-micro or e2-small
   - Boot disk: Ubuntu LTS (e.g., 22.04)
  - Firewall: check “Allow HTTP” and “Allow HTTPS”
   - Management → Automation → Startup script: paste the script below (replace REPO_URL)

Startup script (paste as-is, change only REPO_URL):

```bash
#!/usr/bin/env bash
set -euxo pipefail

REPO_URL="https://github.com/yourname/your-ctf-repo.git"
APP_DIR="/opt/ctf-suite"

apt-get update -y
apt-get install -y git docker.io docker-compose-plugin
systemctl enable --now docker

mkdir -p /opt
if [ ! -d "$APP_DIR" ]; then
  git clone "$REPO_URL" "$APP_DIR"
else
  cd "$APP_DIR" && git pull --ff-only
fi

cd "$APP_DIR"
docker compose up -d --build
```

3) Networking: ensure VPC Firewall allows your access
  - Create a rule allowing `tcp:80,443,8001-8007,2222` with Targets: All instances in the network (see section above).
  - Then open the VM’s External IP on the relevant ports (80, 8001–8007, 2222).

### Option B: Upload a ZIP via browser SSH and run Docker Compose

1) Zip the folder on Windows (PowerShell):

```powershell
# From inside ctf-suite
Compress-Archive -Path * -DestinationPath ..\ctf-suite.zip -Force
```

2) In Google Cloud Console:
   - Compute Engine → VM instances → Create instance (same settings as Option A, no startup script)
   - Click SSH → “Open in browser window”
   - Use the SSH window’s “Upload file” button to upload `ctf-suite.zip` to your home directory

3) In the SSH window, run these minimal commands:

```bash
sudo apt-get update -y ; \
  sudo apt-get install -y unzip docker.io docker-compose-plugin ; \
  sudo systemctl enable --now docker ; \
  mkdir -p ~/ctf-suite && unzip -o ~/ctf-suite.zip -d ~/ctf-suite ; \
  cd ~/ctf-suite ; \
  sudo docker compose up -d --build
```

4) Networking: add a VPC Firewall rule with Targets: All instances in the network (see section above) and browse to the VM External IP on ports 8000–8003.

## Private GitLab (or GitHub) repos: cloning with a token

If your CTF repo is private on GitLab, the included `gcp-startup-template.sh` already supports secure cloning with a token using GCE instance metadata. You can use it either by pasting into the Startup Script box or via `--metadata-from-file`.

What you provide to the VM:

- Metadata `repo-url`: The HTTPS repository URL (e.g., `https://gitlab.com/yourgroup/your-repo.git`)
- Metadata `gitlab-token`: Your GitLab Personal Access Token (or a Deploy Token password)
- Metadata `gitlab-username` (optional): Defaults to `oauth2` for PATs; for Deploy Tokens use the given deploy token username

How it works under the hood:

- The startup script reads the above metadata, configures `git credential.helper store` for the repo host, and writes a single host-scoped entry to `/root/.git-credentials` (no token is printed to logs).
- It then runs `git clone "$repo-url" /opt/ctf-suite` and `docker compose up -d --build`.

Example using the gcloud CLI from PowerShell (Windows):

```powershell
# Adjust the values for your project, zone, repo and token
$Project    = "your-gcp-project"
$Zone       = "us-central1-a"
$Instance   = "ctf-vm"
$RepoUrl    = "https://gitlab.com/yourgroup/your-repo.git"
$GitlabPAT  = "<your-personal-access-token>"
$GitlabUser = "oauth2"  # or your deploy token username

gcloud config set project $Project
gcloud compute instances create $Instance `
  --zone $Zone `
  --machine-type e2-small `
  --tags http-server `
  --image-family ubuntu-2204-lts `
  --image-project ubuntu-os-cloud `
  --metadata "repo-url=$RepoUrl,gitlab-token=$GitlabPAT,gitlab-username=$GitlabUser" `
  --metadata-from-file startup-script=./gcp-startup-template.sh

# After a minute or two, browse to http://35.210.32.202/ (and 8001–8007); SSH on 2222
```

Security notes:

- Prefer using a short-lived token or a Deploy Token with read-only scope for the specific project.
- Metadata values are retrievable by any process on the VM; treat this VM as sensitive. Rotate tokens after use.
- The script avoids `set -x` while writing credentials to prevent leaking secrets in logs.

Windows VM variant (optional):

If you prefer a Windows Server VM, you can adapt the same idea in a startup PowerShell script that pulls metadata and writes Git credentials. Example snippet:

```powershell
$md = 'http://metadata.google.internal/computeMetadata/v1/instance/attributes'
$hdr = @{ 'Metadata-Flavor' = 'Google' }
try { $RepoUrl = (Invoke-RestMethod -Headers $hdr -Uri "$md/repo-url") } catch { $RepoUrl = 'https://gitlab.com/yourgroup/your-repo.git' }
try { $GitlabPAT = (Invoke-RestMethod -Headers $hdr -Uri "$md/gitlab-token") } catch { $GitlabPAT = '' }
try { $GitlabUser = (Invoke-RestMethod -Headers $hdr -Uri "$md/gitlab-username") } catch { $GitlabUser = 'oauth2' }

if ($GitlabPAT) {
  git config --global credential.helper store
  $host = ([Uri]$RepoUrl).Host
  $credLine = "https://$GitlabUser:$GitlabPAT@$host"
  $credPath = Join-Path $HOME ".git-credentials"
  Set-Content -Path $credPath -Value $credLine -NoNewline -Encoding UTF8
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  # Install Docker if your base image doesn't have it; steps vary by image/OS version.
}

# Clone and run compose (requires Docker Desktop/Engine on Windows)
New-Item -ItemType Directory -Path C:\ctf-suite -Force | Out-Null
git clone $RepoUrl C:\ctf-suite
# docker compose -f C:\ctf-suite\docker-compose.yml up -d --build
```

Note: Windows containers/compose setup differs from Linux; for simplicity, Ubuntu VMs are recommended.

## Customizing flags

Edit `docker-compose.yml` and change the `FLAG` values per service. Redeploy (or `docker compose up -d --build`) to apply.

## Hardening tips (when you’re ready)

- Put services behind an HTTP reverse proxy (Nginx) and expose only ports you need
- Restrict firewall to your IP/team IP ranges
- Add a Cloud Armor policy if you expose to the internet
- Run on a private VPC and access via IAP or VPN
- Set Docker resource limits to avoid noisy neighbors

## Challenge hints (optional)

- login-sqli: classic boolean-based login bypass
- jwt-weak: inspect `/source`, recover secret, change role to admin, re-sign
- static-secrets: read `/robots.txt` then explore `/hidden/`

## License and disclaimer

Educational use only. You are responsible for how you deploy and expose these services.
