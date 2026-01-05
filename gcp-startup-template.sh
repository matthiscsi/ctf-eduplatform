#!/usr/bin/env bash
# GCE startup script (Debian/Ubuntu). Clones a repo and starts Docker Compose.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

log(){ echo "[startup] $*"; }

wait_for_dpkg(){
  local tries=30
  local sleep_s=2
  for i in $(seq 1 $tries); do
    if fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
       fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
       fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
      log "apt/dpkg lock present, waiting ($i/${tries})..."
      sleep $sleep_s
    else
      return 0
    fi
  done
  log "Warning: apt locks persisted; proceeding anyway"
}

apt_retry(){
  local cmd=("$@")
  local attempts=5
  for n in $(seq 1 $attempts); do
    wait_for_dpkg
    if "${cmd[@]}"; then
      return 0
    fi
    log "Attempt $n failed for: ${cmd[*]}";
    dpkg --configure -a || true
    apt-get -f install -y || true
    sleep 3
  done
  log "ERROR: All attempts failed for: ${cmd[*]}"; return 1
}

# Ensure git has a HOME for global config and credential store during metadata execution
export HOME=/root

# --- BEGIN USER SETTINGS ---
REPO_URL=""  # or GitHub URL
GIT_USERNAME=""  # optional: oauth2 for PATs or token username for deploy tokens
GIT_TOKEN=""     # optional: read-only token; prefer public repo if possible
APP_DIR="/opt/ctf-suite"
# --- END USER SETTINGS ---

log "Stage: initial dpkg recovery"
dpkg --configure -a || true
apt-get -f install -y || true

# Unconditionally purge problematic Anthos/Cloud CLI packages if present (not needed for CTF stack)
if dpkg -l | awk '/google-cloud-cli-anthoscli/ {print $2}' | grep -q 'google-cloud-cli-anthoscli'; then
  log "Purging google-cloud-cli-anthoscli (not required)"
  apt-get purge -y google-cloud-cli-anthoscli || true
fi
if dpkg -l | awk '/google-cloud-cli / {print $2}' | grep -q 'google-cloud-cli'; then
  log "Purging google-cloud-cli (not required)"
  apt-get purge -y google-cloud-cli || true
fi
dpkg --configure -a || true

log "Stage: base package update/install"
apt_retry apt-get update -y
apt_retry apt-get install -y git curl ca-certificates gnupg lsb-release iptables

# Install Docker from Docker's official repo
. /etc/os-release
ARCH="$(dpkg --print-architecture)"
CODENAME="${VERSION_CODENAME:-stable}"

install -m 0755 -d /etc/apt/keyrings
if [ "${ID:-}" = "debian" ]; then
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor --batch --yes -o /etc/apt/keyrings/docker.gpg
  fi
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
elif [ "${ID:-}" = "ubuntu" ]; then
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor --batch --yes -o /etc/apt/keyrings/docker.gpg
  fi
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
else
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor --batch --yes -o /etc/apt/keyrings/docker.gpg
  fi
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
fi

apt_retry apt-get update -y
apt_retry apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# Fallback: ensure docker compose exists even if plugin package was unavailable
if ! docker compose version >/dev/null 2>&1; then
  mkdir -p /usr/local/lib/docker/cli-plugins
  COMPOSE_VERSION="v2.29.2"
  curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${ARCH}" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi

# One-time tokenized clone to avoid persistent secrets on disk
CLONE_URL="$REPO_URL"
if [ -n "${GIT_TOKEN:-}" ]; then
  PROTO="$(echo "$REPO_URL" | awk -F '://' '{print $1}')"
  REST="$(echo "$REPO_URL" | sed -E 's#^[a-zA-Z]+://##')"
  # For GitLab PATs, 'oauth2' must be the username in HTTPS URLs
  CLONE_URL="${PROTO}://oauth2:${GIT_TOKEN}@${REST}"
fi

mkdir -p /opt
if [ ! -d "$APP_DIR/.git" ]; then
  git clone "$CLONE_URL" "$APP_DIR"
  # Sanitize remote to remove embedded credentials
  git -C "$APP_DIR" remote set-url origin "$REPO_URL"
else
  git -C "$APP_DIR" pull --ff-only
fi

cd "$APP_DIR"
docker compose up -d --build

# --- Diagnostics: show status, port bindings, and health checks ---
echo "[startup] Docker compose services status:" || true
docker compose ps || true

echo "[startup] Port inspection (host):" || true
docker ps --format '{{.Names}} -> {{.Ports}}' || true

check_port() {
  local name="$1"; local url="$2"; local retries=20; local wait=3
  echo "[startup] Checking ${name} at ${url}..." || true
  for i in $(seq 1 $retries); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "[startup] ${name} OK" || true
      return 0
    fi
    sleep "$wait"
  done
  echo "[startup] ${name} failed health check after $((retries*wait))s" || true
  return 1
}

check_port "login-sqli"  "http://127.0.0.1:8001/healthz" || docker compose logs --no-color --tail=200 login-sqli || true
check_port "jwt-weak"     "http://127.0.0.1:8002/healthz" || docker compose logs --no-color --tail=200 jwt-weak || true
check_port "static-secrets" "http://127.0.0.1:8003/healthz" || docker compose logs --no-color --tail=200 static-secrets || true
check_port "portal"       "http://127.0.0.1:8000/healthz" || docker compose logs --no-color --tail=200 portal || true
