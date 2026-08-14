#!/bin/bash
set -uo pipefail
# Note: NOT using `set -e` — some steps (already-installed stacks, non-fatal
# setup) can return non-zero and we want to continue with a warning instead of
# aborting the whole bootstrap.

BIN_DIR="/usr/local/bin"

# ============================================================
#  UI helpers
# ============================================================
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "1" ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
  C_BLUE=$'\e[34m'; C_CYAN=$'\e[36m'; C_GREY=$'\e[90m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''
  C_RED=''; C_GREEN=''; C_YELLOW=''
  C_BLUE=''; C_CYAN=''; C_GREY=''
fi

if [[ "${LANG:-}${LC_ALL:-}" == *UTF-8* || "${LANG:-}${LC_ALL:-}" == *utf8* ]]; then
  G_OK="✓"; G_ERR="✗"; G_WARN="⚠"; G_ARROW="➜"; G_DOT="•"
  BOX_TL="╭"; BOX_TR="╮"; BOX_BL="╰"; BOX_BR="╯"; BOX_H="─"; BOX_V="│"
else
  G_OK="+"; G_ERR="x"; G_WARN="!"; G_ARROW=">"; G_DOT="*"
  BOX_TL="+"; BOX_TR="+"; BOX_BL="+"; BOX_BR="+"; BOX_H="-"; BOX_V="|"
fi

BOX_WIDTH=60
STEP_NO=0
STEP_TOTAL=14
WARNINGS=()

_repeat() { local n=$1 ch=$2 out=''; while ((n-- > 0)); do out+="$ch"; done; printf '%s' "$out"; }

# $1 = accent color, $2 = title, $3.. = body lines
banner() {
  local accent="$1"; shift
  local title="$1"; shift
  local line
  printf '%s%s%s%s%s\n' "$accent" "$BOX_TL" "$(_repeat "$BOX_WIDTH" "$BOX_H")" "$BOX_TR" "$C_RESET"
  printf '%s%s%s %s%-*s%s %s%s\n' \
    "$accent" "$BOX_V" "$C_RESET" \
    "$C_BOLD" $((BOX_WIDTH - 2)) "$title" "$C_RESET" \
    "$accent$BOX_V" "$C_RESET"
  for line in "$@"; do
    printf '%s%s%s %-*s %s%s\n' \
      "$accent" "$BOX_V" "$C_RESET" \
      $((BOX_WIDTH - 2)) "$line" \
      "$accent$BOX_V" "$C_RESET"
  done
  printf '%s%s%s%s%s\n' "$accent" "$BOX_BL" "$(_repeat "$BOX_WIDTH" "$BOX_H")" "$BOX_BR" "$C_RESET"
}

step() {
  STEP_NO=$((STEP_NO + 1))
  printf '\n%s%s[%d/%d]%s %s%s%s\n' \
    "$C_BOLD" "$C_BLUE" "$STEP_NO" "$STEP_TOTAL" "$C_RESET" \
    "$C_BOLD" "$1" "$C_RESET"
  provision_event running "$1" "$STEP_NO" "$STEP_TOTAL"
}

info()  { printf '   %s%s%s %s\n' "$C_GREY" "$G_DOT" "$C_RESET" "$1"; }
ok()    { printf '   %s%s%s %s\n' "$C_GREEN" "$G_OK" "$C_RESET" "$1"; }
warn()  { printf '   %s%s%s %s\n' "$C_YELLOW" "$G_WARN" "$C_RESET" "$1"; }
err()   { printf '   %s%s%s %s\n' "$C_RED" "$G_ERR" "$C_RESET" "$1" >&2; }

die() { err "$1"; provision_event failed "$1" "$STEP_NO" "$STEP_TOTAL"; exit "${2:-1}"; }

# Post a provision milestone/status to the portal. Redefined with real behaviour
# below once we know we're provisioning; this stub keeps early calls safe.
provision_event() { :; }

run() {
  local label="$1"; shift
  local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  [[ "$G_OK" == "+" ]] && frames='|/-\'
  local tmp; tmp="$(mktemp)"
  ( "$@" >"$tmp" 2>&1 ) &
  local pid=$! i=0
  if [[ -t 1 ]]; then
    while kill -0 "$pid" 2>/dev/null; do
      local f="${frames:i++%${#frames}:1}"
      printf '\r   %s%s%s %s' "$C_CYAN" "$f" "$C_RESET" "$label"
      sleep 0.1
    done
    printf '\r\033[K'
  fi
  if wait "$pid"; then
    ok "$label"; rm -f "$tmp"; return 0
  else
    err "$label"
    [[ -s "$tmp" ]] && sed 's/^/     /' "$tmp" | tail -n 15 >&2
    rm -f "$tmp"; return 1
  fi
}

# ============================================================
#  Root check (must come AFTER helpers — err/C_DIM are used here)
# ============================================================
if [[ $EUID -ne 0 ]]; then
  err "Please run this script as root."
  printf '\n   Example:\n     %ssudo %s%s\n' "$C_DIM" "$0" "$C_RESET"
  exit 1
fi

# The normal (non-root) user that should own the GitHub SSH key. When the script
# is run via sudo, $SUDO_USER is that user. Falls back to a detected login user.
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
  TARGET_USER="$(logname 2>/dev/null || echo root)"
fi

# ------------------------------------------------------------
# Portal provisioning stream (optional). When the install command supplies a
# PROVISION_ID, mirror all output + step milestones to the portal so the user can
# watch this install live. Best-effort — it must never break the install.
PROVISION_ID="${PROVISION_ID:-}"
PORTAL_ORIGIN=""
PROVISION_LOG=""
UPLOADER_PID=""

if [ -n "$PROVISION_ID" ] && [ -n "${ENROLL_URL:-}" ] && [ -n "${ENROLL_TOKEN:-}" ] && command -v curl >/dev/null 2>&1; then
  PORTAL_ORIGIN=$(printf '%s' "$ENROLL_URL" | sed -E 's#/api/enroll/?$##')

  # Real milestone poster (replaces the early no-op stub).
  provision_event() { # $1=status $2=step $3=step_no $4=step_total
    [ -n "$PORTAL_ORIGIN" ] || return 0
    curl -fsS -m 8 -X POST "$PORTAL_ORIGIN/api/provision/$PROVISION_ID/log" \
      -H "Authorization: Bearer $ENROLL_TOKEN" \
      ${1:+-H "X-Status: $1"} ${2:+-H "X-Step: $2"} ${3:+-H "X-Step-No: $3"} ${4:+-H "X-Step-Total: $4"} \
      >/dev/null 2>&1 || true
  }

  PROVISION_LOG=$(mktemp)
  # Ship new log bytes to the portal every few seconds (text body, no escaping).
  ( off=0
    while true; do
      sz=$(wc -c < "$PROVISION_LOG" 2>/dev/null || echo 0)
      if [ "${sz:-0}" -gt "$off" ]; then
        if tail -c +$((off + 1)) "$PROVISION_LOG" 2>/dev/null | \
             curl -fsS -m 8 -X POST "$PORTAL_ORIGIN/api/provision/$PROVISION_ID/log" \
               -H "Authorization: Bearer $ENROLL_TOKEN" -H 'Content-Type: text/plain' \
               --data-binary @- >/dev/null 2>&1; then
          off=$sz
        fi
      fi
      sleep 3
    done ) &
  UPLOADER_PID=$!

  # Mirror stdout+stderr into that file (console still shows everything).
  exec > >(tee -a "$PROVISION_LOG") 2>&1
  # On exit: let the final chunk flush, then stop the uploader.
  trap 'sleep 4; [ -n "$UPLOADER_PID" ] && kill "$UPLOADER_PID" 2>/dev/null; :' EXIT
  provision_event running "Starting install" 0 "$STEP_TOTAL"
fi

# ------------------------------------------------------------
step "Preflight checks"
[ -d "$BIN_DIR" ] || die "$BIN_DIR does not exist."
for c in wget bash openssl sed systemctl ip awk hostname; do
  command -v "$c" >/dev/null 2>&1 && ok "$c present" || die "Required command missing: $c"
done

# ------------------------------------------------------------
step "Fetching agent source"
# When run via `curl … | bash`, the repo isn't on disk yet — clone it. On a
# re-run of an existing git checkout, fast-forward instead.
REPO="${REPO:-https://github.com/henryberlin47/wcloud-agent.git}"
if ! command -v git >/dev/null 2>&1; then
  info "Installing git..."
  apt-get update -qq && apt-get install -y -qq git || die "Could not install git (needed to fetch the agent)."
fi
if [ -d /opt/wcloud/.git ]; then
  info "Updating existing agent checkout..."
  git -C /opt/wcloud pull --ff-only || warn "git pull failed — using the existing checkout."
elif [ -f /opt/wcloud/src/server.js ]; then
  ok "Agent already present at /opt/wcloud (non-git) — skipping clone."
else
  info "Cloning $REPO -> /opt/wcloud ..."
  git clone --depth 1 "$REPO" /opt/wcloud || die "git clone failed."
fi
ok "Agent source ready at /opt/wcloud."

# ------------------------------------------------------------
step "Installing WordOps"
# WordOps prompts for a git name/email (to save server configs) on install AND on
# every `wo` invocation until one is set. Under `curl | bash` there's no TTY, so
# its read loops forever. Seed a random identity up front — unconditionally, so it
# also covers a half-installed `wo` left by an interrupted earlier run.
GIT_RAND=$(openssl rand -hex 4)
git config --global user.name  >/dev/null 2>&1 || git config --global user.name  "wcloud-$GIT_RAND"
git config --global user.email >/dev/null 2>&1 || git config --global user.email "wcloud-$GIT_RAND@wcloud.local"

if command -v wo >/dev/null 2>&1; then
  ok "WordOps already installed ($(wo --version 2>/dev/null | head -n1 || echo present)) — skipping."
else
  info "Downloading WordOps installer (wops.cc)..."
  if wget -qO /tmp/wo-install wops.cc && bash /tmp/wo-install </dev/null; then
    ok "WordOps installed."
  else
    rm -f /tmp/wo-install
    die "WordOps install failed — cannot continue without it."
  fi
  rm -f /tmp/wo-install
fi

# Make sure wo is on PATH for the rest of this script (installer adds it, but
# the current shell may not have picked it up yet).
if ! command -v wo >/dev/null 2>&1; then
  export PATH="$PATH:/usr/local/bin"
fi
command -v wo >/dev/null 2>&1 || die "wo not found on PATH after install."

# ------------------------------------------------------------
step "Installing WordOps stack"
if wo stack install; then
  ok "Base stack installed."
else
  warn "wo stack install returned non-zero (may already be installed)."
  WARNINGS+=("wo stack install returned non-zero — verify base stack manually.")
fi

# ------------------------------------------------------------
step "Installing Redis stack"
if wo stack install --redis; then
  ok "Redis stack installed."
else
  warn "wo stack install --redis returned non-zero (may already be installed)."
  WARNINGS+=("wo stack install --redis returned non-zero — verify Redis manually.")
fi

# ------------------------------------------------------------
step "Securing default Nginx vhost"

info "Writing default catch-all vhost..."
cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    root /var/www/html;

    # Allow Let's Encrypt HTTP-01 challenge
    location ^~ /.well-known/acme-challenge/ {
        allow all;
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        return 403;
    }
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;

    server_name _;

    root /var/www/html;

    ssl_certificate     /var/www/22222/cert/22222.crt;
    ssl_certificate_key /var/www/22222/cert/22222.key;

    # Allow Let's Encrypt HTTP-01 challenge
    location ^~ /.well-known/acme-challenge/ {
        allow all;
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        return 403;
    }
}
EOF

# Ensure the vhost is actually enabled (WordOps normally symlinks it, but be safe).
if [ ! -e /etc/nginx/sites-enabled/default ]; then
  ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
fi

info "Preparing ACME challenge directory..."
mkdir -p /var/www/html/.well-known/acme-challenge
chown -R www-data:www-data /var/www/html/.well-known
chmod -R 755 /var/www/html/.well-known

info "Testing Nginx configuration..."
if nginx -t; then
  if systemctl reload nginx; then
    ok "Default catch-all installed (unknown domains -> 403, ACME allowed)."
  else
    warn "nginx reload failed."
    WARNINGS+=("nginx reload failed after installing default vhost.")
  fi
else
  warn "nginx -t failed — default vhost NOT reloaded. Fix config manually."
  WARNINGS+=("nginx -t failed for the default catch-all vhost.")
fi

# ============================================================
# PHP-FPM Tuning for WordOps (dynamic version detection)
# ============================================================
# Detect highest installed PHP version under /etc/php (e.g., 8.4, 8.3)
PHP_VERSION=$(ls /etc/php 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$' | sort -V | tail -n 1)
if [ -z "$PHP_VERSION" ]; then
  PHP_VERSION="8.3"
fi
PHP_INI="/etc/php/$PHP_VERSION/fpm/php.ini"
POOL_CONF="/etc/php/$PHP_VERSION/fpm/pool.d/www.conf"

banner "$C_CYAN" "PHP-FPM $PHP_VERSION Tuning (WordOps)" \
  "php.ini : $PHP_INI" \
  "pool    : $POOL_CONF"

# ------------------------------------------------------------
step "Checking PHP config files"
[ -f "$PHP_INI" ]   || die "PHP-FPM php.ini not found: $PHP_INI"
ok "Found php.ini"
[ -f "$POOL_CONF" ] || die "PHP-FPM pool config not found: $POOL_CONF"
ok "Found pool config"

# Sets `key = value`, uncommenting/replacing an existing line or appending.
set_ini_value() {
  local file="$1" key="$2" value="$3"
  if grep -qE "^[;[:space:]]*$key[[:space:]]*=" "$file"; then
    sed -i -E "s|^[;[:space:]]*$key[[:space:]]*=.*|$key = $value|" "$file"
  else
    echo "$key = $value" >> "$file"
  fi
  info "$(printf '%-24s = %s' "$key" "$value")"
}

# ------------------------------------------------------------
step "Tuning php.ini"
set_ini_value "$PHP_INI" "max_execution_time"     "600"
set_ini_value "$PHP_INI" "max_input_time"         "600"
set_ini_value "$PHP_INI" "max_input_vars"         "3000"
set_ini_value "$PHP_INI" "memory_limit"           "512M"
set_ini_value "$PHP_INI" "post_max_size"          "512M"
set_ini_value "$PHP_INI" "upload_max_filesize"    "512M"
set_ini_value "$PHP_INI" "session.gc_maxlifetime" "1440"
ok "php.ini tuned (7 directives)"

# ------------------------------------------------------------
step "Tuning PHP-FPM pool"
set_ini_value "$POOL_CONF" "pm.start_servers"     "12"
set_ini_value "$POOL_CONF" "pm.min_spare_servers" "8"
set_ini_value "$POOL_CONF" "pm.max_spare_servers" "16"
set_ini_value "$POOL_CONF" "pm.max_children"      "30"
set_ini_value "$POOL_CONF" "pm.max_requests"      "500"
ok "Pool tuned (5 directives)"

# ------------------------------------------------------------
step "Restarting & verifying PHP-FPM"
if run "restart php$PHP_VERSION-fpm" systemctl restart "php$PHP_VERSION-fpm"; then
  echo
  info "Effective values:"
  "php-fpm$PHP_VERSION" -i 2>/dev/null \
    | grep -E "max_execution_time|max_input_time|max_input_vars|memory_limit|post_max_size|upload_max_filesize|session.gc_maxlifetime" \
    | sed 's/^/     /'
else
  WARNINGS+=("php$PHP_VERSION-fpm failed to restart — check journalctl -u php$PHP_VERSION-fpm.")
fi

# ------------------------------------------------------------
step "Installing Node.js"
# The wcloud is a Node.js service — node MUST be present before deploying it.
if command -v node >/dev/null 2>&1; then
  ok "Node.js already installed ($(node --version 2>/dev/null))"
else
  info "Node.js not found — installing Node.js 22.x LTS via NodeSource..."
  if curl -fsSL https://deb.nodesource.com/setup_22.x -o /tmp/nodesource_setup.sh \
     && bash /tmp/nodesource_setup.sh \
     && apt-get install -y nodejs; then
    rm -f /tmp/nodesource_setup.sh
    ok "Node.js installed ($(node --version 2>/dev/null))"
  else
    rm -f /tmp/nodesource_setup.sh
    die "Node.js installation failed — cannot deploy wcloud without it."
  fi
fi
# npm sanity check (some minimal images split it out)
command -v npm >/dev/null 2>&1 && ok "npm present ($(npm --version 2>/dev/null))" \
  || { warn "npm not found — agent dependency installs may fail."; WARNINGS+=("npm missing after Node.js install."); }

# ------------------------------------------------------------
step "Generating agent configuration"
# Canonical location — .env in the agent's working directory so both
# systemd EnvironmentFile= and dotenv (require('dotenv').config()) find it.
AGENT_CONFIG="/opt/wcloud/.env"

if [ -f "$AGENT_CONFIG" ] && [ "${FORCE_REGEN_ENV:-0}" != "1" ]; then
  ok "Agent configuration already exists at $AGENT_CONFIG — skipping."
  info "Re-run with FORCE_REGEN_ENV=1 to regenerate."
else
  [ -f /opt/wcloud/.env.example ] \
    || die "/opt/wcloud/.env.example not found — is the agent repo deployed to /opt/wcloud?"

  info "Generating agent configuration from example..."

  # Copy the example file to create base config
  cp "/opt/wcloud/.env.example" "$AGENT_CONFIG"
  chmod 600 "$AGENT_CONFIG"

  # Generate a secure random token (64 hex characters)
  AGENT_TOKEN=$(openssl rand -hex 32)

  # Get the server's primary IP locally (no external API call).
  # `ip route get` returns the source IP used for outbound traffic — on a VPS
  # with the public IP bound directly to the NIC, this IS the public IP.
  SERVER_IP=$(ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  [ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

  if [ -z "$SERVER_IP" ]; then
    warn "Could not determine server IP, using default loopback"
    WARNINGS+=("IP detection failed — AGENT_HOST left as 127.0.0.1; fix $AGENT_CONFIG manually.")
    SERVER_IP="127.0.0.1"
  elif [[ "$SERVER_IP" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
    warn "Detected IP $SERVER_IP is private (server may be behind NAT)."
    WARNINGS+=("AGENT_HOST=$SERVER_IP is a private address — verify it's reachable by the control panel.")
  fi

  # Allowlist = only the portal may reach this root agent. Derive its IP from the
  # enroll URL host when provided; otherwise fall back to the known panel IP.
  # ponytail: uses the portal's *ingress* IP — override AGENT_ALLOWED_IPS if the
  # portal's egress differs (multi-homed / behind a separate NAT).
  PORTAL_IP="91.108.105.205"
  if [ -n "${ENROLL_URL:-}" ]; then
    PORTAL_HOST=$(printf '%s' "$ENROLL_URL" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##')
    RESOLVED=$(getent hosts "$PORTAL_HOST" 2>/dev/null | awk '{print $1; exit}')
    [ -n "$RESOLVED" ] && PORTAL_IP="$RESOLVED"
  fi

  # Replace placeholder values in the config file
  sed -i "s|^AGENT_TOKEN=.*|AGENT_TOKEN=$AGENT_TOKEN|" "$AGENT_CONFIG"
  sed -i "s|^AGENT_HOST=.*|AGENT_HOST=$SERVER_IP|" "$AGENT_CONFIG"
  sed -i "s|^AGENT_ALLOWED_IPS=.*|AGENT_ALLOWED_IPS=$PORTAL_IP|" "$AGENT_CONFIG"
  sed -i "s|^AGENT_SERVER_NAME=.*|AGENT_SERVER_NAME=$(hostname)|" "$AGENT_CONFIG"

  # Portal enrollment (passed in by the portal's install command). Lets the agent
  # self-register on startup instead of a manual "add server" form.
  [ -n "${ENROLL_URL:-}" ]   && sed -i "s|^PORTAL_ENROLL_URL=.*|PORTAL_ENROLL_URL=$ENROLL_URL|" "$AGENT_CONFIG"
  [ -n "${ENROLL_TOKEN:-}" ] && sed -i "s|^ENROLL_TOKEN=.*|ENROLL_TOKEN=$ENROLL_TOKEN|" "$AGENT_CONFIG"
  [ -n "${PROVISION_ID:-}" ] && sed -i "s|^PROVISION_ID=.*|PROVISION_ID=$PROVISION_ID|" "$AGENT_CONFIG"

  # Verify the injections actually landed (guards against a changed .env.example)
  grep -q "^AGENT_TOKEN=$AGENT_TOKEN$" "$AGENT_CONFIG" \
    || die "Token injection failed — AGENT_TOKEN key missing in .env.example?"
  grep -q "^AGENT_HOST=$SERVER_IP$" "$AGENT_CONFIG" \
    || die "Host injection failed — AGENT_HOST key missing in .env.example?"
  grep -q "^AGENT_ALLOWED_IPS=$PORTAL_IP$" "$AGENT_CONFIG" \
    || die "Allowlist injection failed — AGENT_ALLOWED_IPS key missing in .env.example?"

  # Verify no unfilled placeholders remain (empty required values)
  for key in AGENT_TOKEN AGENT_HOST AGENT_ALLOWED_IPS; do
    val=$(grep -E "^${key}=" "$AGENT_CONFIG" | head -n1 | cut -d= -f2-)
    [ -n "$val" ] || warn "$key is empty in $AGENT_CONFIG"
  done

  ok "Agent configuration created at $AGENT_CONFIG"
  info "Generated token: $AGENT_TOKEN"
  info "Server IP: $SERVER_IP"
  info "Control panel IP: $PORTAL_IP"
fi

# ------------------------------------------------------------
step "Installing agent dependencies"
[ -d /opt/wcloud ] || die "/opt/wcloud not found — deploy the agent repo first."
if [ -f /opt/wcloud/package.json ]; then
  if run "npm install (production) in /opt/wcloud" \
       npm install --omit=dev --no-audit --no-fund --prefix /opt/wcloud; then
    :
  else
    die "npm install failed — agent cannot start without its dependencies."
  fi
else
  warn "No package.json in /opt/wcloud — skipping npm install."
  WARNINGS+=("package.json missing in /opt/wcloud — agent deps not installed.")
fi

# ------------------------------------------------------------
step "Deploying wcloud service"
if [ -f "/etc/systemd/system/wcloud.service" ]; then
  ok "wcloud service already deployed"
  systemctl daemon-reload
  if systemctl restart wcloud.service; then
    ok "wcloud service restarted"
  else
    warn "wcloud restart failed — check journalctl -u wcloud."
    WARNINGS+=("wcloud.service failed to restart.")
  fi
else
  [ -f /opt/wcloud/wcloud.service ] \
    || die "/opt/wcloud/wcloud.service not found — cannot deploy agent unit."
  # Sanity-check it's actually a systemd unit, not stray file content
  if ! grep -q '^\[Service\]' /opt/wcloud/wcloud.service \
     || ! grep -q '^ExecStart=' /opt/wcloud/wcloud.service; then
    die "wcloud.service is not a valid systemd unit (missing [Service]/ExecStart) — fix the file in the repo."
  fi
  cp "/opt/wcloud/wcloud.service" /etc/systemd/system/
  systemctl daemon-reload
  if systemctl enable --now wcloud.service; then
    ok "wcloud service started"
  else
    warn "wcloud failed to start — check journalctl -u wcloud."
    WARNINGS+=("wcloud.service failed to start.")
  fi
fi

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------
echo
if [ "${#WARNINGS[@]}" -eq 0 ]; then
  banner "$C_GREEN" "${G_OK} Server initialization complete" \
    "WordOps + Redis installed" \
    "Nginx default secured, PHP tuned" \
    "Node.js installed, agent configured & started"
else
  banner "$C_YELLOW" "${G_WARN} Initialized with ${#WARNINGS[@]} warning(s)" \
    "Review the items below before deploying."
  echo
  for w in "${WARNINGS[@]}"; do
    printf '     %s%s%s %s\n' "$C_YELLOW" "$G_ARROW" "$C_RESET" "$w"
  done
fi

echo
printf '   %sNext steps:%s\n' "$C_BOLD" "$C_RESET"
printf '     %s%s Deploy a WordPress site: wo site create <domain> --wp%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
printf '     %s%s Check the agent service: systemctl status wcloud%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
echo