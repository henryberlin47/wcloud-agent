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

# Fresh cloud images run unattended-upgrades / apt-daily on first boot, which hold
# /var/lib/dpkg/lock-frontend. Any apt-based install (WordOps, `wo stack install`)
# then dies with "Could not get lock ... held by process N (unattended-upgr)".
# Stop those timers/services so they can't re-grab the lock during provisioning,
# then wait for any in-flight run to release it. Call before every apt step.
# Lock holders via fuser (psmisc); minimal images may lack it, so fall back to
# the apt/dpkg process names rather than silently treating the lock as free.
apt_busy() {
  if command -v fuser >/dev/null 2>&1; then
    fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1
  else
    pgrep -x '(apt|apt-get|dpkg|unattended-upgr)' >/dev/null 2>&1
  fi
}
apt_wait() {
  systemctl stop apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  systemctl stop apt-daily.service apt-daily-upgrade.service unattended-upgrades.service >/dev/null 2>&1 || true
  local waited=0
  while apt_busy; do
    if [ "$waited" -ge 300 ]; then
      warn "dpkg/apt lock still held after 5m — proceeding anyway."
      break
    fi
    [ "$waited" -eq 0 ] && info "Background apt (unattended-upgrades) is running; waiting for the dpkg lock..."
    sleep 5; waited=$((waited + 5))
  done
}

# ============================================================
#  Root check (must come AFTER helpers — err/C_DIM are used here)
# ============================================================
if [[ $EUID -ne 0 ]]; then
  err "Please run this script as root."
  printf '\n   Example:\n     %ssudo %s%s\n' "$C_DIM" "$0" "$C_RESET"
  exit 1
fi

# Non-interactive apt for the whole run. Under `curl | bash`, any apt operation
# that draws a TUI prompt hangs provisioning forever — most notably Ubuntu's
# needrestart popping a "Pending kernel upgrade" / service-restart dialog after
# NodeSource's prereq install. These exports are inherited by every child
# (WordOps, NodeSource, apt-get) so no step can block on a dialog.
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a       # auto-restart services, never ask
export NEEDRESTART_SUSPEND=1    # belt-and-suspenders: disable needrestart prompts

# The normal (non-root) user that should own the GitHub SSH key. When the script
# is run via sudo, $SUDO_USER is that user. Falls back to a detected login user.
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
  TARGET_USER="$(logname 2>/dev/null || echo root)"
fi

# ------------------------------------------------------------
# Prefer IPv4 for everything. Fresh VPS images often ship a broken/unrouted IPv6
# that silently stalls curl/git/apt/wo/acme.sh and enrollment on long timeouts.
# gai.conf makes the whole system prefer IPv4 (covers every glibc-based tool);
# explicit `-4` on our own fetches below is belt-and-suspenders.
if ! grep -qs '^precedence ::ffff:0:0/96  100' /etc/gai.conf 2>/dev/null; then
  printf '\n# wcloud: prefer IPv4 (broken IPv6 on fresh VPS stalls installs)\nprecedence ::ffff:0:0/96  100\n' >> /etc/gai.conf
fi

# ------------------------------------------------------------
# Portal provisioning stream (optional). When the install command supplies a
# PROVISION_ID, mirror all output + step milestones to the portal so the user can
# watch this install live. Best-effort — it must never break the install.
# The command is reusable across servers, so each run mints its own provision id
# (the portal creates the record on first log). Keeps every server's progress on
# its own card.
PROVISION_ID="${PROVISION_ID:-}"
if [ -z "$PROVISION_ID" ] && [ -n "${ENROLL_URL:-}" ]; then
  PROVISION_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "prov-$(openssl rand -hex 8)")
fi
PORTAL_ORIGIN=""
PROVISION_LOG=""
UPLOADER_PID=""

if [ -n "$PROVISION_ID" ] && [ -n "${ENROLL_URL:-}" ] && [ -n "${ENROLL_TOKEN:-}" ] && command -v curl >/dev/null 2>&1; then
  PORTAL_ORIGIN=$(printf '%s' "$ENROLL_URL" | sed -E 's#/api/enroll/?$##')
  PROVISION_NAME=$(hostname 2>/dev/null || echo server)

  # The enroll token goes in a header FILE (mktemp → 0600), never on curl's
  # argv where any local user could read it from `ps` for its 60-minute life.
  AUTH_HDR=$(mktemp)
  printf 'Authorization: Bearer %s\n' "$ENROLL_TOKEN" > "$AUTH_HDR"

  # Real milestone poster (replaces the early no-op stub).
  provision_event() { # $1=status $2=step $3=step_no $4=step_total
    [ -n "$PORTAL_ORIGIN" ] || return 0
    curl -4 -fsS -m 8 -X POST "$PORTAL_ORIGIN/api/provision/$PROVISION_ID/log" \
      -H @"$AUTH_HDR" -H "X-Name: $PROVISION_NAME" \
      ${1:+-H "X-Status: $1"} ${2:+-H "X-Step: $2"} ${3:+-H "X-Step-No: $3"} ${4:+-H "X-Step-Total: $4"} \
      >/dev/null 2>&1 || true
  }

  PROVISION_LOG=$(mktemp)
  ESC=$(printf '\033')
  # Ship new log bytes to the portal every few seconds. Strip ANSI colour codes
  # and carriage returns first (our script AND WordOps colour their output, and
  # `curl | bash` leaves stdout a tty) so the portal shows clean text.
  ( off=0
    while true; do
      sz=$(wc -c < "$PROVISION_LOG" 2>/dev/null || echo 0)
      if [ "${sz:-0}" -gt "$off" ]; then
        # Send exactly bytes (off, sz] — the file keeps growing while we read,
        # and sending past sz then advancing to sz would re-send that tail.
        if tail -c +$((off + 1)) "$PROVISION_LOG" 2>/dev/null | head -c $((sz - off)) \
             | sed "s/${ESC}\[[0-9;?]*[A-Za-z]//g" | tr -d '\r' \
             | curl -4 -fsS -m 8 -X POST "$PORTAL_ORIGIN/api/provision/$PROVISION_ID/log" \
                 -H @"$AUTH_HDR" -H 'Content-Type: text/plain' \
                 --data-binary @- >/dev/null 2>&1; then
          off=$sz
        fi
      fi
      sleep 3
    done ) &
  UPLOADER_PID=$!

  # Mirror stdout+stderr into that file (console still shows everything).
  exec > >(tee -a "$PROVISION_LOG") 2>&1
  # On exit: let the final chunk flush, stop the uploader, and remove the local
  # log copy + header file (install output and the enroll token).
  trap 'sleep 4; [ -n "$UPLOADER_PID" ] && kill "$UPLOADER_PID" 2>/dev/null; rm -f "$PROVISION_LOG" "$AUTH_HDR"; :' EXIT
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
  apt_wait # first apt call of the run — a fresh box's unattended-upgrades holds the lock
  apt-get update -qq </dev/null && apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold git </dev/null \
    || die "Could not install git (needed to fetch the agent)."
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

apt_wait
if command -v wo >/dev/null 2>&1; then
  ok "WordOps already installed ($(wo --version 2>/dev/null | head -n1 || echo present)) — skipping."
else
  info "Downloading WordOps installer (wops.cc)..."
  # https explicitly: a bare `wops.cc` makes wget start with plain http (then
  # follow the 301) — an unauthenticated hop that could swap the root installer.
  if wget -4 -qO /tmp/wo-install https://wops.cc && bash /tmp/wo-install </dev/null; then
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
# The base stack (nginx/php/mysql) is mandatory: without it every later step
# cascades into "nginx: command not found". `wo stack install` returns 0 when the
# stack is already present, so a non-zero here is a genuine failure, not "already
# installed" — treat it as fatal and surface WordOps' own log (the portal's
# provision stream can't see the box, so its "check the log" is otherwise useless).
apt_wait
# </dev/null on every child that might read stdin: under `curl | bash`, bash
# reads THIS script from stdin as it goes, so a prompting child would swallow
# the rest of the script (or hang) instead of getting EOF.
if wo stack install </dev/null; then
  ok "Base stack installed."
else
  err "wo stack install failed — last lines of /var/log/wo/wordops.log:"
  tail -n 30 /var/log/wo/wordops.log 2>/dev/null || true
  die "WordOps base stack install failed — see the log above (common causes: unsupported OS release/arch, apt repo/lock, no disk)."
fi

# ------------------------------------------------------------
step "Installing Redis stack"
# Redis is the object cache — non-essential, so a redis-only failure warns rather
# than aborts, but we still surface its log tail so it's diagnosable.
if wo stack install --redis </dev/null; then
  ok "Redis stack installed."
else
  warn "wo stack install --redis returned non-zero — last lines of /var/log/wo/wordops.log:"
  tail -n 20 /var/log/wo/wordops.log 2>/dev/null || true
  WARNINGS+=("wo stack install --redis returned non-zero — verify Redis manually.")
fi

# ------------------------------------------------------------
step "Securing default Nginx vhost"

info "Writing default catch-all vhost..."
# Same contract as the agent's nginx edits: back up, write, `nginx -t`, and
# restore on failure — a broken default vhost would make every later `nginx -t`
# (so every SSL/canonical op) fail on this box.
DEFAULT_VHOST=/etc/nginx/sites-available/default
DEFAULT_BAK=""
if [ -f "$DEFAULT_VHOST" ]; then
  DEFAULT_BAK="$DEFAULT_VHOST.wcloud-bak"
  cp -p "$DEFAULT_VHOST" "$DEFAULT_BAK"
fi
DEFAULT_LINKED=0
cat >"$DEFAULT_VHOST" <<'EOF'
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
  ln -s "$DEFAULT_VHOST" /etc/nginx/sites-enabled/default && DEFAULT_LINKED=1
fi

info "Preparing ACME challenge directory..."
mkdir -p /var/www/html/.well-known/acme-challenge
chown -R www-data:www-data /var/www/html/.well-known
chmod -R 755 /var/www/html/.well-known

info "Testing Nginx configuration..."
if nginx -t; then
  [ -n "$DEFAULT_BAK" ] && rm -f "$DEFAULT_BAK"
  if systemctl reload nginx; then
    ok "Default catch-all installed (unknown domains -> 403, ACME allowed)."
  else
    warn "nginx reload failed."
    WARNINGS+=("nginx reload failed after installing default vhost.")
  fi
else
  if [ -n "$DEFAULT_BAK" ]; then mv -f "$DEFAULT_BAK" "$DEFAULT_VHOST"; else rm -f "$DEFAULT_VHOST"; fi
  [ "$DEFAULT_LINKED" = 1 ] && rm -f /etc/nginx/sites-enabled/default
  warn "nginx -t failed — the previous default vhost was restored and nothing was reloaded."
  WARNINGS+=("nginx -t failed for the default catch-all vhost (reverted; unknown domains are not blocked).")
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
  apt_wait
  if curl -4 -fsSL https://deb.nodesource.com/setup_22.x -o /tmp/nodesource_setup.sh \
     && bash /tmp/nodesource_setup.sh </dev/null \
     && apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold nodejs </dev/null; then
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
# (No rclone step: Spaces backup/restore now talks S3 directly from the agent
# via the AWS SDK, installed with the agent's npm dependencies below.)

# ------------------------------------------------------------
step "Generating agent configuration"
# Canonical location — .env in the agent's working directory so both
# systemd EnvironmentFile= and dotenv (require('dotenv').config()) find it.
AGENT_CONFIG="/opt/wcloud/.env"

if [ -f "$AGENT_CONFIG" ] && [ "${FORCE_REGEN_ENV:-0}" != "1" ]; then
  ok "Agent configuration already exists at $AGENT_CONFIG — keeping its token."
  info "Re-run with FORCE_REGEN_ENV=1 to regenerate."
  # A re-run from the portal carries a fresh enroll token + provision id. Write
  # them and drop the .enrolled marker so the restarted agent re-enrolls with
  # THIS run's id — otherwise it skips enrollment (or retries with the expired
  # old token) and this run's provisioning card never completes. Re-enrolling is
  # an idempotent upsert on the portal side.
  if [ -n "${ENROLL_TOKEN:-}" ]; then
    # Replace the key, or append it (a .env from before enrollment lacks it).
    set_env() { grep -q "^$1=" "$AGENT_CONFIG" && sed -i "s|^$1=.*|$1=$2|" "$AGENT_CONFIG" || echo "$1=$2" >> "$AGENT_CONFIG"; }
    [ -n "${ENROLL_URL:-}" ]   && set_env PORTAL_ENROLL_URL "$ENROLL_URL"
    set_env ENROLL_TOKEN "$ENROLL_TOKEN"
    [ -n "${PROVISION_ID:-}" ] && set_env PROVISION_ID "$PROVISION_ID"
    rm -f /opt/wcloud/.enrolled
    ok "Enrollment refreshed for this run"
  fi
else
  # A regenerated AGENT_TOKEN is useless to the portal until it re-enrolls.
  rm -f /opt/wcloud/.enrolled
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

  # Allowlist = only the portal may reach this root agent. This must be the
  # portal's EGRESS IP (what the agent sees). Behind Cloudflare/any proxy that is
  # NOT what the portal's domain resolves to, so it's passed in explicitly as
  # ALLOWED_IPS (the portal bakes in PORTAL_EGRESS_IPS); fall back to the known
  # panel IP. Comma-separated for multi-homed.
  PORTAL_IP="${ALLOWED_IPS:-91.108.105.205}"

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
  # Never print AGENT_TOKEN: all stdout is streamed into the portal's provision
  # log (stored in Mongo). The agent delivers it to the portal via enrollment.
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