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
STEP_TOTAL=13
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
# /var/lib/dpkg/lock-frontend. Any apt-based install then dies with
# "Could not get lock ... held by process N (unattended-upgr)".
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
# (NodeSource, apt-get, add-apt-repository) so no step can block on a dialog.
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
# that silently stalls curl/git/apt/acme.sh and enrollment on long timeouts.
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
  # and carriage returns first (our script and some tools colour their output, and
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
# The stack targets Ubuntu LTS (distro nginx/MariaDB/Redis + the ondrej/php PPA).
OS_ID=$(. /etc/os-release 2>/dev/null; echo "${ID:-}:${VERSION_ID:-}")
case "$OS_ID" in
  ubuntu:22.04|ubuntu:24.04) ok "Ubuntu ${OS_ID#*:}" ;;
  *) die "Unsupported OS ($OS_ID). Use a fresh Ubuntu 22.04 or 24.04 server." ;;
esac
[ -d "$BIN_DIR" ] || die "$BIN_DIR does not exist."
for c in curl bash openssl sed systemctl ip awk hostname; do
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
# The web stack. wcloud manages it end to end (no control-panel layer in
# between): Ubuntu's own nginx / MariaDB / Redis packages get Ubuntu's security
# updates; PHP comes from the ondrej/php PPA so any offered version can sit side
# by side. Per-site pieces (system user, PHP pool, vhost, database, Redis user)
# are created by the agent — see src/lib/sites.js.
PHP_DEFAULT="8.3"
# Keep in sync with PHP_EXTS in src/lib/stack.js (it installs other versions on demand).
PHP_EXTS="fpm cli mysql curl gd intl mbstring xml zip bcmath soap imagick redis opcache"
APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=600)
apt_install() { apt_wait; apt-get "${APT_OPTS[@]}" install "$@" </dev/null; }

step "Installing Nginx, MariaDB and Redis"
apt_wait
apt-get -q -o DPkg::Lock::Timeout=600 update </dev/null >/dev/null || warn "apt-get update reported errors — continuing."
if apt_install nginx mariadb-server redis-server cron curl unzip git openssl ca-certificates logrotate software-properties-common; then
  ok "Packages installed."
else
  die "Installing the base packages failed — see the output above."
fi
systemctl enable --now nginx mariadb redis-server cron >/dev/null 2>&1 || true  # cron runs sites' scheduled jobs (/etc/cron.d)

# ------------------------------------------------------------
step "Installing PHP $PHP_DEFAULT"
if ! grep -rqs "ondrej/php" /etc/apt/sources.list /etc/apt/sources.list.d/; then
  info "Adding the PHP package repository (ppa:ondrej/php)..."
  apt_wait
  LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php </dev/null >/dev/null \
    || die "Could not add the PHP package repository (ppa:ondrej/php)."
fi
PHP_PKGS=(); for e in $PHP_EXTS; do PHP_PKGS+=("php$PHP_DEFAULT-$e"); done
apt_install "${PHP_PKGS[@]}" || die "Installing PHP $PHP_DEFAULT failed — see the output above."
# The package's `www` pool runs as www-data — the group that can read every
# site. Replace it with an inert placeholder (php-fpm won't start without a
# pool); sites get their own pools. Same as stack.js writePlaceholderPool.
cat > "/etc/php/$PHP_DEFAULT/fpm/pool.d/www.conf" <<EOF
; wcloud: placeholder so php-fpm starts with no sites. Site pools are <domain>.conf.
[www]
user = nobody
group = nogroup
listen = /run/php/php$PHP_DEFAULT-fpm.sock
listen.owner = root
listen.group = root
listen.mode = 0600
pm = ondemand
pm.max_children = 1
EOF
systemctl enable "php$PHP_DEFAULT-fpm" >/dev/null 2>&1
systemctl restart "php$PHP_DEFAULT-fpm" || die "php$PHP_DEFAULT-fpm failed to start — check journalctl -u php$PHP_DEFAULT-fpm."
ok "PHP $PHP_DEFAULT ready (other versions install on demand)."

# ------------------------------------------------------------
step "Installing WP-CLI"
if curl -4 -fsSL -o /usr/local/bin/wp.new https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
   && "php$PHP_DEFAULT" /usr/local/bin/wp.new --allow-root --version >/dev/null 2>&1; then
  chmod 755 /usr/local/bin/wp.new && mv -f /usr/local/bin/wp.new /usr/local/bin/wp
  ok "$("php$PHP_DEFAULT" /usr/local/bin/wp --allow-root --version 2>/dev/null)"
else
  rm -f /usr/local/bin/wp.new
  die "WP-CLI download failed."
fi

# ------------------------------------------------------------
step "Installing phpMyAdmin"
# One copy per server, served by each WordPress site at /.wcloud-pma/ through
# that SITE's own PHP pool and signed in with that site's own database login
# (see src/lib/pma.js) — it can only ever see that one site's database.
# There is no login form: the panel hands out single-use sign-in links.
# Latest release, checksum-verified; a re-run upgrades it.
PMA_DIR=/usr/share/wcloud-pma
PMA_VER=$(curl -4 -fsSL https://www.phpmyadmin.net/home_page/version.txt 2>/dev/null | head -n1)
if ! [[ "$PMA_VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  warn "Could not look up the latest phpMyAdmin version — skipping (re-run the installer later)."
  WARNINGS+=("phpMyAdmin not installed (version lookup failed).")
elif [ -f "$PMA_DIR-$PMA_VER/index.php" ]; then
  ok "phpMyAdmin $PMA_VER already installed."
else
  PMA_TMP=$(mktemp -d)
  PMA_TGZ="phpMyAdmin-$PMA_VER-english.tar.gz"
  PMA_URL="https://files.phpmyadmin.net/phpMyAdmin/$PMA_VER/$PMA_TGZ"
  if curl -4 -fsSL -o "$PMA_TMP/$PMA_TGZ" "$PMA_URL" \
     && curl -4 -fsSL -o "$PMA_TMP/$PMA_TGZ.sha256" "$PMA_URL.sha256" \
     && (cd "$PMA_TMP" && sha256sum -c "$PMA_TGZ.sha256" >/dev/null) \
     && tar xzf "$PMA_TMP/$PMA_TGZ" -C "$PMA_TMP"; then
    rm -rf "$PMA_DIR-$PMA_VER"
    mv "$PMA_TMP/phpMyAdmin-$PMA_VER-english" "$PMA_DIR-$PMA_VER"
    rm -rf "$PMA_DIR-$PMA_VER"/{setup,examples,test,doc} # not needed, and setup/ is a known target
    ok "phpMyAdmin $PMA_VER installed (checksum verified)."
  else
    warn "phpMyAdmin download or checksum check failed — skipping."
    WARNINGS+=("phpMyAdmin not installed (download/checksum failed).")
  fi
  rm -rf "$PMA_TMP"
fi
if [ -f "$PMA_DIR-$PMA_VER/index.php" ]; then
  # blowfish_secret: stable across upgrades. (Readable by site users — phpMyAdmin
  # runs as them — which is fine: signon auth keeps no credentials in cookies.)
  mkdir -p /etc/wcloud && chmod 700 /etc/wcloud
  [ -s /etc/wcloud/pma.secret ] || ( umask 077; openssl rand -hex 16 > /etc/wcloud/pma.secret )
  PMA_SECRET=$(cat /etc/wcloud/pma.secret)
  cat > "$PMA_DIR-$PMA_VER/config.inc.php" <<EOF
<?php
// Managed by wcloud (init.sh). phpMyAdmin runs in each site's own PHP pool.
declare(strict_types=1);
\$cfg['blowfish_secret'] = '$PMA_SECRET';
\$cfg['Servers'][1]['auth_type'] = 'signon';
\$cfg['Servers'][1]['SignonSession'] = 'WcloudPMA';
\$cfg['Servers'][1]['SignonURL'] = 'wcloud-signon.php';
\$cfg['Servers'][1]['LogoutURL'] = 'wcloud-signon.php?logout=1';
\$cfg['Servers'][1]['host'] = 'localhost';
\$cfg['Servers'][1]['AllowRoot'] = false;
\$cfg['Servers'][1]['AllowNoPassword'] = false;
// The pool points sys_temp_dir at the site's own tmp/.
\$cfg['TempDir'] = sys_get_temp_dir() . '/wcloud-pma-tmp';
if (!is_dir(\$cfg['TempDir'])) { @mkdir(\$cfg['TempDir'], 0700, true); }
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['VersionCheck'] = false;
\$cfg['SendErrorReports'] = 'never';
\$cfg['ShowCreateDb'] = false;
EOF
  cat > "$PMA_DIR-$PMA_VER/wcloud-signon.php" <<'EOF'
<?php
// wcloud: single-use sign-in to phpMyAdmin from the panel. The agent drops a
// token file (JSON: user, password, db, expires) in THIS site's own temp dir,
// named by the token's SHA-256; this redeems it once and hands the login to
// phpMyAdmin's signon session. No token → no way in (there is no login form).
declare(strict_types=1);
$fail = static function (string $msg): void {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    exit($msg);
};
if (isset($_GET['logout'])) {
    $fail('Signed out of phpMyAdmin. Open it again from your wcloud panel.');
}
$t = $_GET['t'] ?? '';
if (!is_string($t) || !preg_match('/^[a-f0-9]{64}$/', $t)) {
    $fail('Open phpMyAdmin from your wcloud panel.');
}
$file = sys_get_temp_dir() . '/wcloud-pma/' . hash('sha256', $t);
$raw = @file_get_contents($file);
@unlink($file); // single use, even when expired
$d = $raw ? json_decode($raw, true) : null;
if (!is_array($d) || ($d['expires'] ?? 0) < time()) {
    $fail('This phpMyAdmin link has expired or was already used. Open a new one from your wcloud panel.');
}
session_name('WcloudPMA');
session_set_cookie_params(['path' => rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/', 'httponly' => true, 'samesite' => 'Lax', 'secure' => !empty($_SERVER['HTTPS'])]);
session_start();
session_regenerate_id(true);
$_SESSION['PMA_single_signon_user'] = (string) $d['user'];
$_SESSION['PMA_single_signon_password'] = (string) $d['password'];
$_SESSION['PMA_single_signon_host'] = 'localhost';
session_write_close();
header('Location: index.php' . (!empty($d['db']) ? '?route=/database/structure&db=' . rawurlencode((string) $d['db']) : ''));
EOF
  chown -R root:root "$PMA_DIR-$PMA_VER"
  chmod -R u=rwX,go=rX "$PMA_DIR-$PMA_VER"
  ln -sfn "$PMA_DIR-$PMA_VER" "$PMA_DIR"   # atomic switch; old versions are left for rollback
fi

# ------------------------------------------------------------
step "Installing acme.sh (Let's Encrypt)"
# Same layout the agent expects (src/lib/acme.js). --install also adds the
# daily renewal cron job.
ACME_HOME=/etc/letsencrypt
if [ -x "$ACME_HOME/acme.sh" ]; then
  ok "acme.sh already installed."
else
  ACME_SRC=$(mktemp -d)
  if git clone -q --depth 1 https://github.com/acmesh-official/acme.sh.git "$ACME_SRC" \
     && (cd "$ACME_SRC" && ./acme.sh --install --home "$ACME_HOME" --config-home "$ACME_HOME/config" \
          --cert-home "$ACME_HOME/renewal" --noprofile >/dev/null); then
    ok "acme.sh installed."
  else
    rm -rf "$ACME_SRC"
    die "acme.sh install failed."
  fi
  rm -rf "$ACME_SRC"
fi
"$ACME_HOME/acme.sh" --config-home "$ACME_HOME/config" --set-default-ca --server letsencrypt >/dev/null 2>&1 \
  && ok "Default CA: Let's Encrypt" || warn "Could not set Let's Encrypt as the default CA."

# ------------------------------------------------------------
step "Configuring Nginx"
# We own nginx.conf outright (no merging with the distro's defaults, which
# would collide on ssl_protocols/gzip). Back up → write → nginx -t → restore
# on failure, so a re-run on a live server can't leave nginx broken.
NGX_BAK=$(mktemp -d)
cp -a /etc/nginx/nginx.conf "$NGX_BAK/" 2>/dev/null || true
[ -e /etc/nginx/sites-enabled/00-default.conf ] && cp -a /etc/nginx/sites-enabled/00-default.conf "$NGX_BAK/"

cat > /etc/nginx/nginx.conf <<'EOF'
# Managed by wcloud (init.sh). Sites live in sites-enabled/<domain>.conf.
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 4096;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;
    server_names_hash_bucket_size 128;
    server_names_hash_max_size 4096;
    client_max_body_size 512m;
    keepalive_timeout 65;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:20m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    access_log /var/log/nginx/access.log;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml application/rss+xml application/atom+xml image/svg+xml font/ttf font/otf;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Catch-all for unknown hosts: close the connection. A throwaway self-signed
# cert answers TLS for them (nginx on 22.04 predates ssl_reject_handshake).
mkdir -p /etc/nginx/ssl
if [ ! -s /etc/nginx/ssl/default.key ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -subj "/CN=invalid" \
    -keyout /etc/nginx/ssl/default.key -out /etc/nginx/ssl/default.crt >/dev/null 2>&1
  chmod 600 /etc/nginx/ssl/default.key
fi
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/sites-enabled/00-default.conf <<'EOF'
# Managed by wcloud (init.sh): requests for domains not hosted here.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location ^~ /.well-known/acme-challenge/ { root /var/www/html; default_type text/plain; try_files $uri =404; }
    location / { return 444; }
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    ssl_certificate     /etc/nginx/ssl/default.crt;
    ssl_certificate_key /etc/nginx/ssl/default.key;
    return 444;
}
EOF

# HTTP-01 challenges for every site are answered from here (root-owned: no
# site can write into it).
mkdir -p /var/www/html/.well-known/acme-challenge
chmod 755 /var/www /var/www/html /var/www/html/.well-known /var/www/html/.well-known/acme-challenge
rm -f /var/www/html/index.nginx-debian.html

# Per-site PHP error logs (written by each site's own user).
mkdir -p /var/log/wcloud && chmod 755 /var/log/wcloud
cat > /etc/logrotate.d/wcloud <<'EOF'
/var/log/wcloud/*.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

if nginx -t; then
  systemctl reload nginx || systemctl restart nginx || die "nginx failed to (re)start."
  rm -rf "$NGX_BAK"
  ok "Nginx configured (unknown domains are refused, ACME challenges allowed)."
else
  cp -a "$NGX_BAK/nginx.conf" /etc/nginx/nginx.conf 2>/dev/null
  if [ -e "$NGX_BAK/00-default.conf" ]; then cp -a "$NGX_BAK/00-default.conf" /etc/nginx/sites-enabled/; else rm -f /etc/nginx/sites-enabled/00-default.conf; fi
  rm -rf "$NGX_BAK"
  die "The nginx configuration failed its test — previous files restored. See the output above."
fi

# ------------------------------------------------------------
step "Configuring MariaDB and Redis"
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
BUF_MB=$(( MEM_MB / 4 )); [ "$BUF_MB" -lt 128 ] && BUF_MB=128
cat > /etc/mysql/mariadb.conf.d/60-wcloud.cnf <<EOF
# Managed by wcloud (init.sh): sized for this server's ${MEM_MB} MB of RAM.
[mysqld]
innodb_buffer_pool_size = ${BUF_MB}M
max_connections = 300
EOF
systemctl restart mariadb || die "MariaDB failed to start — check journalctl -u mariadb."
# The agent manages databases as root over the unix socket (Ubuntu default).
mysql -e 'SELECT 1' >/dev/null 2>&1 || die "MariaDB is not accepting root connections over its socket."
ok "MariaDB ready (buffer pool ${BUF_MB} MB)."

# Redis: the passwordless default user is turned off; each site gets its own
# login confined to its key prefix (src/lib/stack.js). The agent's admin
# password is root-only.
mkdir -p /etc/wcloud && chmod 700 /etc/wcloud
if [ ! -s /etc/wcloud/redis-admin.pass ]; then
  ( umask 077; openssl rand -hex 24 > /etc/wcloud/redis-admin.pass )
fi
REDIS_ACL=/etc/redis/users.acl
if [ ! -s "$REDIS_ACL" ]; then
  REDIS_HASH=$(tr -d '\n' < /etc/wcloud/redis-admin.pass | sha256sum | cut -d' ' -f1)
  printf 'user default off\nuser wcloud on #%s ~* +@all\n' "$REDIS_HASH" > "$REDIS_ACL"
  chown redis:redis "$REDIS_ACL" && chmod 640 "$REDIS_ACL"
fi
grep -q '^aclfile ' /etc/redis/redis.conf || echo "aclfile $REDIS_ACL" >> /etc/redis/redis.conf
# One database per site (REDIS_DBS in src/lib/stack.js); empty ones cost ~nothing.
sed -i -E 's/^databases [0-9]+/databases 1024/' /etc/redis/redis.conf
grep -q '^databases ' /etc/redis/redis.conf || echo 'databases 1024' >> /etc/redis/redis.conf
systemctl restart redis-server || die "Redis failed to start — check journalctl -u redis-server."
if REDISCLI_AUTH="$(cat /etc/wcloud/redis-admin.pass)" redis-cli --user wcloud --no-auth-warning ping 2>/dev/null | grep -q PONG; then
  ok "Redis ready (per-site logins)."
else
  warn "Redis is running but the admin login failed — sites will run without an object cache."
  WARNINGS+=("Redis admin login failed — object cache unavailable.")
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
# The agent's TLS certificate. Self-signed on purpose: the portal pins its
# fingerprint when the agent enrolls, which is stronger than trusting any CA and
# needs no domain. Kept across re-runs — a new certificate would break the pin
# (re-enrolling, e.g. with a fresh install command, re-pins it).
mkdir -p /etc/wcloud && chmod 700 /etc/wcloud
if [ ! -s /etc/wcloud/agent.key ] || [ ! -s /etc/wcloud/agent.crt ]; then
  if ( umask 077; openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 \
         -subj "/CN=wcloud-agent $(hostname)" -keyout /etc/wcloud/agent.key -out /etc/wcloud/agent.crt ) >/dev/null 2>&1; then
    ok "Agent TLS certificate created (pinned by the portal at enrollment)"
  else
    warn "Could not create the agent TLS certificate — the agent will serve plain HTTP."
    WARNINGS+=("No agent TLS certificate — portal traffic to this server is unencrypted.")
  fi
else
  ok "Agent TLS certificate kept"
fi
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
[ -f /opt/wcloud/wcloud.service ] \
  || die "/opt/wcloud/wcloud.service not found — cannot deploy agent unit."
# Sanity-check it's actually a systemd unit, not stray file content
if ! grep -q '^\[Service\]' /opt/wcloud/wcloud.service \
   || ! grep -q '^ExecStart=' /opt/wcloud/wcloud.service; then
  die "wcloud.service is not a valid systemd unit (missing [Service]/ExecStart) — fix the file in the repo."
fi
# Always install the repo's unit: re-runs pick up sandboxing changes.
cp "/opt/wcloud/wcloud.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable wcloud.service >/dev/null 2>&1
if systemctl restart wcloud.service; then
  ok "wcloud service started"
else
  warn "wcloud failed to start — check journalctl -u wcloud."
  WARNINGS+=("wcloud.service failed to start.")
fi

# apt_wait paused the apt timers for the install; security updates resume now.
systemctl start apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------
echo
if [ "${#WARNINGS[@]}" -eq 0 ]; then
  banner "$C_GREEN" "${G_OK} Server initialization complete" \
    "Nginx, PHP $PHP_DEFAULT, MariaDB, Redis installed" \
    "WP-CLI + acme.sh (Let's Encrypt) ready" \
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
printf '     %s%s Add a site from the wcloud dashboard%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
printf '     %s%s Check the agent service: systemctl status wcloud%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
echo