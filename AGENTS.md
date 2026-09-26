# Project Context — wcloud (agent)

> Read this before touching code. House style: minimal — prefer deleting to
> adding, stdlib to dependencies, one line to fifty. This agent runs as **root**
> on production servers; correctness and safety beat cleverness.

---

## 1. What this is

The per-server half of **wcloud** (a WordPress multi-site manager). The control
panel (`wcloud-portal`, a separate repo) never touches servers directly — it calls
this **agent** over HTTP with a bearer token. The agent is the only thing that runs
privileged commands (nginx, php-fpm, MariaDB, systemctl, wp-cli, acme.sh). It
**owns the web stack**: `init.sh` installs it, and every per-site piece (system
user, PHP-FPM pool, nginx vhost, database, Redis login, certificate) is created
and rendered by the agent from one spec file per site (§6). There is no WordOps
or other panel underneath. See `wcloud-portal/AGENTS.md`
for the portal side and the full two-repo picture.

A small Express app. Returns a **job ID** immediately for operations and streams
**live logs** over SSE. Node 18+, ESM (`"type": "module"`).

## Codebase map (optional)

A graphify knowledge graph of the whole workspace (portal + agent) is at
`../graphify-out/`. `GRAPH_REPORT.md` there lists the god nodes (most-connected
functions), how the code clusters, and cross-repo links — handy for "what
connects to X / how does this flow work". It's a snapshot: rebuild with
`/graphify --update` after significant changes, and treat **this file (AGENTS.md)
as the source of truth for writing code** — the graph is only a map.

---

## 2. Request lifecycle

`src/server.js` is the whole HTTP surface.

- `GET /healthz` — liveness, **no auth, skips the IP allowlist**. Returns
  `{ ok, server, version, time }`.
- Everything else goes through `requireAuth` (`src/auth.js`), which enforces, **in
  order**: (1) IP allowlist — 403 `ip_not_allowed` if the caller IP isn't in
  `AGENT_ALLOWED_IPS`; (2) bearer token — 401 if missing/wrong. The order matters:
  the allowlist must contain the portal's *egress* IP or every `/api/*` call 403s
  while `/healthz` still succeeds (looks "online" but details fail).
- `GET /api/info` — system info (memory, disk, CPU load, software stack, OS/kernel,
  uptime) + `version` + supported operations. `php` is every installed version
  with its FPM status; `phpOffered`/`phpDefault` say what a site can pick. Gathered by shelling out; each probe
  can carry a `timeout` (see §5) so a hanging tool can't stall the whole response.
- `GET /api/sites` — `{ server, count, sites: [domain], details: [publicSpec] }`,
  read from the site specs (`/etc/wcloud/sites/*.json`).
- `GET /api/sites/:domain` — the site's settings (`publicSpec`: `type`, `php`,
  `enableWww`, `canonical`, `ssl`, `created_at`). 404 = not a site here. All
  `/api/sites/:domain/*` routes resolve the spec first (`siteParam`).
- **File manager** — `GET /api/sites/:domain/files?path=` (list),
  `GET …/files/content?path=` (raw bytes), `PUT …/files/content?path=` (raw
  `application/octet-stream` body → the file, atomic replace, ≤512 MB),
  `POST …/files/op` (`mkdir` | `rename` | `move` | `copy` | `delete`). Paths are
  relative to the site's `htdocs`. Every call spawns **`src/fm-worker.js` as the
  site's user** (uid/gid + clean env, `lib/files.js`) — the agent itself never
  touches site files for the file manager: it is root, and a site-planted
  symlink would turn "read this file" into "read any file". The worker also
  confines paths lexically (`path.resolve` against `/`, so `..` can't climb and
  `/`, `''`, `.` are exactly the root, which can't be deleted/renamed).
- `POST /api/sites/:domain/wp-login` — **one-click login** (`lib/wplogin.js`):
  `{ url, user, expires_in }`, a single-use `wp-login.php?wcloud_login=<token>`
  link (2 min) for the first administrator. WordPress stores only the token's
  SHA-256 (a transient); the must-use plugin `mu-plugins/wcloud-login.php`
  (rewritten on every call, as the site user) deletes it before checking —
  single use even when invalid — then sets the auth cookie. The minting PHP
  goes to `wp eval-file -` on stdin, so the token never touches argv.
- `POST /api/sites/:domain/pma-login` — **one-click phpMyAdmin** (`lib/pma.js`):
  `{ url, db, https, expires_in }`. phpMyAdmin is installed ONCE per server by
  `init.sh` (latest release, SHA-256 verified, `setup/` etc. removed) at
  `/usr/share/wcloud-pma` → versioned dir, with `auth_type=signon` and our
  `wcloud-signon.php`. Each WordPress vhost serves it at `/.wcloud-pma/` through
  **that site's own PHP pool** (runs as the site user) and the link signs in
  with **that site's own DB login** (read live from wp-config) — it can see
  only that database. No login form: the agent writes a token file
  `{user,password,db,expires}` into the site's `tmp/wcloud-pma/` AS THE SITE
  USER (password on stdin), named by the token's SHA-256; the signon script
  deletes it before checking (single use), 2-minute expiry. `libraries/`,
  `templates/`, `vendor/`, `sql/` are denied by nginx. The call re-applies the
  site (older vhosts gain the location; no-op otherwise).
- **Plugins** (WordPress sites): `GET /api/sites/:domain/plugins` (live
  `wp plugin list`), `GET …/plugins/search?q=` (WordPress.org, from the server),
  `PUT …/plugins/upload` (raw .zip ≤100 MB → the site's PRIVATE `tmp/` as
  `wcloud-upload-<hex>.zip`, written by fm-worker as the site user — never
  web-reachable) → `{ upload }`. Changes are the **`plugin` op**
  (`operations/plugin.js`): `install` (WordPress.org `slug` or `upload`,
  `activate`, `replace` → `--force`; the zip is always removed), `activate`,
  `deactivate`, `update` (names or `all`), `delete` (= `wp plugin uninstall
  --deactivate`, i.e. WordPress's own Delete incl. the uninstall routine),
  `auto-update-on|off`. Plugin names are checked against `PLUGIN_NAME` (no
  leading `--` can reach wp-cli); all wp-cli runs as the site user.
- **Search engine visibility** (WordPress): `GET /api/sites/:domain/indexing`
  → `{ indexing }` (WordPress's `blog_public`, read live); the `indexing` op
  `{ domain, enabled }` sets it (same setting as Settings → Reading) and clears
  the page cache. The vhost sends `/robots.txt` to `index.php?robots=1`, so
  WordPress's virtual robots.txt works even on plain permalinks (where it would
  otherwise 301 to `/robots.txt/`).
- `GET /api/sites/:domain/credentials` — DB creds read **live** from `wp-config.php`.
  404 = not a readable WP site.
- `GET /api/sites/:domain/wp` — WordPress core version, read **live** via
  `wp core version` (`src/lib/wpinfo.js`). 404 = not a readable WP install.
- `GET /api/sites/:domain/ssl` — live SSL state, parsed **on demand** from the cert
  on disk (`/etc/letsencrypt/live/<domain>/fullchain.pem`): `{ enabled, source:
  none|letsencrypt|letsencrypt-manual|custom, auto_renew, issuer, subject, sans[],
   not_after, days_left, self_signed }`. Nothing is stored — the disk is the source
   of truth (see §3, ssl).
- `GET /api/sites/:domain/ssl-challenge` — the pending manual DNS-01 challenge for
   a site (`{ domain, pending, started_at?, txt_records? }`), read from the state
   file step 1 writes (`/var/lib/wcloud/ssl-challenge/<domain>.json`). `pending:
   false` when none. This is the **only** persistent per-site state (jobs die on
   restart); it exists so the two-step DNS flow survives page reloads and agent
   restarts. Cleared by the verify step, a hard verify failure, and site delete.
- `POST /api/op/:type` — validate + enqueue an operation → `{ jobId, state }`.
- `POST /api/self-update` — refuses (409) while any job is queued/running (the restart would cut it off) or another update runs; `git fetch origin` + `reset --hard origin/main` + `npm install` — an npm failure resets back to the previous commit (new code + old deps would crash-loop on the next restart); respond `{ ok, updated, old_commit, new_commit, version }`, then restart via a *systemd-run 2s timer* (detached — the timer outlives the process that gets SIGTERM'd). Origin/branch hardcoded: this runs remote code as root, no request body ever reaches a shell.
- `POST /api/backup-test`, `POST /api/backup-delete` — quick S3 calls against the Spaces creds passed **in the request body** (per user, per job). Creds live in the S3 client for one call only — never written to config, never logged. `backup-test` is a full round-trip: list (read), then write a tiny probe object and delete it. A read-only check passes on a Space the key can't write to, so the failure would otherwise surface only after a whole archive was built.
- `GET /api/jobs`, `/api/jobs/:id`, `/logs`, `/stream` (SSE), `POST /:id/cancel` —
  job status/logs/cancel. Jobs are **in-memory** (`src/jobs.js`), serialized
  (`AGENT_MAX_CONCURRENT=1`), forgotten ~1h after finishing.
- `GET /api/agent-log?lines=&q=` — the agent's own journal (`journalctl -u wcloud -o json`,
  `src/lib/agentlog.js`) → `{ entries: [{ time, level, message }], matched }`, filtered
  over the last 5000 entries. `jobs.js` writes one line per job start/finish there
  (`[job] <type> <domain> <state> in Ns: reason (id)`; failures on stderr) — the
  step-by-step log stays on the job.

### Transport security (TLS pinning) + sandbox

- The agent serves **HTTPS** with a self-signed EC certificate `init.sh` creates
  at `/etc/wcloud/agent.{crt,key}` (kept across re-runs). `config.tls` holds it
  plus its SHA-256 **fingerprint** and **SPKI pin**; both go to the portal in
  the enroll payload — over the *portal's* HTTPS, with the one-time enroll
  token — and the portal refuses any other certificate from then on. No
  cert files → plain HTTP with a loud warning (dev only).
- `publicUrl()` (config.js) is the one place the agent's own URL is built
  (enrollment, export download links).
- Server-to-server archive downloads (import `sourceUrl`) carry the source
  agent's `sourcePin`; curl checks it with `--pinnedpubkey` (`-k` only skips
  the CA chain — the pin is still enforced). No pin → normal CA verification,
  which a self-signed agent fails: never "accept anything".
- `wcloud.service` sandboxing (NoNewPrivileges, PrivateDevices, Protect*,
  ProtectHome + HOME=/var/lib/wcloud, …) is defence in depth, not a wall. **No
  `User=root` line**: with these options an explicit `User=root` makes systemd
  drop CAP_SETUID, and every run-as-site-user spawn fails with EPERM. `init.sh`
  always installs the repo's unit; self-update does not (re-run init.sh).

---

## 3. Operations

One file per op in `src/operations/*.js`, registered in `src/operations/index.js`.
Each descriptor has:

- `validate(params) -> { ok, errors[], clean }` — **the injection boundary**.
  Domains are normalized (`normDomain`: scheme stripped, lowercased) and checked
  against `DOMAIN_RE`. Never let unvalidated input reach a command.
- `run(job, helpers, clean)` — the work.

Current ops: **deploy** (`type` wordpress|static + `php` → `sites.createSite`, then HTTPS: Let's Encrypt via `issueSsl` (`acme.issueHttp`, or `acme.issueDnsCloudflare` when the portal passes `cfToken`+`cfZoneId` — Cloudflare-managed DNS, works behind the proxy), or the user's own `cert`+`key` — checked by `lib/certcheck.js` BEFORE the site is created, then installed with `applySslConf({certs})`), `searchEngines: false` (WordPress) sets `blog_public` 0 right after install — same setting as the **indexing** op,
**php** (switch a site's PHP version: installs it on demand, moves the pool),
**update** (`wp core update` + `update-db` + php-fpm reload), **delete** (custom
cron/procs/locks, then `sites.deleteSite`; requires `confirm:true`), **ssl** (mode-driven, below),
**sslDnsVerify** (step 2 of manual DNS-01, below),
**purge** (WP Rocket + object cache), **siteconfig** (`realIp`, `redirects`,
`domainRedirect`, `phpSettings`, `fpm` → spec → `applySite`; validated by
`sites.cleanRedirects` / `cleanDomainRedirect` / `phpsettings.cleanPhpSettings` / `cleanFpm`),
**nginxrule** (named custom nginx rules: save/delete via `lib/nginxrules.js`),
**cron** (a WordPress site's scheduled jobs: save/delete/run/wpcron, `lib/cron.js`),
**cfcache** (Cloudflare cache purge credentials + helper plugin, `lib/cfcache.js`),
**resetPassword** (`wp user update --user_pass`),
**export** (builds the archived site; `buildSiteArchive` in `export.js` is the shared
archive builder), **import** (restores an archive; `runRestoreFromLocal` in
`import.js` is the shared restore body — decrypt/extract/DB/SSL/canonical all live
there), **backup** (build archive via the shared helper + S3-upload to Spaces)
and **restore** (S3-download + the shared restore path; in-place restore first
runs the full **delete** op). backup/restore take the user's Spaces creds per call
in params and run with a longer per-op timeout (`AGENT_BACKUP_TIMEOUT_MS`, default
12h). No shells are used — args are arrays, so domain values can't inject shell
syntax.

**ssl — mode-driven (`{ domain, mode, cert?, key?, cfToken?, cfZoneId? }`)**, never "always issue":
- `off` — `spec.ssl = false` and re-apply: the vhost is rendered without the 443
  server, **the certs stay on disk** (turning HTTPS back on is instant).
- `le-http` — `acme.issueHttp`: acme.sh HTTP-01 via the shared webroot
  `/var/www/html` (every vhost serves `/.well-known/acme-challenge/` from it, even
  when redirecting to HTTPS), `--install-cert` with a `--reloadcmd` so acme.sh's
  cron renews in place. www is included when served; if www fails (no DNS yet)
  it retries for the bare domain.
- `le-dns-manual` — **step 1 of the two-step manual DNS-01 flow** (provider-
  independent, for domains behind Cloudflare/proxies where HTTP-01 can't reach
  the origin): `acme.sh --issue --dns -d D --force --yes-I-know...` prints the TXT
  records, saves the ACME order, exits 3. The op stores them in the challenge
  state file (§2) and returns `{ pending, txt_records }`; nothing on the box is
  changed yet. **Step 2** is the `sslDnsVerify` op — the user has added the TXT
  records at their DNS provider by then.
- `le-dns-cf` — DNS-01 through the **Cloudflare API** (`acme.issueDnsCloudflare`):
  works behind the orange cloud and renews itself. The portal sends the owner's
  token for the domain's zone + the zone id. acme.sh's `dns_cf` runs with them in
  env; its saved `SAVED_CF_*` copy is stripped from `account.conf` straight after,
  and the acme.sh domain entry is removed (`--remove`) so its cron never renews it
  with a token it no longer has. The agent keeps `{token, zoneId, www}` in
  `/etc/wcloud/cf-dns/<d>.json` (root 0600) and sets `spec.sslDns = 'cloudflare'`;
  `acme.startDnsRenewer` (every 12h) queues an `ssl-renew` job for such sites
  with ≤30 days left. Any other mode (or deleting the site) removes the token file.
  Live status: `source: letsencrypt-dns`, `auto_renew: true`.
- `custom` — pasted fullchain + key. **Validated before anything is written**: both
  parse as PEM, the key's public key equals the cert's (public-key compare — covers
  RSA/EC/Ed25519), and the cert's SAN covers the domain. A bad pair never touches
  disk. Then `applySslConf(helpers, domain, { certs })` — the cert pair joins the
  same backup → nginx -t → rollback transaction, so a chain nginx rejects restores
  the previous working cert (shared wiring, §5). `cert`/`key`
  arrive in the authenticated body only, the key is written `600 root:root`, and
  neither is ever logged or echoed (job views redact both).

**Manual DNS-01 state machine** — `src/lib/acme.js` owns it. acme.sh clears
`Le_Vlist` (the saved ACME order) after *every* verification attempt, and a lost
vlist means a new order = a new TXT the user must re-add. So the agent captures
the vlist at step 1 and **restores it into the domain conf before every verify**
— the same token stays valid for as long as propagation takes. `sslDnsVerify`
runs `acme.sh --renew -d D --force --yes-I-know...`: exit 0 → `--install-cert`
into `/etc/letsencrypt/live/<domain>/` (600 root:root) + `writeManualMarker` +
`applySslConf` + clear state; exit 3 → a fresh order was created, new TXT
records stored back in the state file; exit 1 with "DNS problem/NXDOMAIN" →
**soft fail** (the CA can't see the record yet — state + same TXT stay, the user
retries); any other failure → hard fail, state cleared. The resulting cert is
flagged by the `.wcloud-ssl-manual` marker → `source: letsencrypt-manual`,
`auto_renew: false` in the live status.

**Cert/nginx wiring** — all certs (LE, custom, manual-DNS) live at
`/etc/letsencrypt/live/<domain>/` (`fullchain.pem`, `key.pem`, `sites.certDir`).
`sites.applySslConf(helpers, domain, {certs?})` = `applySite` with `ssl: true`
(+ the cert pair joins the same transaction, §6). `src/lib/certinfo.js` reads
the live state: `enabled` = the spec's `ssl` flag, `source` from the issuer (a
`.wcloud-ssl-manual` marker flags non-renewing manual-DNS certs).

**Log format** — ops use `logger(helpers)` (`src/lib/log.js`). Commands are silent
on success and dump `$ cmd` + last 15 lines only on failure. Output reads like a
numbered script (`➜ 1. …` / `✓ …` / `✗ …`).

---

## 4. Self-enrollment & install streaming

Driven by env the portal's install command injects (`init.sh` writes them to
`.env`):

- `src/enroll.js` — on startup, if `PORTAL_ENROLL_URL` + `ENROLL_TOKEN` are set and
  the `.enrolled` marker is absent, POSTs `{ token, api_key, base_url, name,
  hostname, version, provision_id }` to the portal's `/api/enroll` (a few retries,
  best-effort — never blocks serving). Writes `.enrolled` on success so it enrolls
  once. To re-provision: delete `/opt/wcloud/.enrolled`.
- `init.sh` — the one-shot bootstrap the install command runs (Ubuntu 22.04 /
  24.04 only — checked in preflight). It: clones/pulls the repo to `/opt/wcloud`;
  installs the stack — distro nginx / MariaDB / Redis, PHP `DEFAULT_PHP` from
  the ondrej/php PPA (other versions are installed on demand by the agent),
  WP-CLI, acme.sh at `/etc/letsencrypt` with Let's Encrypt as default CA and its
  renewal cron; writes our own `nginx.conf` + a catch-all default vhost (unknown
  hosts get 444; self-signed cert for TLS), sizes MariaDB's buffer pool to RAM,
  turns Redis' passwordless default user off (ACL file + a root-only admin
  password in `/etc/wcloud/redis-admin.pass`, `databases 1024`); then Node + the
  agent. Writes `.env` (token, host, allowlist from `ALLOWED_IPS`, enroll vars)
  and **streams its own stdout** to the portal's `/api/provision/:pid/log` (ANSI
  stripped) with per-step milestones. Each run mints its own `PROVISION_ID`.
  Safe to re-run on a live server (config is backed up / kept, nginx changes are
  `nginx -t`-gated).

`config.version` is read from `package.json` at startup and surfaced in
`/healthz`, `/api/info`, and the enroll payload.

---

## 5. Key libraries (`src/lib/`)

- **sys.js** — the OS-touching core. `run(helpers, cmd, args, opts)` spawns without
  a shell, returns `{ code, stdout, stderr }`, never throws on non-zero. `opts`:
  `cwd, env, stdin, quiet, verbose, as` (`{uid, gid, home}` — run as a site user
  with a **clean env**, never the agent's), and **`timeout`** (kills and resolves
  `{code:-1}` — use it on probes that might hang). Also `userIds(name)`,
  `certCovers`, nginx/systemctl helpers.
- **wplogin.js** — one-click wp-admin login links (§2).
- **pma.js** — one-click phpMyAdmin links for a site's database (§2).
- **plugins.js** — plugin list + WordPress.org search (changes: the `plugin` op).
- **files.js** + **../fm-worker.js** — the file manager (§2): spawn the worker
  as the site user, collect its JSON / stream its output, map error codes.
- **sites.js** — the site model (§6): spec store (`readSpec`/`listSites`),
  `renderVhost`/`renderPool`, `applySite` (the transaction), `createSite`,
  `deleteSite`, `applySslConf`, `syncWpAddress`.
- **stack.js** — shared services: `PHP_VERSIONS`/`DEFAULT_PHP`, `ensurePhp`
  (apt install on demand), MariaDB `createDatabase`/`dropDatabase` (SQL on
  stdin), Redis `createRedisUser`/`dropRedisUser`.
- **wp.js** — WordPress on a site: `wpCli(helpers, spec)` (as the site user, with
  the site's PHP), `setupWordPress` (DB, Redis login, generated `wp-config.php`,
  core download + install), `pinWpUrls`, `clearWpCaches`, `readWpVersion`,
  `readDbCredentials` (live via `wp config get`; nothing stored).
- **acme.js** — Let's Encrypt via acme.sh: `issueHttp` (auto-renewing HTTP-01)
  and the manual DNS-01 two-step flow + its state file (see §3).
- **certinfo.js** — live SSL state (see §3 "ssl").
- **spaces.js** — DigitalOcean Spaces (S3) transfers via `@aws-sdk/client-s3`:
  `uploadFile` (multipart through lib-storage's `Upload`, so archives past S3's
  5GB single-PUT limit work), `downloadFile`, `putObject`, `deleteObject`,
  `listTopLevel`. **Nothing here creates the bucket** — the Space is pre-created
  by the user and a Spaces key usually can't create one; rclone's habit of
  calling CreateBucket when its HeadBucket failed used to kill every upload with
  a 403. The signing region is derived from the endpoint host
  (`nyc3.digitaloceanspaces.com` → `nyc3`), because SigV4 rejects a region that
  doesn't match the endpoint. `explainSpacesError` maps failures to actionable
  text and **walks nested errors** — a connection failure arrives as an
  `AggregateError` whose own message is just `"AggregateError"` (Node races IPv6
  and IPv4), so the real code lives in `.errors`/`.cause`.
- **certcheck.js** — `checkCustomCert(domain, cert, key, {www})`: in-memory (Node crypto) validation of a user certificate — PEM parses, key matches, `checkHost` covers the domain, not expired/not-yet-valid; www-coverage and self-signed are warnings. Shared by the ssl op (custom) and deploy. The portal runs the same rules (`server/utils/certcheck.ts`) for its live form check.
- **log.js** — the step logger used by operations.
- **wpcore.js** — `wordpressCore()`: the server's one copy of the latest
  WordPress (`/var/cache/wcloud-wp/wordpress-<v>.tar.gz`, root 0755/0644, newest 2
  kept), downloaded once per release and checked against wordpress.org's
  published SHA-1. Deploys unpack it AS the site user (`setupWordPress`); only
  the tiny version-check call goes out per deploy, and when wordpress.org is
  unreachable the newest cached copy is used. Never writable by a site (a shared
  wp-cli cache would let one site poison the next one's core). Any failure →
  `wp core download` as before. Self-check: `node src/lib/wpcore.js`.
- **sitelogs.js** — `readSiteLog(domain, access|error|php, {lines, q})`: the tail
  (last 4 MB window) of a site's log, filtered; opened `O_NOFOLLOW` (a symlinked
  log is refused, never read as root). `GET /api/sites/:d/logs`.
- **realip.js** — `/etc/nginx/wcloud/cloudflare-realip.conf` (`set_real_ip_from`
  for every Cloudflare range + `real_ip_header CF-Connecting-IP`), included by a
  vhost when `spec.realIp` (default on). Only Cloudflare's addresses are trusted,
  so the header can't be spoofed by a direct visitor. The built-in list is
  refreshed daily from cloudflare.com/ips-v4|v6 (validated CIDRs, `nginx -t`,
  restored on failure).
- **cron.js** — per-site jobs in `/etc/cron.d/wcloud-<domain_with_underscores>`
  (cron ignores names with dots), rendered from `spec.crons` / `spec.wpCron`
  by `applySite` (same transaction; PHP switch re-renders). Each line runs as
  the site user (user field is ours, never input), `cd htdocs`, PATH starts
  with `/usr/local/lib/wcloud/php<v>` (wrappers: `php`/`wp` → the site's PHP),
  HOME/WP_CLI_CACHE_DIR in the site's tmp, output appended to
  `/var/log/wcloud/<d>.cron.log` (Logs tab "cron"). `cleanJob`/`scheduleOk`
  are the boundary: 5 numeric fields or @hourly/@daily/@weekly/@monthly, one-line
  commands (a newline could add a root line), `%` escaped. "wpCron: server" =
  `DISABLE_WP_CRON` (`setWpConstant`) + `wp cron event run --due-now` every
  1/5/15 min. The cron op also `systemctl enable --now cron`. "Run now" runs
  the command exactly like cron and shows its output in the job log.
- **cfcache.js** — Cloudflare purges for a site. The PORTAL writes the zone's
  Cache Rules; the agent keeps `{token, zoneId, hosts}` in
  `/etc/wcloud/cf-cache/<d>.json` (root 0600) and purges by host
  (`purge_cache {hosts}`, 10 s debounce) — from the purge op (`only:
  'cloudflare'` = just that), the cfcache op, and the watcher.
  `CLOUDFLARE_API` env overrides the API base (tests).
- **nginxrules.js** — named custom nginx rules in `/var/www/<d>/conf/nginx/<id>.conf`
  (first line `# wcloud-name: <name>`; disabled = renamed `.conf.off`). Every
  save/delete is one transaction: write, `nginx -t`, restore the previous files
  on failure and throw nginx's own `[emerg]` line; success reloads nginx and
  clears the page cache. `GET /api/sites/:d/nginx-rules` lists them.

---

## 6. The site model (`src/lib/sites.js`) — read before touching a site

**`/etc/wcloud/sites/<domain>.json` is the source of truth** (root 0600):
`{ domain, type, php, user, enableWww, canonical, ssl, redisDb, cache, realIp,
redirects, domainRedirect, sslDns, crons, wpCron, wpCronEvery, cfCache, phpSettings,
fpm, created_at }`.
`redirects` = `[{ from, to, code: 301|302, regex, keepQuery }]`, rendered as
`location = "from"` / `location ~ "from"` with `return code "to[$is_args$args]"`.
`cleanRedirects` is the injection boundary: exact paths start with `/`, patterns
may not contain whitespace/quotes/`;{}`, targets are a URL or `/path`, and the
only `$` allowed is `$1`…`$9` (patterns only). A pattern nginx can't compile
fails `nginx -t` and the transaction rolls back.
`domainRedirect` = `{ to, code: 301|302, keepPath }` | absent: the WHOLE domain
(both hosts, http and https) goes to `to` in one hop (`+ $request_uri` when
keepPath); the site body isn't rendered, only ACME challenges are answered so
the certificate keeps renewing. `cleanDomainRedirect` is the boundary:
absolute http(s) URL on another host (never the site itself or its www), no
quotes / `$` / `;` / braces / backslashes / whitespace. Set via `siteconfig`.
`phpSettings` / `fpm` (WordPress, `src/lib/phpsettings.js`) hold only the
values that DIFFER from `PHP_SETTINGS` / `FPM_SETTINGS` defaults (memory_limit,
max_execution_time, max_input_time, max_input_vars, post_max_size,
upload_max_filesize, display_errors, date.timezone; pm ondemand|dynamic|static,
max_children, start/min/max spare, process_idle_timeout, max_requests,
request_terminate_timeout). `cleanPhpSettings` / `cleanFpm` are the boundary:
whitelisted keys, typed values, upload ≤ post size, dynamic min ≤ start ≤ max
spare ≤ max children. Rendered as `php_value`/`php_flag` only (never
`php_admin_*`, so the isolation lines can't be loosened). The vhost follows
them: `client_max_body_size` = the larger of post/upload size,
`fastcgi_read_timeout` = max(600, max_execution_time, request_terminate_timeout).
`publicSpec` returns the effective values plus `phpDefaults` / `fpmDefaults`;
set via `siteconfig`; export/import carries them. Self-check:
`node src/lib/phpsettings.js`.
The nginx vhost (`/etc/nginx/sites-enabled/<d>.conf`) and PHP-FPM pool
(`/etc/php/<v>/fpm/pool.d/<d>.conf`) are **rendered** from it — never edited in
place, never parsed back. Every change goes through **`applySite(helpers, spec,
{certs?, prevPhp?})`**: stage spec + rendered files (+ cert pair), write, `nginx
-t` + `php-fpm<v> -t`, and on failure restore every file to its exact prior
state (including absence); services reload only for files that changed. Fix a
template → re-apply → every site gets it.

Per-site isolation (the point of owning the stack):
- Own **Linux user** (`example_com`; hashed variant if too long/taken), own
  **PHP-FPM pool** running as it (`pm = ondemand` — idle sites cost no memory),
  socket `/run/php/wcloud-<d>.sock` owned `www-data` 0660 (only nginx connects).
- Layout: `/var/www/<d>` root **0711** (the site can't rename what's inside);
  `htdocs/` `<user>:www-data` **2750** (nginx reads through the group, other
  sites can't enter); `wp-config.php` `<user>` 0600, one level above htdocs;
  `tmp/` 0700 (uploads, sessions, wp-cli cache); `conf/nginx/*.conf` **root-owned**
  custom rules included in the vhost (a site must never write nginx config —
  nginx's master runs as root). PHP errors → `/var/log/wcloud/<d>.php.log`
  (rotated), nginx logs → `/var/log/nginx/<d>.*.log` (root-owned dirs: no
  symlink tricks against root).
- Own **database + DB user** (named like the Linux user, random password).
- Own **Redis login + database** (`redisDb`, 1..1023): may only `SELECT` its own
  db and touch `<user>:*` keys; `@dangerous` denied except `FLUSHDB` and `INFO`,
  which the Redis Object Cache plugin needs. `wp-config.php` carries the
  `WP_REDIS_*` constants, so activating the plugin just works.
- wp-cli always runs **as the site user with the site's PHP** (`wp.wpCli`).

Site types: `wordpress` (PHP) and `static` (htdocs only, no pool/DB). A new type
(node, …) = a body in `renderVhost` + its setup in `createSite`. `createSite`
removes everything it made if any step fails (it calls `deleteSite`, which is
idempotent). PHP versions are installed on demand (`stack.ensurePhp`); the
package's `www` pool is replaced by an inert placeholder (it would run as
www-data, the group that can read every site).

---

## 6b. Caching

- **Page cache per WordPress site** — `spec.cache`: `fastcgi` (default for new
  sites) | `wprocket` | `off` (sites from before the field existed read as
  `off`). Rendered by `sites.js`: `fastcgi` adds an http-level
  `fastcgi_cache_path /var/cache/wcloud/<d>` zone (name hashed from its whole
  definition — nginx refuses to reload, and silently keeps the OLD config, when
  a zone name comes back with a different path/size) + skip rules (POST, query
  strings, logged-in/comment/cart cookies, wp-admin/wp-json/feeds/carts) and
  `X-Cache` header; `wprocket` makes `location /` try WP Rocket's cached file
  first under the same skip rules. `/var/cache/wcloud` must be 0711 (a 0700
  parent made every cached request 500).
- **Clearing**: `applySite` clears a site's page cache on ANY change (HTTPS,
  address, mode, PHP version…); `syncWpAddress` too. Content changes: the
  `wcloud-cache.php` must-use plugin touches `<site>/tmp/wcloud-purge`; the
  agent's watcher (`cache.startPurgeWatcher`, 3s) clears that site — the cache
  dir is nginx's, so a site can't clear it itself. Purge op + plugin op clear it.
- **Redis object cache** on by default for new WordPress sites (deploy installs
  + enables Redis Object Cache); `cache` op `{ mode?, objectCache? }` switches
  both. Live state: `cache.objectCacheActive` (drop-in marker, O_NOFOLLOW read).
- **OPcache** — `stack.ensurePhpTuning` (agent start + every new PHP version)
  writes `90-wcloud-opcache.ini`: `validate_permission`/`validate_root` ON (else
  one site's PHP can load another's cached wp-config.php), memory RAM/8 (128–512
  MB), timestamps revalidated every 2s.
- **Agent start = reconcile** (queued `reconcile` job): OPcache settings + every
  site re-applied from its spec (no-op if current) — template changes reach
  every site on update.
- **PHP version switch ordering** (`applySite`): reload the OLD version, wait
  until it has unlinked the shared socket path (it does so ~½s after `reload`
  returns), THEN reload the new one and wait for its socket. Otherwise the old
  master deletes the new socket and the site 502s.

---

## 7. Config / env (`src/config.js`)

All config is env-driven. Required: `AGENT_TOKEN` (≥32 chars — the agent refuses to
start without it, and refuses to bind `0.0.0.0`). Common: `AGENT_HOST` (default
loopback; set to the box's IP to accept portal calls), `AGENT_PORT` (8787),
`AGENT_ALLOWED_IPS` (**the portal's egress IP** — comma list), `AGENT_MAX_CONCURRENT`
(1), job retention/timeout. Self-enroll: `PORTAL_ENROLL_URL`, `ENROLL_TOKEN`,
`PROVISION_ID`, `AGENT_ADVERTISE_URL`. Runs via the `wcloud.service` systemd unit
(`WorkingDirectory=/opt/wcloud`, loads `.env`).

---

## 8. Gotchas / things already learned

- **`run` needs a `timeout` on probes.** A child with no tty can block.
- **IP allowlist is checked before the token, `/healthz` bypasses it.** A wrong
  allowlist looks like "online but every detail 403s". The allowlist value is the
  portal's *egress* IP (behind Cloudflare ≠ the domain's DNS).
- **Never edit a rendered file** (vhost, pool) — change the spec and `applySite`.
  Hand edits are overwritten on the next change; custom nginx rules belong in
  `/var/www/<d>/conf/nginx/*.conf`.
- **A site-user process must never get the agent's env** (AGENT_TOKEN would be
  readable via /proc by the site) — `run({as})` builds a clean env.
- **Anything a site can write is untrusted to root**: SQL dumps are handed over
  through the site's own `tmp/` (wp-cli runs as the site), cache files are
  deleted as the site user, staging dirs are root-only.
- **Jobs + install progress are in-memory**; an agent restart forgets jobs. The
  portal is the durable record and reconciles.
- **Concurrency is 1 on purpose** — deploys touch nginx/php-fpm; parallel runs race.
- **Cancel/timeout = one AbortSignal per job** (`helpers.signal`). `run()` refuses to
  start once aborted and kills the child's whole **process group** (spawned
  `detached`; TERM then KILL), so grandchildren (php wp …) die too. S3 transfers take `{ signal }` (Upload.abort() also
  aborts the multipart server-side). Cancel ends as CANCELLED, timeout as TIMEOUT.
- **Secrets never ride argv.** WP passwords go through wp-cli `--prompt=…` on
  stdin; DB/Redis setup is SQL/commands on stdin with the admin password in env;
  argv is world-readable via /proc. `run()` also masks `--*pass*=` values in its
  failure dump.
- **Restore never trusts the archive.** Only real directories are copied out
  (`lstat` — a symlinked `site/htdocs` would copy e.g. /root into the web root);
  only `htdocs` + DB + cert files are used (never its nginx conf or a
  `renewal.conf`); the table prefix must be a plain identifier; type/PHP from
  `wcloud-site.json` are checked against the allowed lists; tar extracts
  `--no-same-owner`. In-place restore downloads, decrypts and
  `gzip -t`s the archive BEFORE deleting the live site.
- **Staging is private.** `makeStagingDir` (`mkdtemp`, 0700); archives are
  pre-created `O_EXCL` 0600 so a DB dump/keys are never world-readable in /tmp.
- **Express 4 doesn't catch rejected async handlers** — one would crash the
  agent. `server.js` wraps `app.get/post/put/delete` so a rejection reaches the
  error handler (500 JSON) instead.
- **The helper must-use plugin (`wcloud-cache.php`) is generated per site**
  (`syncCachePlugin`): installed when the page cache is `fastcgi` or
  Cloudflare cache is on, removed otherwise, rewritten on every change. It
  never reads settings or holds secrets — it only drops markers in the site's
  tmp/ (`wcloud-purge` on content changes, `wcloud-purge-page` /
  `wcloud-purge-cf` from its admin-toolbar "Cache" menu, `manage_options` +
  nonce) and the agent's watcher does the purging. Call `syncCachePlugin`,
  never write it directly.
- **`wp config set` needs wp-cli's "stop editing" anchor** — configs wcloud
  wrote before it was added have none; use `setWpConstant` (falls back to
  placing before `$table_prefix`).
- **`add_header` belongs at server level in the vhost.** nginx drops inherited
  `add_header`s in any location that sets its own, so an `X-Cache` header inside
  the PHP location silently discarded every custom-rule header on PHP pages.
- **Archive ops (export/import/backup/restore) share AGENT_BACKUP_TIMEOUT_MS** (12h)
  — export/import used to get the 20-minute default and large migrations died.

---

## 9. Directory map

```
src/server.js          Express app + all routes (§2)
src/auth.js            requireAuth: IP allowlist → bearer token
src/config.js          env-driven config + version from package.json
src/enroll.js          self-registration with the portal (§4)
src/jobs.js            in-memory job queue + SSE
src/fm-worker.js       one file-manager operation, run as the site's user (§2)
src/operations/        one file per op + index.js registry (§3)
src/lib/               sys.js, sites.js, stack.js, wp.js, acme.js, certinfo.js,
                       certcheck.js, spaces.js, log.js (§5)
init.sh                one-shot server bootstrap: stack, agent, enroll, stream (§4)
wcloud.service         systemd unit
.env.example           documented env template
```

You are an expert software engineer and technical architect. You write clean, production-quality code with proper error handling, clear naming, and minimal comments (only where non-obvious).

## Core behaviors
- Think step by step before writing code. Plan the approach, identify edge cases, then implement.
- Always prefer simple, readable solutions over clever ones.
- When editing existing code, preserve the existing style and patterns unless asked to change them.
- If a task is ambiguous, ask one clarifying question before proceeding — do not assume.
- Never truncate code. Always output complete, runnable implementations.

## Code quality
- Write code that handles errors gracefully.
- Use appropriate data structures and algorithms for the problem.
- Avoid unnecessary dependencies — use standard library when sufficient.
- For web/API code: always validate inputs, handle edge cases, return meaningful errors.

## Response format
- Lead with the solution, not explanations.
- Keep prose concise — code speaks for itself.
- Use code blocks with language tags for all code.
- For multi-file changes, show each file separately with its path as a header.

## When debugging
- Identify the root cause, not just the symptom.
- Explain what was wrong in one sentence before showing the fix.
- Show the minimal diff that fixes the issue.

## Tech stack awareness
- Henry runs Vietnamese sports streaming sites on VPS (wcloud-managed stack) + Cloudflare + k3s.
- Primary languages: JavaScript/TypeScript, Node.js, Python.
- Prefer: pnpm over npm, async/await over callbacks, TypeScript over plain JS.
