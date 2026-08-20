# Project Context — wcloud (agent)

> Read this before touching code. House style: minimal — prefer deleting to
> adding, stdlib to dependencies, one line to fifty. This agent runs as **root**
> on production servers; correctness and safety beat cleverness.

---

## 1. What this is

The per-server half of **wcloud** (a WordPress multi-site manager). The control
panel (`wcloud-portal`, a separate repo) never touches servers directly — it calls
this **agent** over HTTP with a bearer token. The agent is the only thing that runs
privileged commands (`wo`, nginx, systemctl, wp-cli). See `wcloud-portal/AGENTS.md`
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
  uptime) + `version` + supported operations. Gathered by shelling out; each probe
  can carry a `timeout` (see §5) so a hanging tool can't stall the whole response.
- `GET /api/sites` — `{ server, count, sites: [...] }` via `woSiteList`.
- `GET /api/sites/:domain/credentials` — DB creds read **live** from `wp-config.php`
  (see §6). 404 = not a readable WP site.
- `POST /api/op/:type` — validate + enqueue an operation → `{ jobId, state }`.
- `POST /api/self-update` — `git fetch origin` + `reset --hard origin/main` + `npm install`, respond `{ ok, updated, old_commit, new_commit, version }`, then restart via a *systemd-run 2s timer* (detached — the timer outlives the process that gets SIGTERM'd). Origin/branch hardcoded: this runs remote code as root, no request body ever reaches a shell.
- `POST /api/backup-test`, `POST /api/backup-delete` — quick rclone calls against the Spaces creds passed **in the request body** (per user, per job). Creds live in the rclone subprocess `env` for one call only — never written to config, never logged (command lines carry no secrets).
- `GET /api/jobs`, `/api/jobs/:id`, `/logs`, `/stream` (SSE), `POST /:id/cancel` —
  job status/logs/cancel. Jobs are **in-memory** (`src/jobs.js`), serialized
  (`AGENT_MAX_CONCURRENT=1`), forgotten ~1h after finishing.

---

## 3. Operations

One file per op in `src/operations/*.js`, registered in `src/operations/index.js`.
Each descriptor has:

- `validate(params) -> { ok, errors[], clean }` — **the injection boundary**.
  Domains are normalized (`normDomain`: scheme stripped, lowercased) and checked
  against `DOMAIN_RE`. Never let unvalidated input reach a command.
- `run(job, helpers, clean)` — the work.

Current ops: **deploy** (`wo site create --wp` + SSL), **update** (`wp core update`
+ `update-db` + php-fpm restart), **delete** (removes site, nginx, certs; requires
`confirm:true`), **ssl** (`wo site update --le --force`), **purge** (WP Rocket +
object cache), **resetPassword** (`wp user update --user_pass`), **export** (builds
the archived site; `buildSiteArchive` in `export.js` is the shared archive builder),
**import** (restores an archive; `runRestoreFromLocal` in `import.js` is the shared
restore body — decrypt/extract/DB/SSL/canonical all live there), **backup** (build
archive via the shared helper + rclone-upload to Spaces) and **restore** (rclone-
download + the shared restore path; in-place restore first runs the full **delete**
op). backup/restore take the user's Spaces creds per call in params and run with a
longer per-op timeout (`AGENT_BACKUP_TIMEOUT_MS`, default 12h). No shells are used
— args are arrays, so domain values can't inject shell syntax.

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
- `init.sh` — the one-shot bootstrap the install command runs. It: clones/pulls the
  repo to `/opt/wcloud`; installs WordOps + Node + the agent; **seeds a git
  identity** (WordOps' `wo` prompts for one and would hang non-interactively —
  see §8); writes `.env` (token, host, allowlist from `ALLOWED_IPS`, enroll vars);
  and **streams its own stdout** to the portal's `/api/provision/:pid/log` (ANSI
  stripped) with per-step milestones. Each run mints its own `PROVISION_ID`.

`config.version` is read from `package.json` at startup and surfaced in
`/healthz`, `/api/info`, and the enroll payload.

---

## 5. Key libraries (`src/lib/`)

- **sys.js** — the OS-touching core. `run(helpers, cmd, args, opts)` spawns without
  a shell, returns `{ code, stdout, stderr }`, never throws on non-zero. `opts`:
  `cwd, env, stdin, quiet, verbose, asUser` (`sudo -u <user> -H`), and **`timeout`**
  (SIGKILLs and resolves `{code:-1}` — use it on probes that might hang). Also
  `wpCli(helpers, srcDir)` (runs `php /usr/local/bin/wp` as `www-data`),
  `resolveWpRoot(domain)`, `woSiteList`, `woSiteExists`, nginx helpers.
- **credentials.js** — `readDbCredentials(helpers, domain)`: reads DB_NAME/USER/
  PASSWORD live via `wp config get`. No cache, no storage. Has a path-traversal
  guard on the domain.
- **panelcert.js** — pins the `:22222` WordOps panel to its self-signed cert and
  locks it, so it can't be repointed at a deletable site cert. Called at startup.
- **log.js** — the step logger used by operations.

---

## 6. `resolveWpRoot` — WordOps layout (easy to get wrong)

WordOps puts the WordPress **core** in `<domain>/htdocs/` but keeps `wp-config.php`
**one level above** it. wp-cli's `--path` / cwd must point at the *core*
(`wp-load.php`), and wp-cli finds the config by walking up on its own. Detecting the
root by `wp-config.php` wrongly picks the parent dir → wp-cli reports "not a
WordPress installation". `resolveWpRoot` therefore probes **`wp-load.php`**, not
`wp-config.php`. All wp-cli ops (update, purge, resetPassword, credentials) depend
on this.

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

- **`wo` hangs without a git identity.** WordOps prompts for a git name/email on
  first run and on every `wo` invocation until one is set; under systemd/non-tty
  that blocks forever — which silently hung `/api/info`. `server.js` seeds a git
  identity at startup, and `init.sh` seeds one before installing WordOps. Keep both.
- **`run` needs a `timeout` on probes.** A child with no tty (like a prompting tool)
  can block. `/api/info`'s `wo --version` uses `timeout`.
- **IP allowlist is checked before the token, `/healthz` bypasses it.** A wrong
  allowlist looks like "online but every detail 403s". The allowlist value is the
  portal's *egress* IP (behind Cloudflare ≠ the domain's DNS).
- **`wo` colorizes output** — strip ANSI before matching (`woSiteList`).
- **Delete uses `wo site list`, not `wo site info`** for existence (`woSiteExists`):
  `info` returns nonzero once files are gone though the registry row survives, which
  made deletes silently skip. Delete passes `--force` to clear orphaned rows.
- **Jobs + install progress are in-memory**; an agent restart forgets jobs. The
  portal is the durable record and reconciles.
- **Concurrency is 1 on purpose** — deploys touch nginx/php-fpm; parallel runs race.

---

## 9. Directory map

```
src/server.js          Express app + all routes (§2)
src/auth.js            requireAuth: IP allowlist → bearer token
src/config.js          env-driven config + version from package.json
src/enroll.js          self-registration with the portal (§4)
src/jobs.js            in-memory job queue + SSE
src/operations/        one file per op + index.js registry (§3)
src/lib/               sys.js, credentials.js, panelcert.js, log.js (§5)
src/templates/         nginx snippets (custom-cache.conf)
init.sh                one-shot server bootstrap (clone, install, enroll, stream) (§4)
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
- Henry runs Vietnamese sports streaming sites on WordOps VPS + Cloudflare + k3s.
- Primary languages: JavaScript/TypeScript, Node.js, Python.
- Prefer: pnpm over npm, async/await over callbacks, TypeScript over plain JS.
