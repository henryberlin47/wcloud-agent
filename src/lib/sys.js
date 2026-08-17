import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import fssync from 'node:fs';
import config from '../config.js';
import { logger } from './log.js';

// ============================================================
//  sys.js — shared system helpers for native operation logic
// ============================================================
// Everything an operation needs to touch the OS: run commands (streaming into
// the job log), remove files/dirs, kill processes, and thin wrappers around
// systemctl / nginx / wo. No shells are used (args are arrays), so interpolated
// domain values can never inject shell syntax.
// ============================================================

/**
 * Run a command to completion, streaming stdout/stderr into the job log.
 * Never uses a shell. Returns { code, stdout, stderr } and does NOT throw on
 * non-zero exit — callers decide what a failure means.
 *
 * @param {object} helpers  { log, err, onCancel }
 * @param {string} command
 * @param {string[]} args
 * @param {object} [opts]   { cwd, env, stdin, quiet, verbose, asUser }
 *   (default)   → silent while it succeeds; on failure the command line and the
 *                 tail of its output are logged, so a broken step stays
 *                 diagnosable without drowning the job log in normal output.
 *   verbose=true→ echo the command and stream every line live
 *   quiet=true  → never log, even on failure (probes/version checks)
 *   asUser      → run via `sudo -u <user> -H` (for wp-cli as www-data)
 */
export function run(helpers, command, args = [], opts = {}) {
  const { cwd, env = {}, stdin, quiet = false, verbose = false, asUser, timeout } = opts;
  const { log, err, onCancel } = helpers;

  let cmd = command;
  let cmdArgs = args;
  if (asUser) {
    cmd = 'sudo';
    cmdArgs = ['-u', asUser, '-H', command, ...args];
  }

  return new Promise((resolve, reject) => {
    if (verbose) log(`$ ${cmd} ${cmdArgs.join(' ')}`);
    const child = spawn(cmd, cmdArgs, { cwd, env: { ...process.env, ...env }, shell: false });

    let stdout = '';
    let stderr = '';
    let killed = false;
    let timedOut = false;

    // Optional hard timeout so a probe that hangs (e.g. an interactive tool with
    // no tty) can't stall the caller forever. Resolves with code -1, not reject.
    const timer = timeout
      ? setTimeout(() => { timedOut = true; try { child.kill('SIGKILL'); } catch {} }, timeout)
      : null;

    onCancel?.((reason) => {
      killed = true;
      err?.(`[cancel:${reason}] SIGTERM → pid ${child.pid}`);
      try { child.kill('SIGTERM'); } catch {}
      setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 5000).unref?.();
    });

    lineReader(child.stdout, (line) => { stdout += line + '\n'; if (verbose) log?.(line); });
    lineReader(child.stderr, (line) => { stderr += line + '\n'; if (verbose) err?.(line); });

    if (stdin != null) child.stdin.write(stdin);
    child.stdin.end();

    child.on('error', (e) => { if (timer) clearTimeout(timer); reject(new Error(`spawn failed for ${cmd}: ${e.message}`)); });
    child.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      if (killed) return reject(new Error(`cancelled (signal ${signal || 'n/a'})`));
      if (timedOut) return resolve({ code: -1, stdout, stderr });
      const c = code ?? -1;
      // Failure is the only time the raw command + output are worth the noise.
      if (c !== 0 && !quiet && !verbose) {
        err?.(`$ ${cmd} ${cmdArgs.join(' ')}`);
        for (const line of tailLines(`${stdout}${stderr}`, 15)) err?.(`    ${line}`);
      }
      resolve({ code: c, stdout, stderr });
    });
  });
}

// Last n non-blank lines — enough context to diagnose, not a wall of text.
function tailLines(s, n) {
  const lines = String(s).split('\n').map((l) => l.trimEnd()).filter((l) => l.trim());
  return lines.slice(-n);
}

function lineReader(stream, onLine) {
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      onLine(buf.slice(0, i).replace(/\r$/, ''));
      buf = buf.slice(i + 1);
    }
  });
  stream.on('end', () => { if (buf.length) onLine(buf.replace(/\r$/, '')); });
}

// --- filesystem -------------------------------------------------------------

export async function pathExists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

export async function removePath(p) {
  await fs.rm(p, { recursive: true, force: true });
}

// wp-cli's --path must point at the WordPress CORE (where wp-load.php lives), not
// at wp-config.php. WordOps puts the core in <domain>/htdocs but keeps
// wp-config.php one level ABOVE it, so detecting by wp-config would wrongly pick
// the parent dir (wp-cli then reports "not a WordPress installation"). Detect the
// core via wp-load.php; wp-cli finds the config by walking up from there.
export async function resolveWpRoot(domain) {
  const base = `${config.wwwDir}/${domain}`;
  if (await pathExists(`${base}/htdocs/wp-load.php`)) return `${base}/htdocs`;
  if (await pathExists(`${base}/wp-load.php`)) return base;
  return `${base}/htdocs`; // WordOps default; let wp-cli report the real error
}

// Detect installed PHP version from /etc/php directories
export function getPhpVersion() {
  try {
    const dirs = fssync.readdirSync('/etc/php');
    const versions = dirs.filter(d => /^\d+\.\d+$/.test(d));
    if (!versions.length) throw new Error('no php dirs');
    // sort numerically major.minor
    versions.sort((a, b) => {
      const [aMaj, aMin] = a.split('.').map(Number);
      const [bMaj, bMin] = b.split('.').map(Number);
      return (aMaj - bMaj) || (aMin - bMin);
    });
    const version = versions[versions.length - 1];
    const flag = version.replace('.', '');
    const service = `php${version}-fpm`;
    return { version, flag, service };
  } catch {
    return { version: '8.3', flag: '83', service: 'php8.3-fpm' };
  }
}

// --- process management -----------------------------------------------------

/**
 * Find PIDs whose full command line matches any of the given substrings.
 * Reads /proc directly (no pgrep dependency). Excludes our own PID.
 */
export async function findPidsMatching(patterns) {
  const self = String(process.pid);
  const pids = new Set();
  let entries;
  try { entries = await fs.readdir('/proc'); } catch { return []; }
  for (const name of entries) {
    if (!/^\d+$/.test(name) || name === self) continue;
    let cmdline;
    try {
      cmdline = await fs.readFile(`/proc/${name}/cmdline`, 'utf8');
    } catch { continue; }
    // cmdline args are NUL-separated
    const joined = cmdline.replace(/\0/g, ' ');
    if (patterns.some((p) => joined.includes(p))) pids.add(name);
  }
  return [...pids];
}

export function killPids(pids, signal = 'SIGTERM') {
  let n = 0;
  for (const pid of pids) {
    try { process.kill(Number(pid), signal); n += 1; } catch {}
  }
  return n;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- service wrappers -------------------------------------------------------

export async function systemctl(helpers, action, unit) {
  return run(helpers, 'systemctl', [action, unit]);
}

// nginx -t ; returns true if config is valid.
export async function nginxTest(helpers) {
  const r = await run(helpers, 'nginx', ['-t']);
  return r.code === 0;
}

export async function nginxReload(helpers) {
  return run(helpers, 'systemctl', ['reload', 'nginx']);
}

// wo site delete <domain> --no-prompt --force ; returns { ok, code }.
// --force removes the WordOps record even when files/DB are already gone (the
// agent deletes the site dir first, so paths won't exist by this point).
// --all is intentionally NOT used: these sites use a remote shared DB, so there
// is no local WordOps-owned DB to drop.
export async function woSiteDelete(helpers, domain) {
  const r = await run(helpers, 'wo', ['site', 'delete', domain, '--no-prompt', '--force'], { stdin: '' });
  return { ok: r.code === 0, code: r.code };
}

// True if the site is in WordOps' registry. Checks `wo site list` (the same
// source `wo site list` shows the user), NOT `wo site info` — info returns
// nonzero once a site's files/nginx config are gone, even while the registry
// row survives, which made delete skip the row and leave it un-deletable.
export async function woSiteExists(helpers, domain) {
  const sites = await woSiteList(helpers).catch(() => null);
  if (sites === null) return false; // couldn't read the registry — don't guess
  return sites.includes(domain);
}

// wo site list ; returns an array of domain strings (one per line).
// Filters out blank lines and any decorative/header lines wo might print.
export async function woSiteList(helpers) {
  const r = await run(helpers, 'wo', ['site', 'list'], { quiet: true });
  if (r.code !== 0) {
    throw new Error(`wo site list failed (code ${r.code})`);
  }
  return r.stdout
    .split('\n')
    // wo colorizes its output; strip ANSI so exact domain matching works.
    // eslint-disable-next-line no-control-regex
    .map((s) => s.replace(/\x1b\[[0-9;]*m/g, '').trim())
    // keep only plausible domain lines (contain a dot, no spaces)
    .filter((s) => s && !s.includes(' ') && s.includes('.'));
}

// --- wp-cli -----------------------------------------------------------------

// Build a wp-cli runner bound to a site's app dir. All wp calls run as www-data.
//   const wp = wpCli(helpers, '/var/www/example.com');
//   await wp(['core', 'update']);
// Override the WP root with opts.wpPath (e.g. for old Acorn: { wpPath: 'web/wp' }).
export function wpCli(helpers, srcDir, opts = {}) {
  const { wpPath } = opts;
  return (args, extra = {}) => {
    const cliArgs = ['/usr/local/bin/wp', ...args];
    if (wpPath) cliArgs.push('--path=' + wpPath);
    return run(helpers, '/usr/bin/php', cliArgs, {
      cwd: srcDir,
      asUser: 'www-data',
      ...opts,
      ...extra,
    });
  };
}

// Add or remove www.<base> on every `server_name ...;` that lists <base>.
// Returns { out, changed }; files whose server_name doesn't mention the
// base come back unchanged.
export function adjustServerNames(content, base, wwwHost, enableWww) {
  let changed = false;
  const out = content.replace(/server_name\s+([^;]+);/g, (m, hosts) => {
    const list = hosts.trim().split(/\s+/);
    if (!list.includes(base) && !list.includes(wwwHost)) return m;
    if (enableWww && !list.includes(wwwHost)) {
      changed = true;
      return `server_name ${[...list, wwwHost].join(' ')};`;
    }
    if (!enableWww && list.includes(wwwHost)) {
      const next = list.filter((h) => h !== wwwHost);
      if (!next.length) return m; // never leave an empty server_name
      changed = true;
      return `server_name ${next.join(' ')};`;
    }
    return m;
  });
  return { out, changed };
}

// True if the cert's SAN list includes host (quiet probe).
export async function certCovers(helpers, certPath, host) {
  const r = await run(helpers, 'openssl', ['x509', '-in', certPath, '-noout', '-ext', 'subjectAltName'], { quiet: true, timeout: 15_000 });
  if (r.code !== 0) return false;
  return r.stdout.includes(`DNS:${host}`);
}

// Apply the user's domain preferences to a live site.
//   canonical "www"|"root" → 301 the other variant (conf/nginx/canonical.conf)
//                            + pin WP home/siteurl to the preferred host
//   canonical "none"       → delete any prior redirect, leave WP as-is
//   enableWww true/false   → ensure/remove www.<domain> in the vhost's
//                            server_name (backup + nginx -t + rollback)
// Reloads nginx at the end when (and only when) something changed.
export async function setCanonical(helpers, domain, canonical, enableWww = true) {
  const { ok, warn, err } = logger(helpers);
  const wwwHost = `www.${domain}`;
  const confPath = `${config.wwwDir}/${domain}/conf/nginx/canonical.conf`;
  let changed = false;

  // 1) Redirect snippet / WP options.
  if (canonical === 'none') {
    if (await pathExists(confPath)) {
      await removePath(confPath);
      ok(`Removed preferred-domain redirect for ${domain}`);
      changed = true;
    } else {
      ok('No preferred domain — both versions served, no redirect');
    }
  } else {
    const canonicalHost = canonical === 'www' ? wwwHost : domain;
    const otherHost = canonical === 'www' ? domain : wwwHost;
    const certPath = `/etc/letsencrypt/live/${domain}/fullchain.pem`;
    const hasSsl = await pathExists(certPath);
    if (!hasSsl) warn(`No SSL cert for ${domain} yet — redirect keeps $scheme so http stays http`);

    // WordOps includes conf/nginx/*.conf inside the server { } block, so
    // if(host) + return is one of nginx's safe-if patterns here.
    const confDir = `${config.wwwDir}/${domain}/conf/nginx`;
    await fs.mkdir(confDir, { recursive: true });
    await fs.writeFile(confPath,
      `# force canonical host — 301 the other variant, preserve path + query\n` +
      `if ($host = ${otherHost}) {\n    return 301 ${hasSsl ? 'https' : '$scheme'}://${canonicalHost}$request_uri;\n}\n`);
    ok(`${otherHost} 301 → ${hasSsl ? 'https' : '$scheme'}://${canonicalHost}`);
    changed = true;

    // Pin WP home/siteurl to the preferred host (scheme matches cert state)
    // so WP's own links + redirect backstop agree with nginx.
    const wp = wpCli(helpers, await resolveWpRoot(domain));
    const scheme = hasSsl ? 'https' : 'http';
    for (const key of ['home', 'siteurl']) {
      const r = await wp(['option', 'update', key, `${scheme}://${canonicalHost}`]);
      if (r.code !== 0) warn(`wp option update ${key} failed (code ${r.code}) — WP links may use the wrong host`);
    }
    ok(`WP home/siteurl = ${scheme}://${canonicalHost}`);
  }

  // 2) www enablement — edit the vhost's server_name. This is the one edit
  //    that can take a live site down: back up, edit, nginx -t, roll back.
  //    WordOps' main vhost is /etc/nginx/sites-available/<domain> (same path
  //    delete.js removes); the port-443 block may live in the per-site
  //    ssl.conf instead, so probe both. No-op when no file mentions the host.
  const files = [];
  for (const f of [`/etc/nginx/sites-available/${domain}`, `${config.wwwDir}/${domain}/conf/nginx/ssl.conf`]) {
    if (await pathExists(f)) files.push(f);
  }
  if (!files.length) {
    warn(`No nginx vhost found for ${domain} — www ${enableWww ? 'enablement' : 'removal'} skipped; verify the config manually`);
  }
  for (const path of files) {
    const orig = await fs.readFile(path, 'utf8');
    const { out, changed: c } = adjustServerNames(orig, domain, wwwHost, enableWww);
    if (!c) continue;
    const backup = `${path}.wcloud-bak`;
    await fs.copyFile(path, backup);
    await fs.writeFile(path, out);
    if (await nginxTest(helpers)) {
      await removePath(backup);
      ok(`${enableWww ? 'Enabled' : 'Removed'} ${wwwHost} in ${path}`);
      changed = true;
    } else {
      await fs.copyFile(backup, path);
      await removePath(backup);
      err(`server_name change in ${path} failed nginx -t — rolled back; ${wwwHost} ${enableWww ? 'not enabled' : 'still served'}`);
    }
  }

  // 3) Cert coverage: a redirect needs BOTH hosts to pass TLS. If www is
  //    served but the cert lacks it, re-issue (requires www DNS to resolve).
  if (canonical !== 'none' && enableWww) {
    const certPath = `/etc/letsencrypt/live/${domain}/fullchain.pem`;
    if ((await pathExists(certPath)) && !(await certCovers(helpers, certPath, wwwHost))) {
      warn(`Cert for ${domain} does not cover ${wwwHost} — re-issuing (needs www DNS to resolve)`);
      const r = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force']);
      if (r.code === 0) { ok(`SSL re-issued to cover ${wwwHost}`); changed = true; }
      else warn(`Cert re-issue failed — is DNS for ${wwwHost} ready? Re-run the SSL op once it is.`);
    }
  }

  // 4) Final validate + reload, only when something above actually changed.
  if (changed) {
    if (await nginxTest(helpers)) {
      await nginxReload(helpers);
      ok('nginx reloaded');
    } else {
      err('nginx -t FAILED after canonical changes — review config');
    }
  }
}

// Standard cache-clear routine used after code/DB changes:
//   - WP Rocket page cache (native fn via eval; disk fallback if provided)
//   - object cache flush
// webrootDir is optional; if given, the disk fallback wipes app/cache/wp-rocket.
export async function clearWpCaches(helpers, srcDir, webrootDir = null) {
  const wp = wpCli(helpers, srcDir);
  const rocket = await wp([
    'eval',
    'if (function_exists("rocket_clean_domain")) { rocket_clean_domain(); echo "WP Rocket cache cleared"; } else { echo "WP Rocket not active"; }',
  ]);
  if (rocket.code !== 0 && webrootDir) {
    const dir = `${webrootDir}/app/cache/wp-rocket`;
    if (await pathExists(dir)) {
      // wipe contents but keep the dir
      const fs = await import('node:fs/promises');
      try {
        for (const e of await fs.readdir(dir)) await removePath(`${dir}/${e}`);
      } catch {}
    }
  }
  const flush = await wp(['cache', 'flush'], { quiet: true });
  return { rocketOk: rocket.code === 0, objectFlushed: flush.code === 0 };
}