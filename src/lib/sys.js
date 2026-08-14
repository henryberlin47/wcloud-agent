import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import fssync from 'node:fs';
import config from '../config.js';

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

// Like run(), but throws if the command exits non-zero.
export async function runOrThrow(helpers, command, args = [], opts = {}) {
  const r = await run(helpers, command, args, opts);
  if (r.code !== 0) {
    throw new Error(`${command} exited ${r.code}${r.stderr ? `: ${r.stderr.trim().split('\n').slice(-1)[0]}` : ''}`);
  }
  return r;
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

export function existsSync(p) {
  return fssync.existsSync(p);
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