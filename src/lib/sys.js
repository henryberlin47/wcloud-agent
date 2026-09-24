import { spawn } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import fs from 'node:fs/promises';

// ============================================================
//  sys.js — shared system helpers for native operation logic
// ============================================================
// Everything an operation needs to touch the OS: run commands (streaming into
// the job log), remove files/dirs, kill processes, and thin wrappers around
// systemctl / nginx. No shells are used (args are arrays), so interpolated
// domain values can never inject shell syntax.
// ============================================================

/**
 * Run a command to completion, streaming stdout/stderr into the job log.
 * Never uses a shell. Returns { code, stdout, stderr, timedOut } and does NOT throw on
 * non-zero exit — callers decide what a failure means.
 *
 * @param {object} helpers  { log, err, signal }  (signal: the job's AbortSignal)
 * @param {string} command
 * @param {string[]} args
 * @param {object} [opts]   { cwd, env, stdin, quiet, verbose, as, timeout }
 *   (default)   → silent while it succeeds; on failure the command line and the
 *                 tail of its output are logged, so a broken step stays
 *                 diagnosable without drowning the job log in normal output.
 *   verbose=true→ echo the command and stream every line live
 *   quiet=true  → never log, even on failure (probes/version checks)
 *   as          → { uid, gid, home }: run as that user (a site's wp-cli). The
 *                 child gets a clean env — never the agent's, which holds
 *                 AGENT_TOKEN and would be readable by the site via /proc.
 *   timeout     → hard kill after N ms; resolves with code:-1 and timedOut:true
 */
export function run(helpers, command, args = [], opts = {}) {
  const { cwd, env = {}, stdin, quiet = false, verbose = false, as, timeout } = opts;
  const { log, err, signal: jobSignal } = helpers;

  const cmd = command;
  const cmdArgs = args;
  const childEnv = as
    ? { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', HOME: as.home, LANG: 'C.UTF-8', ...env }
    : { ...process.env, ...env };
  // Never echo a secret flag value into the job log (it's served to the portal).
  const shown = () => `$ ${cmd} ${cmdArgs.map((a) => String(a).replace(/^(--[\w-]*pass[\w-]*=).+/i, '$1***')).join(' ')}`;

  return new Promise((resolve, reject) => {
    // Cancelled/timed out between commands: don't start the next one.
    if (jobSignal?.aborted) return reject(new Error(`cancelled (${jobSignal.reason ?? 'aborted'})`));

    if (verbose) log(shown());
    // detached → the child leads its own process group, so a kill reaches every
    // descendant (php wp … and anything it spawned).
    const child = spawn(cmd, cmdArgs, {
      cwd, env: childEnv, shell: false, detached: true,
      ...(as ? { uid: as.uid, gid: as.gid } : {}), // libuv also drops root's supplementary groups
    });

    let stdout = '';
    let stderr = '';
    let killed = false;
    let timedOut = false;

    // TERM the whole group, then KILL whatever ignored it.
    const killTree = () => {
      const sig = (s) => { try { process.kill(-child.pid, s); } catch {} };
      sig('SIGTERM');
      setTimeout(() => sig('SIGKILL'), 5000).unref?.();
    };

    // Optional hard timeout so a probe that hangs (e.g. an interactive tool with
    // no tty) can't stall the caller forever. Resolves with code -1, not reject.
    const timer = timeout
      ? setTimeout(() => { timedOut = true; killTree(); }, timeout)
      : null;

    const onAbort = () => {
      killed = true;
      err?.(`[${jobSignal.reason ?? 'cancel'}] stopping pid ${child.pid} and its children`);
      killTree();
    };
    jobSignal?.addEventListener('abort', onAbort, { once: true });

    lineReader(child.stdout, (line) => { stdout += line + '\n'; if (verbose) log?.(line); });
    lineReader(child.stderr, (line) => { stderr += line + '\n'; if (verbose) err?.(line); });

    if (stdin != null) child.stdin.write(stdin);
    child.stdin.end();

    const settle = () => { if (timer) clearTimeout(timer); jobSignal?.removeEventListener('abort', onAbort); };
    // A killed process whose pipes are still held open (a straggler outside the
    // group) would delay 'close' indefinitely; once it has exited, stop waiting.
    child.on('exit', () => {
      if (killed || timedOut) { child.stdout?.destroy(); child.stderr?.destroy(); }
    });
    child.on('error', (e) => { settle(); reject(new Error(`spawn failed for ${cmd}: ${e.message}`)); });
    child.on('close', (code, signal) => {
      settle();
      if (killed) return reject(new Error(`cancelled (signal ${signal || 'n/a'})`));
      if (timedOut) return resolve({ code: -1, stdout, stderr, timedOut: true });
      const c = code ?? -1;
      // Failure is the only time the raw command + output are worth the noise.
      if (c !== 0 && !quiet && !verbose) {
        err?.(shown());
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

// uid/gid/home of a local user, straight from /etc/passwd (no shell-out).
export async function userIds(name) {
  const line = (await fs.readFile('/etc/passwd', 'utf8')).split('\n').find((l) => l.startsWith(`${name}:`));
  if (!line) throw new Error(`The site's system user (${name}) is missing on this server.`);
  const [, , uid, gid, , home] = line.split(':');
  return { uid: Number(uid), gid: Number(gid), home };
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
  return run(helpers, 'systemctl', [action, unit], { timeout: 60000 });
}

// nginx -t ; returns true if config is valid.
export async function nginxTest(helpers) {
  const r = await run(helpers, 'nginx', ['-t'], { timeout: 30000 });
  return r.code === 0;
}

export async function nginxReload(helpers) {
  return systemctl(helpers, 'reload', 'nginx');
}

// True if the cert file's SANs cover host (exact, or a one-label wildcard) —
// Node's RFC 6125 matcher, the same one lib/certcheck.js uses. Never throws.
export async function certCovers(certPath, host) {
  try { return !!new X509Certificate(await fs.readFile(certPath)).checkHost(String(host).trim().toLowerCase()); }
  catch { return false; }
}
