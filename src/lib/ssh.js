import fs from 'node:fs/promises';
import { run, pathExists, withLock } from './sys.js';

// ============================================================
//  ssh.js — who can log in over SSH, who did, who tried
// ============================================================
// Read-only scan (GET /api/ssh): sshd's effective settings, every
// authorized_keys entry of every user with a login shell, the last week's
// logins and failed attempts from the journal, fail2ban's sshd jail.
// Changes (op `sshsecurity`): password login on/off (one drop-in that wins over
// cloud-init's), fail2ban for sshd on/off, remove keys. Which keys are
// *expected* is the portal's to know — the agent only reports and removes.
// ============================================================

const DROPIN = '/etc/ssh/sshd_config.d/00-wcloud.conf'; // first match wins in sshd_config
const JAIL = '/etc/fail2ban/jail.d/wcloud-sshd.conf';
const DAYS = 7;
const APT_ENV = { DEBIAN_FRONTEND: 'noninteractive', NEEDRESTART_MODE: 'a', NEEDRESTART_SUSPEND: '1' };
const quiet = { quiet: true, timeout: 30_000 };

// `sshd -T`: the settings sshd actually runs with, every file applied.
async function sshdConfig(helpers) {
  const r = await run(helpers, '/usr/sbin/sshd', ['-T'], quiet);
  const c = {};
  for (const l of r.stdout.split('\n')) { const i = l.indexOf(' '); if (i > 0 && !(l.slice(0, i) in c)) c[l.slice(0, i)] = l.slice(i + 1).trim(); }
  return c;
}

// ── Keys ─────────────────────────────────────────────────────────────────────
// /root and /home are hidden from the agent (wcloud.service ProtectHome), so the
// key files are read and changed by src/sshkeys.js in a transient systemd
// service of its own (systemd-run), outside that sandbox.
const KEYS_WORKER = new URL('../sshkeys.js', import.meta.url).pathname;
async function keys(helpers, req) {
  const r = await run(helpers, 'systemd-run', ['--pipe', '--wait', '--quiet', '--collect', '--service-type=exec', process.execPath, KEYS_WORKER],
    { stdin: JSON.stringify(req), quiet: true, timeout: 60_000 });
  let out = null;
  try { out = JSON.parse(r.stdout); } catch { /* below */ }
  if (r.code !== 0 || !out) throw new Error(out?.error || `Couldn't read the SSH keys: ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
  return out;
}
const listKeys = (helpers, cfg) => keys(helpers, { op: 'list', akf: cfg.authorizedkeysfile }).then((o) => o.keys);
// A key limited to a command (command=, restrict) doesn't let anyone log in to a shell: not a way in for the lockout guards.
const loginKey = (k) => !/(^|[\s,])(restrict|command=)/.test(k.options);

// ── Logins (journal) ─────────────────────────────────────────────────────────
// _COMM (the process name) is set by journald; SYSLOG_IDENTIFIER (-t) is whatever
// a program says it is — `logger -t sshd` would forge logins. Messages are anchored
// because a username is attacker text: `Invalid user Accepted password for root …`.
const JOURNAL = ['_COMM=sshd', '_COMM=sshd-session', '-o', 'json', '--no-pager'];
const ACCEPTED = /^Accepted (\S+) for (\S+) from ([0-9a-fA-F.:]+) port \d+(?: ssh2)?(?:: \S+ (SHA256:\S+))?/;
const FAILED = /^Failed (?:password|publickey) for (?!invalid user )(\S+) from ([0-9a-fA-F.:]+) port \d+/; // invalid users: counted by INVALID
const INVALID = /^Invalid user ([\s\S]*) from ([0-9a-fA-F.:]+) port \d+$/;

/** `journalctl -o json` lines → { accepted: [{ time, method, user, ip, fingerprint }], failed: [{ time, user, ip }], cursor }. */
export function parseJournal(out) {
  const accepted = [];
  const failed = [];
  let cursor = null;
  for (const l of out.split('\n')) {
    if (!l.trim()) continue;
    let e;
    try { e = JSON.parse(l); } catch { continue; }
    cursor = e.__CURSOR || cursor;
    if (e._COMM !== 'sshd' && e._COMM !== 'sshd-session') continue;
    const msg = Array.isArray(e.MESSAGE) ? Buffer.from(e.MESSAGE).toString('utf8') : String(e.MESSAGE ?? ''); // bytes when not UTF-8
    const time = new Date(Number(e.__REALTIME_TIMESTAMP) / 1000).toISOString();
    let m = msg.match(ACCEPTED);
    if (m) accepted.push({ time, method: m[1], user: m[2], ip: m[3], fingerprint: m[4] || null });
    else if ((m = msg.match(FAILED) || msg.match(INVALID))) failed.push({ time, user: m[1], ip: m[2] });
  }
  return { accepted, failed, cursor };
}

async function logins(helpers) {
  const r = await run(helpers, 'journalctl', [...JOURNAL, '--since', `-${DAYS}d`], { quiet: true, timeout: 90_000 });
  const j = parseJournal(r.stdout);
  const ips = new Map();
  for (const f of j.failed) {
    const e = ips.get(f.ip) || { ip: f.ip, count: 0, last: f.time, users: new Set() };
    e.count++; e.last = f.time;
    if (e.users.size < 5) e.users.add(f.user || '(empty)');
    ips.set(f.ip, e);
  }
  return {
    days: DAYS,
    accepted: j.accepted.reverse().slice(0, 100), // newest first
    failed: { total: j.failed.length, ips: [...ips.values()].sort((a, b) => b.count - a.count).slice(0, 20).map((e) => ({ ...e, users: [...e.users] })) },
  };
}

// ── fail2ban ─────────────────────────────────────────────────────────────────
async function fail2ban(helpers) {
  if (!(await pathExists('/usr/bin/fail2ban-client'))) return { installed: false, enabled: false };
  const r = await run(helpers, 'fail2ban-client', ['status', 'sshd'], quiet);
  if (r.code !== 0) return { installed: true, enabled: false };
  const num = (k) => Number((r.stdout.match(new RegExp(`${k}:\\s+(\\d+)`)) || [])[1] || 0);
  return {
    installed: true, enabled: true, banned: (r.stdout.match(/Banned IP list:\s*(.*)/) || [])[1]?.trim().split(/\s+/).filter(Boolean) || [],
    totalBanned: num('Total banned'), totalFailed: num('Total failed'),
  };
}

/**
 * SSH logins after a journal cursor (the portal's login alert asks every
 * minute) → { cursor, logins: [{ time, method, user, ip, fingerprint, key }] }.
 * key: the authorized_keys entry the login used ({ comment, user }), or null
 * when that key isn't on the server any more. No `after`, or one the journal
 * no longer has (rotated): a new starting point at the newest entry — logins
 * already in the journal are history, returned only as `knownIps`.
 */
export const CURSOR_RE = /^[\w=;]{10,400}$/;
const cursorOf = (out) => (out.match(/^-- cursor: (\S+)\s*$/m) || [])[1] || null;
export async function sshLoginsSince(helpers, after) {
  if (after) {
    const r = await run(helpers, 'journalctl', [...JOURNAL, '--after-cursor', after, '-n', '5000'], { quiet: true, timeout: 30_000 });
    if (r.code === 0) {
      const j = parseJournal(r.stdout);
      // The key must be in the login's OWN authorized_keys: the same key in another user's file is not it.
      let byUserKey = new Map();
      if (j.accepted.some((x) => x.fingerprint)) byUserKey = new Map((await listKeys(helpers, await sshdConfig(helpers))).map((k) => [`${k.user}|${k.fingerprint}`, { comment: k.comment, user: k.user }]));
      return { cursor: j.cursor || after, logins: j.accepted.map((x) => ({ ...x, key: x.fingerprint ? byUserKey.get(`${x.user}|${x.fingerprint}`) || null : null })) };
    }
  }
  const r = await run(helpers, 'journalctl', ['-n', '1', '-o', 'cat', '--show-cursor', '--no-pager'], { quiet: true, timeout: 30_000 });
  return { cursor: cursorOf(r.stdout), logins: [], knownIps: [...new Set((await logins(helpers)).accepted.map((a) => a.ip))], restarted: !!after };
}

/** Just the keys — the portal's new-key alert asks every few minutes; no journal read. */
export const sshKeys = async (helpers) => ({ keys: await listKeys(helpers, await sshdConfig(helpers)) });

/** Everything the portal's Server → Security tab shows. */
export async function sshStatus(helpers) {
  const cfg = await sshdConfig(helpers);
  const [keyList, log, f2b] = await Promise.all([listKeys(helpers, cfg), logins(helpers), fail2ban(helpers)]);
  const lastUsed = new Map();
  for (const a of log.accepted) if (a.fingerprint && !lastUsed.has(`${a.user}|${a.fingerprint}`)) lastUsed.set(`${a.user}|${a.fingerprint}`, a.time);
  return {
    config: {
      port: cfg.port || '22', passwordLogin: cfg.passwordauthentication === 'yes', permitRootLogin: cfg.permitrootlogin || null,
      managed: await pathExists(DROPIN),
    },
    keys: keyList.map((k) => ({ ...k, lastUsed: lastUsed.get(`${k.user}|${k.fingerprint}`) || null })),
    logins: log,
    fail2ban: f2b,
  };
}

// ── Changes (op `sshsecurity`) ───────────────────────────────────────────────

/** Test the sshd config and reload; on failure put `prev` (null = no file) back. */
async function applySshd(helpers, content, prev) {
  await fs.writeFile(DROPIN, content, { mode: 0o644 });
  const t = await run(helpers, '/usr/sbin/sshd', ['-t'], { timeout: 30_000 });
  if (t.code !== 0) {
    if (prev === null) await fs.rm(DROPIN, { force: true }); else await fs.writeFile(DROPIN, prev);
    throw new Error(`sshd rejected the change, nothing was applied: ${(t.stderr || t.stdout).trim().slice(0, 300)}`);
  }
  // Reload: open sessions stay connected. Ubuntu's unit is ssh, others sshd.
  const r = await run(helpers, 'systemctl', ['reload', 'ssh'], { quiet: true, timeout: 30_000 });
  if (r.code !== 0) await run(helpers, 'systemctl', ['reload', 'sshd'], { timeout: 30_000 });
}

export async function setPasswordLogin(helpers, on) {
  const main = await fs.readFile('/etc/ssh/sshd_config', 'utf8').catch(() => '');
  if (!/^\s*Include\s+\/etc\/ssh\/sshd_config\.d\/\*\.conf/mi.test(main)) {
    throw new Error('This server\'s sshd_config doesn\'t read /etc/ssh/sshd_config.d — change PasswordAuthentication there by hand.');
  }
  if (!on && !(await listKeys(helpers, await sshdConfig(helpers))).some(loginKey)) {
    throw new Error('No SSH key is set up for any user — turning password login off would lock everyone out. Add a key first.');
  }
  const v = on ? 'yes' : 'no';
  const prev = await fs.readFile(DROPIN, 'utf8').catch(() => null);
  await applySshd(helpers, `# Managed by wcloud (portal: Server → Security). Edits here are overwritten.\nPasswordAuthentication ${v}\nKbdInteractiveAuthentication ${v}\n`, prev);
}

export async function setFail2ban(helpers, on) {
  if (on && !(await pathExists('/usr/bin/fail2ban-client'))) {
    const r = await withLock('apt', () => run(helpers, 'apt-get', ['-o', 'DPkg::Lock::Timeout=600', 'install', '-y', '-q', 'fail2ban', 'python3-systemd'],
      { env: APT_ENV, timeout: 900_000 }));
    if (r.code !== 0) throw new Error('fail2ban could not be installed on this server.');
  }
  if (!(await pathExists('/usr/bin/fail2ban-client'))) return; // off and never installed: nothing to do
  // The journal backend: Ubuntu 24.04 has no auth.log unless rsyslog is installed.
  // Matched by program, not unit: fail2ban's default is sshd.service, Ubuntu's unit is ssh.service.
  await fs.writeFile(JAIL, on
    ? '# Managed by wcloud (portal: Server → Security).\n[sshd]\nenabled = true\nbackend = systemd\njournalmatch = _COMM=sshd + _COMM=sshd-session\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n'
    : '# Managed by wcloud (portal: Server → Security).\n[sshd]\nenabled = false\n', { mode: 0o644 });
  if (on) await run(helpers, 'systemctl', ['enable', 'fail2ban'], { quiet: true, timeout: 30_000 });
  const r = await run(helpers, 'systemctl', ['restart', 'fail2ban'], { timeout: 60_000 });
  if (on && r.code !== 0) throw new Error('fail2ban didn\'t start — see the log above.');
}

/**
 * Remove keys: [{ user, fingerprint }]. Each changed file is backed up next to
 * itself (authorized_keys.wcloud-<time>.bak) and replaced atomically with the
 * same owner and mode. Returns how many lines were removed.
 */
export async function removeKeys(helpers, list) {
  const cfg = await sshdConfig(helpers);
  const all = await listKeys(helpers, cfg);
  const gone = (k) => list.some((x) => x.user === k.user && x.fingerprint === k.fingerprint);
  if (cfg.passwordauthentication !== 'yes' && all.some(loginKey) && !all.some((k) => loginKey(k) && !gone(k))) {
    throw new Error('That would remove every SSH key while password login is off — nobody could log in. Keep at least one key.');
  }
  return (await keys(helpers, { op: 'remove', akf: cfg.authorizedkeysfile, list })).removed;
}

// Self-check: node src/lib/ssh.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const assert = (await import('node:assert')).strict;
  const entry = (comm, message, extra = {}) => JSON.stringify({ _COMM: comm, __CURSOR: `c-${message.length}`, __REALTIME_TIMESTAMP: '1700000000000000', MESSAGE: message, ...extra });
  const out = [
    entry('sshd-session', 'Accepted publickey for bob from 1.2.3.4 port 5022 ssh2: ED25519 SHA256:abcDEF+/12'),
    entry('logger', 'Accepted password for root from 6.6.6.6 port 1 ssh2'), // a local program logging as sshd: ignored
    entry('sshd', 'Invalid user Accepted password for root from 6.6.6.6 port 1 from 7.7.7.7 port 22'), // the name is attacker text
    entry('sshd', 'Failed password for invalid user admin from 8.8.8.8 port 22 ssh2'), // counted by its Invalid user line
    entry('sshd', 'Invalid user admin from 8.8.8.8 port 22'),
    entry('sshd', 'Failed password for root from 9.9.9.9 port 22 ssh2'),
    entry('sshd', 'xAccepted password for root from 6.6.6.6 port 1 ssh2'), // not anchored: ignored
    entry('sshd', 'Accepted password for bob from 1.2.3.4 port 5023 ssh2', { MESSAGE: [...Buffer.from('Accepted password for bob from 1.2.3.4 port 5023 ssh2')] }),
  ].join('\n');
  const j = parseJournal(out);
  assert.deepEqual(j.accepted.map((a) => [a.user, a.ip, a.method, a.fingerprint]), [
    ['bob', '1.2.3.4', 'publickey', 'SHA256:abcDEF+/12'], ['bob', '1.2.3.4', 'password', null]]);
  assert.deepEqual(j.failed.map((f) => [f.user, f.ip]), [['Accepted password for root from 6.6.6.6 port 1', '7.7.7.7'], ['admin', '8.8.8.8'], ['root', '9.9.9.9']]);
  assert.equal(j.cursor, `c-${'Accepted password for bob from 1.2.3.4 port 5023 ssh2'.length}`);
  assert.equal(j.accepted[0].time, '2023-11-14T22:13:20.000Z');
  assert.equal(loginKey({ options: 'no-pty,command="x"' }), false);
  assert.equal(loginKey({ options: 'from="10.0.0.1",restrict' }), false);
  assert.equal(loginKey({ options: 'no-pty' }), true);
  console.log('ssh ok');
}
