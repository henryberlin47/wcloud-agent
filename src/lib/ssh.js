import fs from 'node:fs/promises';
import { run, pathExists, withLock, sshdRun, sleep } from './sys.js';
import config from '../config.js';
import { applyFirewall, readSettings } from './firewall.js';

// ============================================================
//  ssh.js — who can log in over SSH, who did, who tried
// ============================================================
// Read-only scan (GET /api/ssh): sshd's effective settings, every
// authorized_keys entry of every user with a login shell, the last week's
// logins and failed attempts from the journal, fail2ban's sshd jail.
// Changes (op `sshsecurity`): the SSH port, password login, hardening (one drop-in that wins
// over cloud-init's), fail2ban for sshd on/off, remove keys. Which keys are
// *expected* is the portal's to know — the agent only reports and removes.
// ============================================================

const DROPIN = '/etc/ssh/sshd_config.d/00-wcloud.conf'; // first match wins in sshd_config
const JAIL = '/etc/fail2ban/jail.d/wcloud-sshd.conf';
const DAYS = 7;
const APT_ENV = { DEBIAN_FRONTEND: 'noninteractive', NEEDRESTART_MODE: 'a', NEEDRESTART_SUSPEND: '1' };
const quiet = { quiet: true, timeout: 30_000 };

// `sshd -T`: the settings sshd actually runs with, every file applied.
async function sshdConfig(helpers) {
  const r = await sshdRun(helpers, ['-T'], quiet);
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
      harden: parseDropin(await fs.readFile(DROPIN, 'utf8').catch(() => '')).harden,
    },
    keys: keyList.map((k) => ({ ...k, lastUsed: lastUsed.get(`${k.user}|${k.fingerprint}`) || null })),
    logins: log,
    fail2ban: f2b,
  };
}

// ── Changes (op `sshsecurity`) ───────────────────────────────────────────────
// The drop-in is wcloud's whole SSH config: parseDropin reads it back, renderDropin
// writes it from one settings object, so port, password login and hardening compose.

/** The drop-in's settings: { port, passwordLogin, harden }; null = the drop-in doesn't set it. */
export function parseDropin(txt) {
  const v = (k) => (txt.match(new RegExp(`^${k} (\\S+)$`, 'mi')) || [])[1];
  return {
    port: v('Port') ? Number(v('Port')) : null,
    passwordLogin: v('PasswordAuthentication') ? v('PasswordAuthentication') === 'yes' : null,
    harden: /^# hardening: on$/m.test(txt),
  };
}

// Keyboard-interactive follows password login, except under hardening: password auth is
// PasswordAuthentication alone, so it keeps working with keyboard-interactive off.
export function renderDropin(s) {
  return [
    '# Managed by wcloud (portal: Server → Security). Edits here are overwritten.',
    `Port ${s.port}`,
    `PasswordAuthentication ${s.passwordLogin ? 'yes' : 'no'}`,
    `KbdInteractiveAuthentication ${s.passwordLogin && !s.harden ? 'yes' : 'no'}`,
    ...(s.harden ? [
      '# hardening: on',
      'PermitRootLogin prohibit-password',
      'MaxAuthTries 3',
      'LoginGraceTime 30',
      'X11Forwarding no',
      'AllowAgentForwarding no',
      'PermitEmptyPasswords no',
      'ClientAliveInterval 300', // idle sessions end after 10 minutes
      'ClientAliveCountMax 2',
    ] : []),
  ].join('\n') + '\n';
}

// A setting the drop-in doesn't set yet is sshd's effective value, so the first change keeps it.
async function settingsOf(helpers) {
  const d = parseDropin(await fs.readFile(DROPIN, 'utf8').catch(() => ''));
  const cfg = await sshdConfig(helpers);
  return { port: d.port ?? Number(cfg.port || 22), passwordLogin: d.passwordLogin ?? cfg.passwordauthentication === 'yes', harden: d.harden };
}

// Ports wcloud and the web stack use. Below 1024 only 22 is allowed for SSH.
const RESERVED = [80, 443, 3306, 6379];
export function portProblem(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) return 'The SSH port must be a whole number from 1 to 65535.';
  if (port < 1024 && port !== 22) return 'Below 1024 only port 22 can be used for SSH.';
  if (port === config.port || RESERVED.includes(port)) return 'That port is used by wcloud or the web stack — pick another.';
  return null;
}

// `ss -ltnpH`: the TCP listeners as { port, process }.
const listeners = async (helpers) => (await run(helpers, 'ss', ['-ltnpH'], quiet)).stdout.split('\n').filter(Boolean).map((l) => {
  const c = l.trim().split(/\s+/);
  return { port: Number(c[3].slice(c[3].lastIndexOf(':') + 1)), process: (l.match(/users:\(\("([^"]*)"/) || [])[1] || null };
});
const portTaken = async (helpers, port) => (await listeners(helpers)).some((l) => l.port === port && l.process !== 'sshd');
async function listening(helpers, port) {
  for (let i = 0; i < 10; i++) { if ((await listeners(helpers)).some((l) => l.port === port)) return true; await sleep(500); }
  return false;
}
const socketMode = async (helpers) => (await run(helpers, 'systemctl', ['is-active', 'ssh.socket'], quiet)).stdout.trim() === 'active';

// How the running sshd picks up a change: 'socket' (a new port, socket-activated), 'restart' (a
// new port, classic ssh.service), 'reload' (anything else). A SIGHUP reload applies the auth settings
// but keeps the old listeners, so a port needs a restart. Open sessions stay in every case: the units
// use KillMode=process, so only the listening sshd process goes.
async function reloadSshd(helpers, how) {
  if (how === 'socket') {
    // sshd-socket-generator copies `Port` into the socket's ListenStream on daemon-reload.
    await run(helpers, 'systemctl', ['daemon-reload'], quiet);
    const r = await run(helpers, 'systemctl', ['restart', 'ssh.socket'], { timeout: 30_000 });
    if (r.code !== 0) throw new Error(`The SSH socket didn't restart: ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
    return;
  }
  // Ubuntu's unit is ssh, others sshd.
  const act = how === 'restart' ? 'restart' : 'reload';
  const r = await run(helpers, 'systemctl', [act, 'ssh'], quiet);
  if (r.code !== 0) await run(helpers, 'systemctl', [act, 'sshd'], { timeout: 30_000 });
}

const restoreFile = (f, data) => (data === null ? fs.rm(f, { force: true }) : fs.writeFile(f, data));
const jailText = (on, ports) => `# Managed by wcloud (portal: Server → Security).\n[sshd]\n${on
  ? `enabled = true\nbackend = systemd\njournalmatch = _COMM=sshd + _COMM=sshd-session\nport = ${ports}\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n`
  : 'enabled = false\n'}`;

/**
 * SSH settings { port?, passwordLogin?, harden? }, merged with the current ones and written as one
 * drop-in, tested with `sshd -t`, applied. A port change: open the new port in the firewall and
 * fail2ban (both ports), move sshd, check the new port listens, only then close the old one.
 * Any failure up to that point undoes everything.
 */
export async function setSshd(helpers, change) {
  const main = await fs.readFile('/etc/ssh/sshd_config', 'utf8').catch(() => '');
  if (!/^\s*Include\s+\/etc\/ssh\/sshd_config\.d\/\*\.conf/mi.test(main)) {
    throw new Error('This server\'s sshd_config doesn\'t read /etc/ssh/sshd_config.d — change these settings there by hand.');
  }
  const cur = await settingsOf(helpers);
  const next = { ...cur, ...change };
  const keyLogins = async () => (await listKeys(helpers, await sshdConfig(helpers))).filter(loginKey);
  if (change.passwordLogin === false && !(await keyLogins()).length) {
    throw new Error('No SSH key is set up for any user — turning password login off would lock everyone out. Add a key first.');
  }
  if (next.harden) {
    // Hardening turns root's password login off, so someone has to be able to get in with a key.
    const users = new Set((await keyLogins()).map((k) => k.user));
    const sudo = ((await run(helpers, 'getent', ['group', 'sudo'], quiet)).stdout.trim().split(':')[3] || '').split(',');
    if (!users.has('root') && ![...users].some((u) => sudo.includes(u))) {
      throw new Error('Hardening turns off root login by password, and no SSH key is set up for root or a sudo user — you would be locked out. Add a key first.');
    }
  }

  const moved = next.port !== cur.port;
  if (moved) {
    const why = portProblem(next.port);
    if (why) throw new Error(why);
    if (await portTaken(helpers, next.port)) throw new Error('That port is already used by another program on this server.');
  }
  const fw = (await readSettings()).enabled;
  const prevJail = await fs.readFile(JAIL, 'utf8').catch(() => null);
  const f2b = /^enabled = true$/m.test(prevJail ?? '');
  const prev = await fs.readFile(DROPIN, 'utf8').catch(() => null);
  const how = !moved ? 'reload' : (await socketMode(helpers)) ? 'socket' : 'restart';
  const restartF2b = async () => {
    const r = await run(helpers, 'systemctl', ['restart', 'fail2ban'], { timeout: 60_000 });
    if (r.code !== 0) throw new Error('fail2ban didn\'t restart — see the log above.');
  };

  const undo = [];
  let applied = false;
  try {
    if (moved && fw) {
      await applyFirewall(helpers, {}, { sshPorts: [cur.port, next.port] }); // the new port opens before sshd moves
      undo.push(() => applyFirewall(helpers, {}, { sshPorts: [cur.port] }));
    }
    if (moved && f2b) {
      undo.push(async () => { await restoreFile(JAIL, prevJail); await restartF2b(); });
      await fs.writeFile(JAIL, jailText(true, `${cur.port},${next.port}`), { mode: 0o644 });
      await restartF2b();
    }
    undo.push(async () => { await restoreFile(DROPIN, prev); if (applied) await reloadSshd(helpers, how).catch(() => {}); });
    await fs.writeFile(DROPIN, renderDropin(next), { mode: 0o644 });
    const t = await sshdRun(helpers, ['-t'], { timeout: 30_000 });
    if (t.code !== 0) throw new Error(`sshd rejected the change, nothing was applied: ${(t.stderr || t.stdout).trim().slice(0, 300)}`);
    applied = true;
    await reloadSshd(helpers, how);
    if (moved && !(await listening(helpers, next.port))) throw new Error(`sshd isn't listening on port ${next.port} — the change was undone.`);
  } catch (e) {
    for (const u of undo.reverse()) await u().catch(() => {});
    throw e;
  }
  // Committed: the new port is up. Only now does the old one close.
  if (moved) {
    try {
      if (fw) await applyFirewall(helpers, {});
      if (f2b) { await fs.writeFile(JAIL, jailText(true, String(next.port)), { mode: 0o644 }); await restartF2b(); }
    } catch (e) {
      throw new Error(`SSH now listens on port ${next.port}, but closing port ${cur.port} in the firewall or fail2ban failed: ${e.message}`);
    }
  }
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
  // The jail bans on the port sshd listens on now (the port option is what the ban rule blocks).
  await fs.writeFile(JAIL, jailText(on, (await settingsOf(helpers)).port), { mode: 0o644 });
  if (on) await run(helpers, 'systemctl', ['enable', 'fail2ban'], quiet);
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
  const hard = { port: 2222, passwordLogin: true, harden: true };
  assert.deepEqual(parseDropin(renderDropin(hard)), hard);
  assert.deepEqual(parseDropin(renderDropin({ port: 22, passwordLogin: false, harden: false })), { port: 22, passwordLogin: false, harden: false });
  assert.match(renderDropin(hard), /^PermitRootLogin prohibit-password$/m);
  assert.match(renderDropin(hard), /^KbdInteractiveAuthentication no$/m);
  assert.match(renderDropin({ ...hard, harden: false }), /^KbdInteractiveAuthentication yes$/m);
  assert.doesNotMatch(renderDropin({ ...hard, harden: false }), /PermitRootLogin|MaxAuthTries/);
  assert.equal(portProblem(22), null);
  assert.equal(portProblem(2222), null);
  for (const bad of [0, 65536, '2222', 1000, 80, 443, 3306, 6379, config.port]) assert.notEqual(portProblem(bad), null, String(bad));
  assert.match(jailText(true, '22,2222'), /^port = 22,2222$/m);
  console.log('ssh ok');
}
