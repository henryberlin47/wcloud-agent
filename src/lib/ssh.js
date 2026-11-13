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

// ── Logins (journal) ─────────────────────────────────────────────────────────
const ACCEPTED = /Accepted (\S+) for (\S+) from (\S+) port \d+(?: ssh2)?(?:: \S+ (SHA256:\S+))?/;
const FAILED = /Failed (?:password|publickey) for (?!invalid user )(\S+) from (\S+)/; // invalid users: counted by INVALID
const INVALID = /Invalid user (\S*) from (\S+)/;

async function logins(helpers) {
  const r = await run(helpers, 'journalctl', ['-t', 'sshd', '-t', 'sshd-session', '--since', `-${DAYS}d`, '-o', 'short-iso', '--no-pager',
    '-g', 'Accepted |Failed (password|publickey) for |Invalid user '], { quiet: true, timeout: 90_000 });
  const accepted = [];
  const ips = new Map();
  let failed = 0;
  for (const l of r.stdout.split('\n')) {
    const time = l.slice(0, l.indexOf(' ')).replace(/([+-]\d\d)(\d\d)$/, '$1:$2'); // +0000 → +00:00 (ISO)
    let m = l.match(ACCEPTED);
    if (m) { accepted.push({ time, method: m[1], user: m[2], ip: m[3], fingerprint: m[4] || null }); continue; }
    m = l.match(FAILED) || l.match(INVALID);
    if (!m) continue;
    failed++;
    const e = ips.get(m[2]) || { ip: m[2], count: 0, last: time, users: new Set() };
    e.count++; e.last = time;
    if (e.users.size < 5) e.users.add(m[1] || '(empty)');
    ips.set(m[2], e);
  }
  return {
    days: DAYS,
    accepted: accepted.reverse().slice(0, 100), // newest first
    failed: { total: failed, ips: [...ips.values()].sort((a, b) => b.count - a.count).slice(0, 20).map((e) => ({ ...e, users: [...e.users] })) },
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

/** Just the keys — the portal's new-key alert asks every few minutes; no journal read. */
export const sshKeys = async (helpers) => ({ keys: await listKeys(helpers, await sshdConfig(helpers)) });

/** Everything the portal's Server → Security tab shows. */
export async function sshStatus(helpers) {
  const cfg = await sshdConfig(helpers);
  const [keyList, log, f2b] = await Promise.all([listKeys(helpers, cfg), logins(helpers), fail2ban(helpers)]);
  const lastUsed = new Map();
  for (const a of log.accepted) if (a.fingerprint && !lastUsed.has(a.fingerprint)) lastUsed.set(a.fingerprint, a.time);
  return {
    config: {
      port: cfg.port || '22', passwordLogin: cfg.passwordauthentication === 'yes', permitRootLogin: cfg.permitrootlogin || null,
      managed: await pathExists(DROPIN),
    },
    keys: keyList.map((k) => ({ ...k, lastUsed: lastUsed.get(k.fingerprint) || null })),
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
  if (!on && !(await listKeys(helpers, await sshdConfig(helpers))).length) {
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
  if (cfg.passwordauthentication !== 'yes' && all.length && all.every(gone)) {
    throw new Error('That would remove every SSH key while password login is off — nobody could log in. Keep at least one key.');
  }
  return (await keys(helpers, { op: 'remove', akf: cfg.authorizedkeysfile, list })).removed;
}
