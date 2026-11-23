import { run } from './sys.js';

// ============================================================
//  integrity.js — intrusion checks: the parsers, and the root-side scan
// ============================================================
// GET /api/integrity (server.js) → findings from src/integrity-worker.js, run
// through `systemd-run --pipe` the way sshkeys.js is (lib/ssh.js): /root and /home
// are hidden from the agent's sandbox (ProtectHome), and the checks must see what
// root sees. Findings are things to review, not verdicts: the portal lets the owner
// mark expected ones, so a scan reports only what is new. Self-check: node src/lib/integrity.js
// ============================================================

const WORKER = new URL('../integrity-worker.js', import.meta.url).pathname;

/** The worker's findings: [{ key, severity, title, detail }]. Throws when the scan fails. */
export async function scanIntegrity(helpers) {
  const r = await run(helpers, 'systemd-run', ['--pipe', '--wait', '--quiet', '--collect', '--service-type=exec', process.execPath, WORKER],
    { quiet: true, timeout: 60_000 });
  let out = null;
  try { out = JSON.parse(r.stdout); } catch { /* below */ }
  if (r.code !== 0 || !Array.isArray(out?.findings)) throw new Error(out?.error || `The intrusion check failed: ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
  return out.findings;
}

/** /etc/passwd → [{ name, uid, home, shell }]. */
export function parsePasswd(text) {
  const out = [];
  for (const l of text.split('\n')) {
    const [name, , uid, , , home, shell = ''] = l.split(':');
    if (name && /^\d+$/.test(uid || '')) out.push({ name, uid: Number(uid), home, shell });
  }
  return out;
}

// A shell that lets someone log in (the same test as sshkeys.js).
export const hasLoginShell = (u) => !/(nologin|false|sync|shutdown|halt)$/.test(u.shell);

/**
 * One sudoers file → [{ who, level }] for each rule that grants ALL or NOPASSWD to someone
 * other than root or an admin group. level: critical = NOPASSWD: ALL, else warning.
 */
export function parseSudoers(text) {
  const out = [];
  for (const raw of text.replace(/\\\n/g, ' ').split('\n')) {
    const line = raw.trim();
    // Comments (#1000 is a user ID rule, not one), includes, Defaults and aliases are not grants.
    if (!line || /^#(?!\d)/.test(line) || /^@|^(Defaults\b|\w+_Alias\b)/.test(line)) continue;
    const m = /^(\S+)\s+[^=]+=\s*(.+)$/.exec(line);
    if (!m) continue;
    const who = m[1].split(',').filter((w) => !['root', '%sudo', '%admin'].includes(w)).join(',');
    if (!who) continue;
    const cmds = m[2].replace(/^\([^)]*\)\s*/, ''); // the runas list (ALL) grants nothing
    const nopasswd = /\bNOPASSWD:/.test(cmds);
    const all = /(^|[\s:,])ALL\b/.test(cmds);
    if (nopasswd && all) out.push({ who, level: 'critical' });
    else if (nopasswd || all) out.push({ who, level: 'warning' });
  }
  return out;
}

/** `dpkg -V` lines (`??5??????   /path`, or `??5?????? c /path` for a conffile) → [{ path, conffile }] whose digest changed. */
export function parseDpkgV(text) {
  const out = [];
  for (const l of text.split('\n')) {
    const m = /^(\S{9}) (.) (\/.+)$/.exec(l);
    if (m && m[1][2] === '5') out.push({ path: m[3], conffile: m[2] === 'c' });
  }
  return out;
}

/** `sshd -T` → { setting: value }, names lower-case; the first value wins, as in sshd. */
export function parseSshdT(text) {
  const c = {};
  for (const l of text.split('\n')) { const i = l.indexOf(' '); if (i > 0 && !(l.slice(0, i) in c)) c[l.slice(0, i)] = l.slice(i + 1).trim(); }
  return c;
}

// Self-check: node src/lib/integrity.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const assert = (await import('node:assert')).strict;
  assert.deepEqual(parsePasswd('root:x:0:0:root:/root:/bin/bash\nwsvc:x:1097:1097::/home/wsvc:/bin/bash\nbad\nsite:x:1001:1001::/x:/usr/sbin/nologin'), [
    { name: 'root', uid: 0, home: '/root', shell: '/bin/bash' }, { name: 'wsvc', uid: 1097, home: '/home/wsvc', shell: '/bin/bash' },
    { name: 'site', uid: 1001, home: '/x', shell: '/usr/sbin/nologin' }]);
  assert.equal(hasLoginShell({ shell: '/usr/sbin/nologin' }), false);
  assert.equal(hasLoginShell({ shell: '/bin/bash' }), true);
  assert.deepEqual(parseSudoers([
    '# comment', '#1001 ALL=(ALL) NOPASSWD: ALL', 'Defaults env_reset', 'Cmnd_Alias X = /bin/ls', 'root ALL=(ALL:ALL) ALL', '%sudo ALL=(ALL:ALL) ALL',
    'wsvc ALL=(ALL) NOPASSWD: ALL', 'bob ALL=(ALL) \\', '  /usr/bin/ls', 'carol ALL=(ALL) NOPASSWD: /usr/bin/systemctl', 'dave ALL=(ALL) ALL',
  ].join('\n')), [{ who: '#1001', level: 'critical' }, { who: 'wsvc', level: 'critical' }, { who: 'carol', level: 'warning' }, { who: 'dave', level: 'warning' }]);
  assert.deepEqual(parseDpkgV('??5?????? c /etc/ssh/sshd_config\n??5??????   /usr/sbin/nginx\n.M.??????   /x\nmissing   /usr/bin/y\n??.??????   /usr/bin/z'), [
    { path: '/etc/ssh/sshd_config', conffile: true }, { path: '/usr/sbin/nginx', conffile: false }]);
  assert.equal(parseSshdT('authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nport 22\nport 2222').authorizedkeysfile, '.ssh/authorized_keys .ssh/authorized_keys2');
  assert.equal(parseSshdT('port 22\nport 2222').port, '22');
  console.log('integrity ok');
}
