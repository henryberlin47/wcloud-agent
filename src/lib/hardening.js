import fs from 'node:fs/promises';
import { run } from './sys.js';

// ============================================================
//  hardening.js — kernel network and filesystem hardening (sysctl)
// ============================================================
// One drop-in, /etc/sysctl.d/99-wcloud-hardening.conf. The agent's unit mounts
// /proc/sys read-only (ProtectKernelTunables), so the values are written by a
// transient unit (systemd-run), as lib/ssh.js does. Turning it off removes the
// file only: the live values stay until the next boot.

// 99-: systemd's 99-protect-links.conf sets fs.protected_fifos = 1 and sysctl loads files by name, so ours must sort after it.
export const SYSCTL_FILE = '/etc/sysctl.d/99-wcloud-hardening.conf';
export const HARDENING = [
  ['net.ipv4.tcp_syncookies', 1], // SYN floods
  ['net.ipv4.conf.all.rp_filter', 2], // spoofed sources; 2 = loose, strict breaks multi-homed and asymmetric routing
  ['net.ipv4.conf.all.accept_redirects', 0], ['net.ipv4.conf.default.accept_redirects', 0],
  ['net.ipv6.conf.all.accept_redirects', 0], ['net.ipv6.conf.default.accept_redirects', 0],
  ['net.ipv4.conf.all.send_redirects', 0], ['net.ipv4.conf.default.send_redirects', 0],
  ['net.ipv4.conf.all.accept_source_route', 0], ['net.ipv4.conf.default.accept_source_route', 0],
  ['net.ipv6.conf.all.accept_source_route', 0], ['net.ipv6.conf.default.accept_source_route', 0],
  ['net.ipv4.icmp_echo_ignore_broadcasts', 1], // smurf amplification
  ['net.ipv4.conf.all.log_martians', 1], // impossible source addresses end up in the journal
  ['kernel.kptr_restrict', 2], ['kernel.dmesg_restrict', 1], // hide kernel addresses from local users
  ['fs.protected_symlinks', 1], ['fs.protected_hardlinks', 1], ['fs.protected_fifos', 2], ['fs.protected_regular', 2],
  ['fs.suid_dumpable', 0], // no core dumps of setuid programs
];

export const hardeningFile = () => '# Managed by wcloud (agent lib/hardening.js). Remove the file to turn hardening off.\n'
  + HARDENING.map(([k, v]) => `${k} = ${v}`).join('\n') + '\n';

const procPath = (key) => `/proc/sys/${key.replaceAll('.', '/')}`;

// { file (the drop-in is in place), applied (every live value matches),
//   mismatches: [{ key, want, now }], settings: [[key, value]] }. A key this kernel doesn't have (no IPv6) is skipped.
export async function hardeningStatus() {
  const file = (await fs.readFile(SYSCTL_FILE, 'utf8').catch(() => null)) === hardeningFile();
  const mismatches = [];
  for (const [key, want] of HARDENING) {
    const now = await fs.readFile(procPath(key), 'utf8').then((s) => s.trim(), () => null);
    if (now !== null && now !== String(want)) mismatches.push({ key, want, now });
  }
  return { file, applied: mismatches.length === 0, mismatches, settings: HARDENING };
}

// Writes the drop-in and loads it. Turning it off only removes the file: the
// values stay until the next boot, and there is no default to put back.
export async function setHardening(helpers, on) {
  if (!on) {
    await fs.rm(SYSCTL_FILE, { force: true });
    return hardeningStatus();
  }
  await fs.writeFile(SYSCTL_FILE, hardeningFile(), { mode: 0o644 });
  await run(helpers, 'systemd-run', ['--pipe', '--wait', '--quiet', '--collect', '--service-type=exec', '/usr/sbin/sysctl', '--system'],
    { quiet: true, timeout: 60_000 });
  return hardeningStatus();
}

// Self-check: node src/lib/hardening.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const assert = (await import('node:assert')).strict;
  const lines = hardeningFile().split('\n').filter((l) => l && !l.startsWith('#'));
  assert.equal(lines.length, HARDENING.length);
  assert.ok(lines.includes('net.ipv4.conf.all.rp_filter = 2'));
  assert.ok(lines.includes('fs.protected_regular = 2'));
  assert.ok(lines.every((l) => /^[a-z0-9_.]+ = \d+$/.test(l)));
  assert.equal(procPath('net.ipv4.conf.all.rp_filter'), '/proc/sys/net/ipv4/conf/all/rp_filter');
  console.log('hardening ok');
}
