import fs from 'node:fs/promises';
import { run, withLock, pathExists } from './sys.js';
import { APT_ENV, APT_LOCK } from './stack.js';

// ============================================================
//  updates.js — operating-system package updates (apt)
// ============================================================
// What is pending comes from apt's own simulation of a full upgrade on the
// cached lists, so the status works offline. A package is a security update
// when one of its origins is a *-security pocket. Installs refresh the lists
// first and then name the packages they install.

export const REBOOT_FILE = '/var/run/reboot-required';
const AUTO_FILE = '/etc/apt/apt.conf.d/20auto-upgrades';
const CONF = ['-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold'];

// An `Inst` line is a package apt would install or upgrade:
//   Inst liblzma5 [5.6.1-a] (5.6.1-b Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])
// The bracketed old version is missing for a package that is new.
const INST = /^Inst (\S+) (?:\[[^\]]*\] )?\((\S+) ([^)]*)\)/;

// Exported for the self-check.
export function parseSimulation(text) {
  const pkgs = [];
  for (const line of String(text).split('\n')) {
    const m = INST.exec(line);
    if (m) pkgs.push({ name: m[1], security: /-security\b/.test(m[3]) });
  }
  pkgs.sort((a, b) => Number(b.security) - Number(a.security));
  return { pending: pkgs.length, security: pkgs.filter((p) => p.security).map((p) => p.name), packages: pkgs };
}

async function simulate(helpers) {
  const r = await run(helpers, 'apt-get', ['-s', 'dist-upgrade'], { env: APT_ENV, quiet: true, timeout: 120_000 });
  if (r.code !== 0) throw new Error('apt could not work out the pending updates (is dpkg interrupted?).');
  return parseSimulation(r.stdout);
}

async function aptUpdate(helpers) {
  const r = await run(helpers, 'apt-get', [...APT_LOCK, 'update', '-qq'], { env: APT_ENV, timeout: 300_000 });
  if (r.code !== 0) throw new Error('apt could not refresh its package lists (see the log above).');
}

async function autoState(helpers) {
  const installed = (await run(helpers, 'dpkg-query', ['-W', '-f=${db:Status-Status}', 'unattended-upgrades'], { quiet: true, timeout: 15_000 })).stdout.trim() === 'installed';
  const conf = await fs.readFile(AUTO_FILE, 'utf8').catch(() => '');
  return { installed, enabled: installed && /APT::Periodic::Unattended-Upgrade\s+"1"/.test(conf) };
}

// { pending, security, packages: [{ name, security }] (security first, ≤50 shown),
//   reboot: { required, packages }, unattended: { installed, enabled } }
export async function updateStatus(helpers, { refresh = false } = {}) {
  if (refresh) await withLock('apt', () => aptUpdate(helpers));
  const sim = await simulate(helpers);
  const reboot = await pathExists(REBOOT_FILE);
  const rebootPkgs = reboot ? (await fs.readFile(`${REBOOT_FILE}.pkgs`, 'utf8').catch(() => '')).split('\n').filter(Boolean) : [];
  return {
    pending: sim.pending,
    security: sim.security.length,
    packages: sim.packages.slice(0, 50),
    reboot: { required: reboot, packages: rebootPkgs },
    unattended: await autoState(helpers),
  };
}

// Refresh the lists, then install: the security packages by name (exactly what
// the status counts) or everything (dist-upgrade). Returns the names installed.
export function installUpdates(helpers, which) {
  return withLock('apt', async () => {
    await run(helpers, 'dpkg', ['--force-confdef', '--force-confold', '--configure', '-a'], { env: APT_ENV, timeout: 300_000 });
    await aptUpdate(helpers);
    const sim = await simulate(helpers);
    const names = which === 'security' ? sim.security : sim.packages.map((p) => p.name);
    if (!names.length) return [];
    const args = which === 'security' ? ['install', '--only-upgrade', '-y', '-q', ...names] : ['dist-upgrade', '-y', '-q'];
    const r = await run(helpers, 'apt-get', [...APT_LOCK, ...CONF, ...args], { env: APT_ENV, timeout: 3_600_000 });
    if (r.code !== 0) throw new Error('The updates could not be installed (see the log above).');
    return names;
  });
}

// Unattended security upgrades every day (the lists refresh daily too). The
// package's own 50unattended-upgrades decides the origins: security only.
export function setAutoSecurity(helpers, on) {
  return withLock('apt', async () => {
    if (on && !(await autoState(helpers)).installed) {
      const r = await run(helpers, 'apt-get', [...APT_LOCK, ...CONF, 'install', '-y', '-q', 'unattended-upgrades'], { env: APT_ENV, timeout: 900_000 });
      if (r.code !== 0) throw new Error('unattended-upgrades could not be installed (see the log above).');
    }
    await fs.writeFile(AUTO_FILE, `// Managed by wcloud (agent lib/updates.js)\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "${on ? 1 : 0}";\n`, { mode: 0o644 });
  });
}

// A minute from now, so the job can finish and report. `shutdown -c` cancels it.
export const scheduleReboot = (helpers) => run(helpers, 'shutdown', ['-r', '+1', 'Rebooting after updates (wcloud)'], { timeout: 30_000 });

// Self-check: node src/lib/updates.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const assert = (await import('node:assert')).strict;
  const p = parseSimulation([
    'Inst liblzma5 [5.6.1+really5.4.5-1ubuntu0.3] (5.6.1+really5.4.5-1ubuntu0.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])',
    'Conf liblzma5 (5.6.1+really5.4.5-1ubuntu0.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])',
    'Inst systemd-timesyncd [255.4-1ubuntu8.17] (255.4-1ubuntu8.19 Ubuntu:24.04/noble-updates [arm64]) []',
    'Inst newpkg (1.0 Ubuntu:24.04/noble-security [amd64])',
    'Remv oldpkg [1.0]',
  ].join('\n'));
  assert.equal(p.pending, 3);
  assert.deepEqual(p.security, ['liblzma5', 'newpkg']);
  assert.deepEqual(p.packages.map((x) => x.name), ['liblzma5', 'newpkg', 'systemd-timesyncd']);
  assert.equal(parseSimulation('').pending, 0);
  console.log('updates ok');
}
