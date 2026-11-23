// ============================================================
//  integrity-worker.js — intrusion checks, as root OUTSIDE the agent's sandbox
// ============================================================
// lib/integrity.js runs this through `systemd-run --pipe` (as sshkeys.js is):
// /root and /home are hidden from the agent itself. Prints one JSON object:
//   { findings: [{ key, severity: critical|warning|info, title, detail }] }
// or { error } and exit 1. A key names the thing (`user:wsvc`, `pkg:/usr/sbin/nginx`),
// so it stays the same from scan to scan. Builtins only, apart from ./lib/integrity.js.
// Every list is bounded; a check that can't run (no mysql, no git) reports nothing.
// ============================================================
import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parsePasswd, hasLoginShell, parseSudoers, parseDpkgV, parseSshdT } from './lib/integrity.js';

const SELF = fileURLToPath(import.meta.url);
const REPO = path.resolve(path.dirname(SELF), '..'); // the agent checkout (REPO_ROOT in server.js)
const MAX = 50;
const SEV = ['critical', 'warning', 'info'];
const SETUID_DIRS = ['/usr/local', '/opt', '/tmp', '/var/tmp', '/dev/shm', '/home', '/root', '/srv', '/var/www'];
const TEMP_DIRS = ['/tmp', '/var/tmp', '/dev/shm'];
// Packages whose files an attacker replaces (`dpkg -V`); conffiles are edited on purpose, so they are skipped.
const PKGS = ['openssh-server', 'openssh-client', 'sudo', 'nginx', 'nginx-common', 'login', 'passwd', 'libpam-modules', 'libpam-runtime', 'coreutils', 'procps', 'util-linux'];
const TOOLS = { hashcat: 'critical', john: 'critical', hydra: 'critical', masscan: 'critical', zmap: 'critical', xmrig: 'critical', minerd: 'critical', cpuminer: 'critical', chisel: 'critical', frpc: 'critical', ngrok: 'critical', nmap: 'warning' };
const OWN_UNITS = ['wcloud.service', 'wcloud-firewall.service'];
const CRON_HEAD = '# wcloud: scheduled jobs for '; // lib/cron.js renderCron: wcloud's own per-site files
const ACME_CRON = /\/acme\.sh --cron --home /; // acme.sh's renewal line in root's crontab (lib/acme.js)
const RANSOM_SQL = "SELECT table_schema, COUNT(*) FROM information_schema.tables WHERE table_name IN ('RECOVER_YOUR_DATA','x_BACKUP_META') OR table_name LIKE '%\\_ORIGINAL' OR table_name LIKE '%README%' GROUP BY table_schema";

// Stdout even when the command exits non-zero (dpkg -V and find do); '' when it can't run.
const sh = (cmd, args, timeout = 20_000) => new Promise((resolve) => {
  execFile(cmd, args, { timeout, maxBuffer: 32 << 20 }, (err, stdout) => resolve(String(stdout || '')));
});
const lines = (s) => s.split('\n').filter(Boolean).slice(0, MAX);
const readText = (f) => fs.readFile(f, 'utf8').catch(() => '');
const names = (dir) => fs.readdir(dir).catch(() => []);
const isFile = (f) => fs.lstat(f).then((st) => st.isFile(), () => false);
// The paths a package installed: dpkg -S prints one line per file it knows; anything else is unowned.
async function owned(files) {
  if (!files.length) return new Set();
  return new Set((await sh('dpkg', ['-S', ...files])).split('\n').map((l) => l.slice(l.indexOf(': ') + 2)));
}

async function scan() {
  const findings = [];
  const add = (key, severity, title, detail) => findings.push({ key, severity, title, detail });

  // 1. Login accounts (root is always there; site users have nologin).
  for (const u of parsePasswd(await readText('/etc/passwd')).filter((u) => hasLoginShell(u) && (u.uid === 0 || u.uid >= 1000)).slice(0, MAX)) {
    if (u.uid === 0 && u.name !== 'root') add(`uid0:${u.name}`, 'critical', `Second root account: ${u.name}`, 'User ID 0 has root\'s rights.');
    if (u.name !== 'root') add(`user:${u.name}`, 'info', `Login account: ${u.name}`, `uid ${u.uid}, shell ${u.shell}`);
  }

  // 2. sudo rules granting ALL or NOPASSWD to anyone but root and the admin groups.
  const sudoFiles = ['/etc/sudoers', ...(await names('/etc/sudoers.d')).filter((n) => !/[.~]/.test(n)).map((n) => `/etc/sudoers.d/${n}`)];
  const sudoPkg = await owned(sudoFiles.filter((f) => f !== '/etc/sudoers'));
  for (const f of sudoFiles) {
    for (const r of parseSudoers(await readText(f)).slice(0, MAX)) {
      // A package's own file (cloud-init's default user) is a warning; a file nobody's package put there is critical.
      const level = r.level === 'critical' && sudoPkg.has(f) ? 'warning' : r.level;
      add(`sudo:${f}:${r.who}`, level, `Sudo rule for ${r.who} in ${f}`, level === 'critical' ? 'No password: any command as root.' : 'Sudo rights for this user.');
    }
  }

  // 3. The dynamic linker: a preload file, or a library path no package put there.
  if (await fs.access('/etc/ld.so.preload').then(() => true, () => false)) {
    add('preload', 'critical', '/etc/ld.so.preload exists', 'Every program loads the libraries listed there, a common way to hide a backdoor.');
  }
  const ld = (await names('/etc/ld.so.conf.d')).filter((n) => n.endsWith('.conf')).map((n) => `/etc/ld.so.conf.d/${n}`).slice(0, MAX);
  const ldPkg = await owned(ld);
  for (const f of ld.filter((f) => !ldPkg.has(f))) add(`ldso:${f}`, 'critical', `Library path not from a package: ${f}`, 'The dynamic linker searches the directories it lists.');

  // 4. Set-user-ID / set-group-ID files where nothing should have them; programs in temp directories.
  for (const p of lines(await sh('find', [...SETUID_DIRS, '-xdev', '-type', 'f', '-perm', '/6000', '-print']))) {
    add(`setuid:${p}`, 'critical', `Set-user-ID or set-group-ID file: ${p}`, 'Runs with its owner\'s rights (usually root). Only system packages ship these.');
  }
  for (const p of lines(await sh('find', [...TEMP_DIRS, '-xdev', '-type', 'f', '-perm', '/111', '-print']))) {
    add(`tmpexec:${p}`, 'warning', `Executable in a temporary directory: ${p}`, 'Anyone can write there, so nothing should run from it.');
  }

  // 5. Known attack and mining tools installed anywhere a program would be run from.
  const toolNames = Object.keys(TOOLS).flatMap((n, i) => [...(i ? ['-o'] : []), '-name', n]);
  for (const p of lines(await sh('find', ['/usr/bin', '/usr/local/bin', '/usr/sbin', '/opt', '-maxdepth', '3', '(', ...toolNames, ')', '-a', '(', '-type', 'f', '-o', '-type', 'l', ')', '-print']))) {
    const name = path.basename(p);
    add(`tool:${p}`, TOOLS[name], TOOLS[name] === 'critical' ? `Known attack or mining tool: ${name}` : `Network scanner: ${name}`, `Found at ${p}.`);
  }

  // 6. Files of the packages that matter that no longer match what they installed.
  for (const f of parseDpkgV(await sh('dpkg', ['-V', ...PKGS])).filter((f) => !f.conffile).slice(0, MAX)) {
    add(`pkg:${f.path}`, 'critical', `Modified package file: ${f.path}`, 'Its content no longer matches the package it came from.');
  }

  // 7. Systemd units, cron files and crontabs that no package put there. wcloud's own are known.
  const unitDir = '/etc/systemd/system';
  const unitFiles = [];
  for (const n of (await names(unitDir)).filter((n) => n.endsWith('.service') && !OWN_UNITS.includes(n)).slice(0, MAX)) {
    const f = path.join(unitDir, n);
    const st = await fs.lstat(f).catch(() => null);
    if (!st) continue;
    // Symlinks into /lib or /usr/lib (packages) and masks (/dev/null) are not ours to judge.
    const target = st.isSymbolicLink() ? path.resolve(unitDir, await fs.readlink(f).catch(() => '')) : '';
    if (!/^(\/usr)?\/lib\/|^\/dev\/null$/.test(target)) unitFiles.push(f);
  }
  const unitPkg = await owned(unitFiles);
  for (const f of unitFiles.filter((f) => !unitPkg.has(f))) add(`unit:${f}`, 'info', `Systemd unit not from a package: ${f}`, 'It starts at boot and no package installed it.');

  const cronDir = '/etc/cron.d';
  const cronFiles = [];
  for (const n of (await names(cronDir)).filter((n) => !/[.~]/.test(n)).slice(0, MAX)) {
    const f = path.join(cronDir, n);
    if (await isFile(f)) cronFiles.push(f);
  }
  const cronPkg = await owned(cronFiles);
  for (const f of cronFiles.filter((f) => !cronPkg.has(f))) {
    if (path.basename(f).startsWith('wcloud-') && (await readText(f)).startsWith(CRON_HEAD)) continue;
    add(`cron:${f}`, 'info', `Cron job not from a package: ${f}`, 'It runs on a schedule and no package installed it.');
  }

  const crontabDir = '/var/spool/cron/crontabs';
  for (const u of (await names(crontabDir)).slice(0, MAX)) {
    const jobs = (await readText(path.join(crontabDir, u))).split('\n').filter((l) => l.trim() && !/^\s*#/.test(l) && !ACME_CRON.test(l));
    if (jobs.length) add(`crontab:${u}`, 'info', `Crontab of user: ${u}`, `${jobs.length} scheduled line(s).`);
  }

  // 8. sshd: keys read from somewhere besides the default files, or by a program; root with a password.
  const cfg = parseSshdT(await sh('/usr/sbin/sshd', ['-T']));
  const akf = (cfg.authorizedkeysfile || '').split(/\s+/).join(' ');
  if (akf && akf !== '.ssh/authorized_keys .ssh/authorized_keys2') add('sshd:authorizedkeysfile', 'critical', 'sshd reads extra authorized_keys files', `AuthorizedKeysFile: ${akf}`);
  if (cfg.authorizedkeyscommand && cfg.authorizedkeyscommand !== 'none') add('sshd:authorizedkeyscommand', 'critical', 'sshd runs a program to find keys', `AuthorizedKeysCommand: ${cfg.authorizedkeyscommand}`);
  if (cfg.permitrootlogin === 'yes' && cfg.passwordauthentication === 'yes') add('sshd:rootlogin', 'warning', 'Root can log in with a password', 'PermitRootLogin yes and PasswordAuthentication yes.');

  // 9. Root's own private keys: one planted there lets root log in to other machines.
  const rootSsh = '/root/.ssh';
  for (const n of (await names(rootSsh)).filter((n) => /^id_/.test(n) && !n.endsWith('.pub')).slice(0, MAX)) {
    if (await isFile(path.join(rootSsh, n))) add(`rootkey:${n}`, 'info', `Private key in root's home: ${n}`, 'root can use it to log in to other machines.');
  }

  // 10. Ransomware leftovers in MariaDB: its note and the originals it kept. Nothing when MariaDB isn't here.
  for (const l of lines(await sh('mysql', ['-N', '-B', '-e', RANSOM_SQL]))) {
    const db = l.split('\t')[0];
    add(`ransom:${db}`, 'critical', `Ransom tables in database: ${db}`, 'Tables a ransom note leaves behind (RECOVER_YOUR_DATA, *_ORIGINAL, *README*).');
  }

  // 11. The agent's own code: a tracked file that differs from git. Untracked files (node_modules) are not judged.
  for (const l of lines(await sh('git', ['--no-optional-locks', '-C', REPO, 'status', '--porcelain', '-uno']))) {
    const f = l.slice(3);
    add(`agentcode:${f}`, 'critical', `Changed agent file: ${f}`, 'The agent runs as root and this file differs from its git version.');
  }

  return findings.sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
}

if (process.argv[1] === SELF) {
  try {
    process.stdout.write(JSON.stringify({ findings: await scan() }));
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: e.message }));
    process.exitCode = 1;
  }
}
