import fs from 'node:fs/promises';
import os from 'node:os';
import { run, pathExists } from './sys.js';
import { logger } from './log.js';

// ============================================================
//  stack.js — the server's shared services: PHP-FPM, MariaDB, Redis
// ============================================================
// init.sh installs the base stack (nginx, MariaDB, Redis, the default PHP);
// everything per-site goes through here. PHP versions beyond the default are
// installed on demand the first time a site asks for one.

// Offered PHP versions (ondrej/php PPA). DEFAULT_PHP is what init.sh installs.
export const PHP_VERSIONS = ['8.1', '8.2', '8.3', '8.4'];
export const DEFAULT_PHP = '8.3';
// Keep in sync with PHP_EXTS in init.sh.
const PHP_EXTS = ['fpm', 'cli', 'mysql', 'curl', 'gd', 'intl', 'mbstring', 'xml', 'zip', 'bcmath', 'soap', 'imagick', 'redis', 'opcache'];

export const fpmService = (v) => `php${v}-fpm`;
export const phpBin = (v) => `/usr/bin/php${v}`;

const APT_ENV = { DEBIAN_FRONTEND: 'noninteractive', NEEDRESTART_MODE: 'a', NEEDRESTART_SUSPEND: '1' };
// Wait out unattended-upgrades instead of failing on its dpkg lock.
const APT_LOCK = ['-o', 'DPkg::Lock::Timeout=600'];

// Installed PHP-FPM versions, oldest first.
export async function installedPhp() {
  const out = [];
  for (const v of PHP_VERSIONS) if (await pathExists(`/usr/sbin/php-fpm${v}`)) out.push(v);
  return out;
}

// Install a PHP version (FPM + CLI + WordPress extensions) if it isn't there.
export async function ensurePhp(helpers, v) {
  if (!PHP_VERSIONS.includes(v)) throw new Error(`PHP ${v} is not offered.`);
  if (await pathExists(`/usr/sbin/php-fpm${v}`)) return;
  const { info, ok } = logger(helpers);
  info(`PHP ${v} isn't installed on this server yet — installing it (a minute or two)`);
  await run(helpers, 'apt-get', [...APT_LOCK, 'update', '-qq'], { env: APT_ENV, timeout: 300_000 });
  const r = await run(helpers, 'apt-get', [...APT_LOCK, 'install', '-y', '-q',
    '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold',
    ...PHP_EXTS.map((e) => `php${v}-${e}`)], { env: APT_ENV, timeout: 900_000 });
  if (r.code !== 0) throw new Error(`PHP ${v} could not be installed on this server.`);
  await writePlaceholderPool(v);
  await writeOpcacheIni(v);
  await run(helpers, 'systemctl', ['enable', '--now', fpmService(v)], { timeout: 60_000 });
  await run(helpers, 'systemctl', ['restart', fpmService(v)], { timeout: 60_000 });
  ok(`PHP ${v} installed`);
}

// The package's default `www` pool runs as www-data — the group that can read
// every site. Nothing may use it, but php-fpm refuses to start with zero pools,
// so it's replaced by an inert one: nobody, root-only socket, no idle workers.
// init.sh writes the same for the default version.
async function writePlaceholderPool(v) {
  await fs.writeFile(`/etc/php/${v}/fpm/pool.d/www.conf`, [
    '; wcloud: placeholder so php-fpm starts with no sites. Site pools are <domain>.conf.',
    '[www]',
    'user = nobody',
    'group = nogroup',
    `listen = /run/php/php${v}-fpm.sock`,
    'listen.owner = root',
    'listen.group = root',
    'listen.mode = 0600',
    'pm = ondemand',
    'pm.max_children = 1',
    '',
  ].join('\n'));
}

// OPcache for a PHP version's FPM (shared by every site on that version).
//  • validate_permission/validate_root: without them, one site's PHP can
//    load ANOTHER site's already-compiled files (e.g. its wp-config.php, and
//    so its DB password) straight from the shared cache — the classic
//    shared-hosting leak. With them, a cached file is only served to a process
//    that could read the file itself.
//  • sized to the server: RAM/8, between 128 and 512 MB.
//  • timestamps still checked (every 2s): edits from the file manager, plugin
//    updates and deploys take effect without a PHP reload.
function opcacheIni() {
  const mb = Math.min(512, Math.max(128, Math.floor(os.totalmem() / 1024 / 1024 / 8)));
  return [
    '; Managed by wcloud (src/lib/stack.js) — rewritten when the agent starts.',
    'opcache.enable=1',
    `opcache.memory_consumption=${mb}`,
    'opcache.interned_strings_buffer=32',
    'opcache.max_accelerated_files=100000',
    'opcache.validate_timestamps=1',
    'opcache.revalidate_freq=2',
    'opcache.validate_permission=1',
    'opcache.validate_root=1',
    'opcache.save_comments=1',
    '',
  ].join('\n');
}
const opcacheIniPath = (v) => `/etc/php/${v}/fpm/conf.d/90-wcloud-opcache.ini`;
async function writeOpcacheIni(v) {
  const want = opcacheIni();
  const have = await fs.readFile(opcacheIniPath(v), 'utf8').catch(() => null);
  if (have === want) return false;
  await fs.writeFile(opcacheIniPath(v), want, { mode: 0o644 });
  return true;
}

// Called at agent start: every installed version gets the current OPcache
// settings (so existing servers pick up a change on the next agent update);
// only versions whose file changed are reloaded.
export async function ensurePhpTuning(helpers) {
  for (const v of await installedPhp()) {
    if (await writeOpcacheIni(v)) await run(helpers, 'systemctl', ['reload-or-restart', fpmService(v)], { quiet: true, timeout: 60_000 });
  }
}

// --- MariaDB (root via unix socket; SQL on stdin, so no password hits argv) --

const sql = (helpers, statements) =>
  run(helpers, 'mysql', ['--batch'], { stdin: statements.join('\n') + '\n', timeout: 60_000 });

// name is a site user ([a-z0-9_], ≤32) — safe inside backticks/quotes.
export async function createDatabase(helpers, name, password) {
  const r = await sql(helpers, [
    `CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`,
    `CREATE USER '${name}'@'localhost' IDENTIFIED BY '${password}';`,
    `GRANT ALL PRIVILEGES ON \`${name}\`.* TO '${name}'@'localhost';`,
  ]);
  if (r.code !== 0) throw new Error('The site database could not be created.');
}

export async function dropDatabase(helpers, name) {
  const r = await sql(helpers, [
    `DROP DATABASE IF EXISTS \`${name}\`;`,
    `DROP USER IF EXISTS '${name}'@'localhost';`,
  ]);
  return r.code === 0;
}

// --- Redis (one ACL user + one database per site) ----------------------------
// init.sh turns the passwordless default user off and stores an admin password
// for the agent. A site's object cache (Redis Object Cache plugin) logs in as
// its own user: it may only SELECT its own database and only touch `<user>:*`
// keys; KEYS/CONFIG/FLUSHALL and the rest of @dangerous are denied. Two are
// given back because the plugin needs them: FLUSHDB (its enable step) — it can
// only empty the site's own database, or database 0, which no site uses — and
// INFO (read on every connect; server stats only, no data).
export const REDIS_DBS = 1024; // init.sh sets `databases` to this

const REDIS_ADMIN = '/etc/wcloud/redis-admin.pass';

async function redis(helpers, commands) {
  if (!(await pathExists(REDIS_ADMIN))) return { code: 1 };
  const pass = (await fs.readFile(REDIS_ADMIN, 'utf8')).trim();
  // Password via env, commands via stdin: neither appears in argv.
  return run(helpers, 'redis-cli', ['--user', 'wcloud', '--no-auth-warning'],
    { env: { REDISCLI_AUTH: pass }, stdin: commands.join('\n') + '\n', quiet: true, timeout: 30_000 });
}

export async function createRedisUser(helpers, name, password, db) {
  const r = await redis(helpers, [
    `ACL SETUSER ${name} reset on >${password} ~${name}:* +@all -@dangerous +flushdb +info -select +select|${db}`,
    'ACL SAVE',
  ]);
  // redis-cli exits 0 even when a command errors; the reply text says.
  return r.code === 0 && !/ERR/.test(r.stdout);
}

// Remove the login and empty its database (so nothing of the site lingers).
export async function dropRedisUser(helpers, name, db) {
  await redis(helpers, [`ACL DELUSER ${name}`, 'ACL SAVE', ...(db ? [`SELECT ${db}`, 'FLUSHDB'] : [])]);
}
