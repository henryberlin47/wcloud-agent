import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import config from '../config.js';
import { run, pathExists, removePath, userIds, nginxTest, nginxReload, sleep } from './sys.js';
import { logger } from './log.js';
import { ensurePhp, installedPhp, fpmService, dropDatabase, dropRedisUser, REDIS_DBS } from './stack.js';
import { setupWordPress, pinWpUrls } from './wp.js';

// ============================================================
//  sites.js — the site model: one spec file → everything else
// ============================================================
// /etc/wcloud/sites/<domain>.json is the source of truth for a site. The nginx
// vhost and PHP-FPM pool are RENDERED from it (never edited in place), and a
// spec change is applied as one transaction: write everything, `nginx -t` +
// `php-fpm -t`, and on failure every file returns to its exact prior state.
// Improving a template and re-applying fixes every site the same way.
//
// Layout (per site, isolated by its own Linux user):
//   /var/www/<d>/              root 0711   (site can't rename what's inside)
//   /var/www/<d>/htdocs/       <user>:www-data 2750  (nginx reads via group)
//   /var/www/<d>/wp-config.php <user> 0600
//   /var/www/<d>/tmp/          <user> 0700  (uploads, sessions, wp-cli cache)
//   /var/www/<d>/conf/nginx/   root 0755   (custom rules, included in the vhost)
//   /etc/nginx/sites-enabled/<d>.conf, /etc/php/<v>/fpm/pool.d/<d>.conf
//   /etc/letsencrypt/live/<d>/{fullchain,key}.pem   (any issuer)
//
// Site types: wordpress (PHP) and static. Adding one (node, …) = a body in
// renderVhost + its setup in createSite.
// ============================================================

export const SITE_TYPES = ['wordpress', 'static'];

// phpMyAdmin: installed once per server by init.sh, served per WordPress site.
export const PMA_DIR = '/usr/share/wcloud-pma';
export const PMA_PATH = '/.wcloud-pma/';

const SPEC_DIR = '/etc/wcloud/sites';
export const siteDir = (d) => `${config.wwwDir}/${d}`;
export const webRoot = (d) => `${siteDir(d)}/htdocs`;
export const siteTmp = (d) => `${siteDir(d)}/tmp`;
const specPath = (d) => `${SPEC_DIR}/${d}.json`;
const vhostPath = (d) => `/etc/nginx/sites-enabled/${d}.conf`;
const poolPath = (d, v) => `/etc/php/${v}/fpm/pool.d/${d}.conf`;
const sockPath = (d) => `/run/php/wcloud-${d}.sock`;
export const phpLogPath = (d) => `/var/log/wcloud/${d}.php.log`;

export const certDir = (d) => `/etc/letsencrypt/live/${d}`;
export const fullchainPath = (d) => `${certDir(d)}/fullchain.pem`;
export const keyPath = (d) => `${certDir(d)}/key.pem`;

const SAFE_DOMAIN = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const USER_RE = /^[a-z][a-z0-9_]{0,31}$/;

// --- spec store -------------------------------------------------------------

export async function readSpec(domain) {
  if (!SAFE_DOMAIN.test(domain) || domain.includes('..')) return null;
  try { return JSON.parse(await fs.readFile(specPath(domain), 'utf8')); } catch { return null; }
}

export async function requireSpec(domain) {
  const s = await readSpec(domain);
  if (!s) throw new Error(`${domain} is not a site on this server.`);
  return s;
}

export async function listSites() {
  let names = [];
  try { names = await fs.readdir(SPEC_DIR); } catch { return []; }
  const out = [];
  for (const n of names.filter((f) => f.endsWith('.json')).sort()) {
    const s = await readSpec(n.slice(0, -5));
    if (s) out.push(s);
  }
  return out;
}

// What the portal sees (all of it is non-secret).
export const publicSpec = (s) => ({
  domain: s.domain, type: s.type, php: s.php || null, enableWww: s.enableWww,
  canonical: s.canonical, ssl: s.ssl, created_at: s.created_at,
});

// --- rendering ----------------------------------------------------------------

const server = (lines) => ['server {', ...lines.map((l) => (l ? `    ${l}` : '')), '}'].join('\n');

function siteBody(s) {
  const d = s.domain;
  const common = [
    `root ${webRoot(d)};`,
    `access_log /var/log/nginx/${d}.access.log;`,
    `error_log /var/log/nginx/${d}.error.log;`,
    '',
    '# Custom rules for this site (root-owned; not overwritten by wcloud).',
    `include ${siteDir(d)}/conf/nginx/*.conf;`,
    '',
    'location ~ /\\.(?!well-known/) { deny all; }',
  ];
  const assets = (fallback) =>
    `location ~* \\.(?:css|js|mjs|map|jpe?g|gif|png|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm|pdf)$ { expires 30d; access_log off; log_not_found off; try_files $uri ${fallback}; }`;

  if (s.type === 'static') {
    return [
      ...common,
      'index index.html index.htm;',
      'location / { try_files $uri $uri/ =404; }',
      assets('=404'),
    ];
  }
  // wordpress. Regex locations match in order: the denies must come first.
  return [
    ...common,
    'index index.php index.html;',
    'location ~* ^/wp-content/uploads/.*\\.php$ { deny all; }',
    'location / { try_files $uri $uri/ /index.php?$args; }',
    'location ~ \\.php$ {',
    '    try_files $uri =404;',
    '    include fastcgi_params;',
    '    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;',
    `    fastcgi_pass unix:${sockPath(d)};`,
    '    fastcgi_read_timeout 600s;',
    '    fastcgi_buffers 16 16k;',
    '    fastcgi_buffer_size 32k;',
    '}',
    assets('/index.php?$args'),
    '',
    // phpMyAdmin, reachable only through a single-use link from the panel
    // (lib/pma.js). Runs in THIS site's pool, as this site's user, signed in
    // with this site's DB login. ^~ wins over the regex locations above.
    `location ^~ ${PMA_PATH} {`,
    `    alias ${PMA_DIR}/;`,
    '    index index.php;',
    `    location ~ ^${PMA_PATH.replace(/\./g, '\\.')}(?:libraries|templates|vendor|sql|config)/ { deny all; }`,
    `    location ~ ^${PMA_PATH.replace(/\./g, '\\.')}(.+\\.php)$ {`,
    `        alias ${PMA_DIR}/$1;`,
    '        include fastcgi_params;',
    `        fastcgi_param SCRIPT_FILENAME ${PMA_DIR}/$1;`,
    `        fastcgi_pass unix:${sockPath(d)};`,
    '        fastcgi_read_timeout 600s;',
    '    }',
    '}',
  ];
}

export function renderVhost(s, { https }) {
  const d = s.domain;
  const www = `www.${d}`;
  const names = `server_name ${s.enableWww ? `${d} ${www}` : d};`;
  // A preferred address only means something when both are served.
  const canon = s.enableWww && s.canonical !== 'none' ? (s.canonical === 'www' ? www : d) : null;
  const other = canon === www ? d : www;
  const toCanon = (scheme) => (canon ? [`if ($host = ${other}) { return 301 ${scheme}://${canon}$request_uri; }`, ''] : []);
  const acme = 'location ^~ /.well-known/acme-challenge/ { root /var/www/html; default_type text/plain; try_files $uri =404; }';

  const out = [`# Managed by wcloud from ${specPath(d)} — regenerated on every change.`,
    `# Put custom rules in ${siteDir(d)}/conf/nginx/*.conf instead of editing this file.`];
  if (https) {
    out.push(server(['listen 80;', 'listen [::]:80;', names, acme,
      `location / { return 301 https://${canon || '$host'}$request_uri; }`]));
    out.push(server(['listen 443 ssl http2;', 'listen [::]:443 ssl http2;', names,
      `ssl_certificate     ${fullchainPath(d)};`, `ssl_certificate_key ${keyPath(d)};`, '',
      ...toCanon('https'), ...siteBody(s)]));
  } else {
    out.push(server(['listen 80;', 'listen [::]:80;', names, acme, '', ...toCanon('http'), ...siteBody(s)]));
  }
  return out.join('\n\n') + '\n';
}

export function renderPool(s) {
  const d = s.domain;
  const tmp = siteTmp(d);
  return [
    `; Managed by wcloud from ${specPath(d)} — regenerated on every change.`,
    `[${d}]`,
    `user = ${s.user}`,
    `group = ${s.user}`,
    `listen = ${sockPath(d)}`,
    'listen.owner = www-data',
    'listen.group = www-data',
    'listen.mode = 0660',
    // ondemand: an idle site costs no memory, which is what lets one server
    // hold hundreds of sites.
    'pm = ondemand',
    'pm.max_children = 20',
    'pm.process_idle_timeout = 30s',
    'pm.max_requests = 500',
    'request_terminate_timeout = 600s',
    `php_admin_value[error_log] = ${phpLogPath(d)}`,
    'php_admin_flag[log_errors] = on',
    `php_admin_value[upload_tmp_dir] = ${tmp}`,
    `php_admin_value[sys_temp_dir] = ${tmp}`,
    `php_admin_value[session.save_path] = ${tmp}`,
    'php_value[memory_limit] = 512M',
    'php_value[max_execution_time] = 600',
    'php_value[max_input_time] = 600',
    'php_value[max_input_vars] = 3000',
    'php_value[post_max_size] = 512M',
    'php_value[upload_max_filesize] = 512M',
    '',
  ].join('\n');
}

// --- apply (the one transaction every change goes through) -------------------

const readOrNull = async (p) => ((await pathExists(p)) ? fs.readFile(p, 'utf8') : null);

// Write the spec + everything rendered from it (and optionally a new cert
// pair) as ONE transaction. nginx -t and php-fpm -t must both pass, or every
// file returns to its exact prior state (including absence) and nothing is
// reloaded. Services reload only for files that actually changed.
//   certs:   { fullchain, key } — pre-validated by the caller, written 600
//   prevPhp: the version whose pool must go (PHP version switch)
export async function applySite(helpers, s, { certs, prevPhp } = {}) {
  const d = s.domain;
  const edits = []; // { path, before, after (null = delete), mode }
  const stage = async (path, after, mode = 0o644) => edits.push({ path, before: await readOrNull(path), after, mode });

  if (certs) {
    await fs.mkdir(certDir(d), { recursive: true, mode: 0o700 });
    const nl = (v) => (v.endsWith('\n') ? v : `${v}\n`);
    await stage(fullchainPath(d), nl(certs.fullchain), 0o600);
    await stage(keyPath(d), nl(certs.key), 0o600);
  }
  const https = s.ssl && (!!certs || (await pathExists(fullchainPath(d))));
  await fs.mkdir(SPEC_DIR, { recursive: true, mode: 0o700 });
  await stage(specPath(d), JSON.stringify(s, null, 2) + '\n', 0o600);
  await stage(vhostPath(d), renderVhost(s, { https }));
  if (s.php) await stage(poolPath(d, s.php), renderPool(s));
  if (prevPhp && prevPhp !== s.php) await stage(poolPath(d, prevPhp), null);

  const changed = edits.filter((e) => e.before !== e.after);
  if (!changed.length) return { changed: false };

  const put = async (e, content) => {
    if (content === null) return removePath(e.path);
    await fs.writeFile(e.path, content, { mode: e.mode });
    await fs.chmod(e.path, e.mode); // writeFile's mode only applies on create
  };
  const rollback = async () => { for (const e of changed) await put(e, e.before); };

  const poolVersions = [prevPhp, s.php].filter((v, i, a) => v && a.indexOf(v) === i &&
    changed.some((e) => e.path === poolPath(d, v)));
  let valid = false;
  try {
    for (const e of changed) await put(e, e.after);
    valid = await nginxTest(helpers);
    if (valid && poolVersions.includes(s.php)) {
      valid = (await run(helpers, `/usr/sbin/php-fpm${s.php}`, ['-t'], { timeout: 30_000 })).code === 0;
    }
  } catch (e) {
    await rollback(); // a write that throws midway must not leave half an edit
    throw e;
  }
  if (!valid) {
    await rollback();
    throw new Error('The new settings were rejected by the web server, so the previous settings were restored and nothing was reloaded. The site is unaffected.');
  }

  // Old version first (it lets go of the socket), then the new one.
  for (const v of poolVersions) await run(helpers, 'systemctl', ['reload-or-restart', fpmService(v)], { timeout: 60_000 });
  // A php-fpm reload returns before the new pool's socket exists: wait for it,
  // or the site's first requests after "ready" get a 502.
  if (poolVersions.includes(s.php)) {
    for (let i = 0; i < 50 && !(await pathExists(sockPath(d))); i++) await sleep(200);
  }
  if (changed.some((e) => !e.path.startsWith('/etc/php/') && e.path !== specPath(d))) await nginxReload(helpers);
  return { changed: true };
}

// HTTPS on, with the cert already in certDir or a new pair (joins the same
// transaction, so a chain nginx rejects restores the previous working cert).
export async function applySslConf(helpers, domain, { certs } = {}) {
  const s = await requireSpec(domain);
  await applySite(helpers, { ...s, ssl: true }, { certs });
  logger(helpers).ok('Web server reloaded with the new certificate');
}

// Point WordPress's own address (home/siteurl) at what nginx now serves.
export async function syncWpAddress(helpers, s) {
  if (s.type !== 'wordpress') return true;
  const https = s.ssl && (await pathExists(fullchainPath(s.domain)));
  const host = !s.enableWww || s.canonical === 'root' ? s.domain : s.canonical === 'www' ? `www.${s.domain}` : undefined;
  return pinWpUrls(helpers, s, { scheme: https ? 'https' : 'http', host });
}

// --- create / delete ------------------------------------------------------------

async function userExists(name) {
  try { await userIds(name); return true; } catch { return false; }
}

// example.com → example_com (readable in ps/top). Too long, not starting with a
// letter, or already taken → a hashed variant that stays unique per domain.
async function pickUser(domain) {
  const base = domain.replace(/[^a-z0-9]/g, '_');
  if (USER_RE.test(base) && !(await userExists(base))) return base;
  const hash = createHash('sha256').update(domain).digest('hex').slice(0, 8);
  const alt = `${base.slice(0, 23).replace(/^[^a-z]/, 's')}_${hash}`;
  if (USER_RE.test(alt) && !(await userExists(alt))) return alt;
  throw new Error(`Could not pick a system user for ${domain}.`);
}

// Lowest Redis database no site uses (0 stays empty on purpose; see stack.js).
async function freeRedisDb() {
  const used = new Set((await listSites()).map((x) => x.redisDb));
  for (let i = 1; i < REDIS_DBS; i++) if (!used.has(i)) return i;
  return null; // full: the site runs without an object cache
}

// Create a site: user, directories, the type's own setup, then apply. On any
// failure everything created so far is removed again.
//   o: { domain, type, php, enableWww, canonical, wp: {...} (see setupWordPress) }
export async function createSite(helpers, o) {
  const d = o.domain;
  if (await readSpec(d)) throw new Error(`${d} already exists on this server.`);
  if (await pathExists(siteDir(d))) throw new Error(`${siteDir(d)} already exists but isn't a wcloud site — move it away first.`);
  const php = o.type === 'wordpress' ? o.php : null;
  if (php) await ensurePhp(helpers, php);

  const user = await pickUser(d);
  const r = await run(helpers, 'useradd', ['--user-group', '--no-create-home', '--home-dir', siteDir(d), '--shell', '/usr/sbin/nologin', user], { timeout: 30_000 });
  if (r.code !== 0) throw new Error(`The site's system user could not be created.`);

  const s = { domain: d, type: o.type, php, user, enableWww: o.enableWww, canonical: o.canonical, ssl: false, created_at: new Date().toISOString() };
  if (s.type === 'wordpress') s.redisDb = await freeRedisDb();
  try {
    const { uid, gid } = await userIds(user);
    const wwwGid = (await userIds('www-data')).gid;
    const mk = async (p, mode, u, g) => { await fs.mkdir(p, { recursive: true }); await fs.chown(p, u, g); await fs.chmod(p, mode); };
    await mk(siteDir(d), 0o711, 0, 0);
    await mk(`${siteDir(d)}/conf/nginx`, 0o755, 0, 0);
    await mk(webRoot(d), 0o2750, uid, wwwGid);
    await mk(siteTmp(d), 0o700, uid, gid);
    await fs.mkdir('/var/log/wcloud', { recursive: true, mode: 0o755 });
    await (await fs.open(phpLogPath(d), 'a', 0o640)).close();
    await fs.chown(phpLogPath(d), uid, gid);

    if (s.type === 'wordpress') {
      await setupWordPress(helpers, s, o.wp || {});
    } else {
      const index = `${webRoot(d)}/index.html`;
      await fs.writeFile(index, `<!doctype html><title>${d}</title><h1>${d}</h1><p>Upload your site to replace this page.</p>\n`, { mode: 0o644 });
      await fs.chown(index, uid, wwwGid);
    }
    await applySite(helpers, s);
  } catch (e) {
    await deleteSite(helpers, d, s).catch(() => {});
    throw e;
  }
  return s;
}

// Remove a site completely. Idempotent: every step tolerates "already gone",
// so a half-created site (a failed createSite) is cleaned up the same way.
export async function deleteSite(helpers, domain, spec = null) {
  const { warn, err } = logger(helpers);
  const s = spec || (await readSpec(domain));

  // 1) Stop serving: vhost + pools out, reload.
  await removePath(vhostPath(domain));
  const pools = [];
  for (const v of await installedPhp()) {
    if (await pathExists(poolPath(domain, v))) { await removePath(poolPath(domain, v)); pools.push(v); }
  }
  if (await nginxTest(helpers)) await nginxReload(helpers);
  else err('The web server configuration is invalid after removing this site. Other sites keep running on the old configuration until it is fixed.');
  for (const v of pools) await run(helpers, 'systemctl', ['reload-or-restart', fpmService(v)], { timeout: 60_000 });

  // 2) The site's user: stop everything it runs, drop its data, remove it.
  //    Only ever a regular (uid ≥ 1000) user we name — never a system account.
  const user = s?.user && USER_RE.test(s.user) ? s.user : null;
  const ids = user ? await userIds(user).catch(() => null) : null;
  if (ids && ids.uid >= 1000) {
    await run(helpers, 'pkill', ['-KILL', '-u', user], { quiet: true, timeout: 15_000 });
  }
  if (user && s.type === 'wordpress') {
    if (!(await dropDatabase(helpers, user))) warn('The site database could not be removed — remove it manually.');
    await dropRedisUser(helpers, user, s.redisDb);
  }
  await removePath(siteDir(domain));
  for (const f of [phpLogPath(domain), `/var/log/nginx/${domain}.access.log`, `/var/log/nginx/${domain}.error.log`]) await removePath(f);
  if (ids && ids.uid >= 1000) {
    const del = await run(helpers, 'userdel', [user], { timeout: 30_000 });
    if (del.code !== 0) warn(`The system user ${user} could not be removed.`);
  }

  // 3) Certificates (any issuer) + acme.sh's renewal config.
  for (const p of [certDir(domain), `/etc/letsencrypt/archive/${domain}`,
    `/etc/letsencrypt/renewal/${domain}`, `/etc/letsencrypt/renewal/${domain}_ecc`]) await removePath(p);

  await removePath(specPath(domain));
}
