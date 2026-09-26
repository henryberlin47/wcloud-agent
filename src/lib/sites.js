import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import config from '../config.js';
import { run, pathExists, removePath, userIds, nginxTest, nginxReload, sleep } from './sys.js';
import { logger } from './log.js';
import { ensurePhp, installedPhp, fpmService, dropDatabase, dropRedisUser, REDIS_DBS } from './stack.js';
import { setupWordPress, pinWpUrls } from './wp.js';
import { ensureRealIpConf } from './realip.js';
import { renderCron, cronFilePath, cronLogPath, ensureWrappers } from './cron.js';
import { poolLines, nginxLimits, phpSettingsOf, fpmOf, PHP_DEFAULTS, FPM_DEFAULTS } from './phpsettings.js';

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

// Page cache per WordPress site (spec.cache): 'fastcgi' = nginx caches PHP's
// HTML (per-site zone below, cleared by lib/cache.js); 'wprocket' = nginx
// serves WP Rocket's cached files directly; 'off'. Sites from before this
// field existed read as 'off' — nothing changes under them silently.
export const CACHE_MODES = ['fastcgi', 'wprocket', 'off'];
export const PAGE_CACHE_ROOT = '/var/cache/wcloud'; // parent /var/cache is the distro's 0755
export const pageCacheDir = (d) => `${PAGE_CACHE_ROOT}/${d}`;
// The zone's name is derived from its whole definition: nginx refuses to
// reload (and silently keeps the OLD config) when an existing zone name comes
// back with a different path or size, so any such change gets a new name.
const cacheZoneArgs = 'levels=1:2 max_size=512m inactive=7d use_temp_path=off';
const cacheZoneSize = '10m';
const cacheZone = (d) => `wc_${createHash('sha256').update(`${pageCacheDir(d)} ${cacheZoneArgs} ${cacheZoneSize}`).digest('hex').slice(0, 12)}`;
const cacheMode = (s) => (s.type === 'wordpress' && CACHE_MODES.includes(s.cache) ? s.cache : 'off');

// Empty a site's page cache (the dir itself stays: nginx owns it).
export async function clearPageCache(domain) {
  let entries = [];
  try { entries = await fs.readdir(pageCacheDir(domain)); } catch { return false; }
  for (const e of entries) await removePath(`${pageCacheDir(domain)}/${e}`);
  return true;
}

// Real visitor IPs behind Cloudflare (spec.realIp): nginx takes the client IP
// from CF-Connecting-IP — but ONLY for connections from Cloudflare's published
// ranges (lib/realip.js keeps this file current), so it can't be spoofed.
export const REALIP_CONF = '/etc/nginx/wcloud/cloudflare-realip.conf';

// Let's Encrypt via Cloudflare DNS (spec.sslDns = 'cloudflare'): the site's
// Cloudflare token, root-only, for the agent's own renewals (lib/acme.js).
export const cfDnsTokenPath = (d) => `/etc/wcloud/cf-dns/${d}.json`;
// Cloudflare cache purges (lib/cfcache.js): the zone token + hosts, root-only.
export const cfCachePath = (d) => `/etc/wcloud/cf-cache/${d}.json`;

// Redirects (spec.redirects): [{ from, to, code: 301|302, regex, keepQuery }].
// Exact paths → `location =`; regexes → `location ~` listed before every other
// regex location, so they win. `to` may use $1…$9 from a regex.
export const REDIRECT_MAX = 200;
const REDIRECT_FROM_EXACT = /^\/[^\s"';{}\\]*$/;
const REDIRECT_FROM_REGEX = /^[^\s"';{}]{1,300}$/;
const REDIRECT_TO = /^(https?:\/\/[^\s"';{}\\$]+|\/[^\s"';{}\\$]*)([^\s"';{}\\]*)$/;
export function cleanRedirects(list) {
  if (!Array.isArray(list)) return 'redirects must be a list';
  if (list.length > REDIRECT_MAX) return `up to ${REDIRECT_MAX} redirects`;
  const out = [];
  for (const r of list) {
    const regex = r?.regex === true;
    const from = String(r?.from || '').trim();
    const to = String(r?.to || '').trim();
    const code = r?.code === 302 ? 302 : 301;
    if (regex ? !REDIRECT_FROM_REGEX.test(from) : !REDIRECT_FROM_EXACT.test(from)) return `"${from}" isn't a valid ${regex ? 'pattern' : 'path (it must start with /)'}`;
    // Only $1…$9 may appear in the target — no other nginx variables.
    if (!REDIRECT_TO.test(to) || /\$(?![1-9])/.test(to) || (!regex && /\$/.test(to))) return `"${to}" isn't a valid target (a URL or a path starting with /${regex ? '; $1…$9 for captures' : ''})`;
    out.push({ from, to, code, regex, keepQuery: r?.keepQuery === true });
  }
  return out;
}
// Whole-domain redirect: { to: "https://new.example/path?", code, keepPath }.
// `to` is an absolute http(s) URL on another host, with no nginx syntax in it
// (quotes, $, ;, braces, backslashes, whitespace). keepPath appends the
// request's path + query. → { value } | { error }
const DOMAIN_REDIRECT_TO = /^https?:\/\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(?::\d{1,5})?(\/[^\s"'`$;{}\\]*)?$/i;
export function cleanDomainRedirect(v, domain) {
  if (v === null || v === false) return { value: null };
  if (typeof v !== 'object') return { error: 'domainRedirect must be an object or null' };
  const to = String(v.to || '').trim();
  const m = to.match(DOMAIN_REDIRECT_TO);
  if (!m || to.length > 500) return { error: `"${to}" isn't a valid address — use a full URL like https://new-domain.com` };
  const host = m[1].toLowerCase();
  if (host === domain || host === `www.${domain}`) return { error: 'The target is this site itself — that would loop.' };
  return { value: { to, code: v.code === 302 ? 302 : 301, keepPath: v.keepPath !== false } };
}
const domainRedirectTarget = (r) => `"${r.keepPath ? r.to.replace(/\/+$/, '') : r.to}${r.keepPath ? '$request_uri' : ''}"`;

function redirectLocations(s) {
  const rs = Array.isArray(s.redirects) ? s.redirects : [];
  const target = (r) => `"${r.to}${r.keepQuery ? '$is_args$args' : ''}"`;
  return [
    ...rs.filter((r) => !r.regex).map((r) => `location = "${r.from}" { return ${r.code} ${target(r)}; }`),
    ...rs.filter((r) => r.regex).map((r) => `location ~ "${r.from}" { return ${r.code} ${target(r)}; }`),
  ];
}

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
  canonical: s.canonical, ssl: s.ssl, cache: s.type === 'wordpress' ? cacheMode(s) : null,
  realIp: !!s.realIp, redirects: Array.isArray(s.redirects) ? s.redirects : [], sslDns: s.sslDns || null,
  domainRedirect: s.domainRedirect || null,
  crons: Array.isArray(s.crons) ? s.crons : [], wpCron: s.wpCron === 'server' ? 'server' : 'wordpress',
  wpCronEvery: s.wpCronEvery || 5, cfCache: !!s.cfCache,
  ...(s.type === 'wordpress' ? { phpSettings: phpSettingsOf(s), phpDefaults: PHP_DEFAULTS, fpm: fpmOf(s), fpmDefaults: FPM_DEFAULTS } : {}),
  created_at: s.created_at,
});

// --- rendering ----------------------------------------------------------------

const server = (lines) => ['server {', ...lines.map((l) => (l ? `    ${l}` : '')), '}'].join('\n');

// Never serve a cached page to someone it isn't for: logged-in users,
// commenters, carts/checkouts, admin, APIs, feeds, POSTs and query strings.
// (A response that sets a cookie is never stored either — nginx default.)
function cacheSkipRules() {
  return [
    '# Page cache: when NOT to use it.',
    'set $skip_cache 0;',
    'if ($request_method = POST) { set $skip_cache 1; }',
    'if ($query_string != "") { set $skip_cache 1; }',
    'if ($request_uri ~* "/wp-admin/|/wp-json/|/xmlrpc.php|wp-.*\\.php|/feed/|index\\.php|sitemap(_index)?\\.xml|/cart/|/checkout/|/my-account/|/addons/") { set $skip_cache 1; }',
    'if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in|woocommerce_items_in_cart|woocommerce_cart_hash|wp_woocommerce_session") { set $skip_cache 1; }',
  ];
}

function siteBody(s) {
  const d = s.domain;
  const common = [
    `root ${webRoot(d)};`,
    `access_log /var/log/nginx/${d}.access.log;`,
    `error_log /var/log/nginx/${d}.error.log;`,
    '',
    ...(s.realIp ? ['# Real visitor IPs behind Cloudflare (trusted only from Cloudflare\'s ranges).', `include ${REALIP_CONF};`] : []),
    '# Custom rules for this site (root-owned; not overwritten by wcloud).',
    `include ${siteDir(d)}/conf/nginx/*.conf;`,
    '',
    ...redirectLocations(s),
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
  const mode = cacheMode(s);
  const lim = nginxLimits(s); // follow the site's PHP upload size / time limits
  return [
    ...common,
    'index index.php index.html;',
    `client_max_body_size ${lim.bodyMB}m;`,
    ...(mode === 'off' ? [] : cacheSkipRules()),
    // At server level, not in the PHP location: a location's own add_header
    // would stop the site's custom-rule headers from reaching PHP pages.
    // Empty (= not sent) on responses that didn't go through the cache.
    ...(mode === 'fastcgi' ? ['add_header X-Cache $upstream_cache_status always;'] : []),
    ...(mode === 'wprocket' ? [
      '# WP Rocket: serve its cached page straight from disk when there is one.',
      'set $rocket_https "";',
      'if ($https = "on") { set $rocket_https "-https"; }',
      'set $rocket_file "/wp-content/cache/wp-rocket/$host${uri}index$rocket_https.html";',
      'if ($skip_cache = 1) { set $rocket_file "/wcloud-no-rocket-cache"; }',
    ] : []),
    'location ~* ^/wp-content/uploads/.*\\.php$ { deny all; }',
    // WordPress only serves its virtual robots.txt through permalink rewrite
    // rules; on plain permalinks it 301s to /robots.txt/. Ask for it directly
    // (a real robots.txt file in htdocs still wins).
    'location = /robots.txt { try_files $uri /index.php?robots=1; access_log off; }',
    mode === 'wprocket'
      ? 'location / { try_files $rocket_file $uri $uri/ /index.php?$args; }'
      : 'location / { try_files $uri $uri/ /index.php?$args; }',
    'location ~ \\.php$ {',
    '    try_files $uri =404;',
    '    include fastcgi_params;',
    '    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;',
    `    fastcgi_pass unix:${sockPath(d)};`,
    `    fastcgi_read_timeout ${lim.readTimeout}s;`,
    '    fastcgi_buffers 16 16k;',
    '    fastcgi_buffer_size 32k;',
    ...(mode === 'fastcgi' ? [
      `    fastcgi_cache ${cacheZone(d)};`,
      '    fastcgi_cache_key "$scheme$request_method$host$request_uri";',
      '    fastcgi_cache_valid 200 301 302 1h;',
      '    fastcgi_cache_bypass $skip_cache;',
      '    fastcgi_no_cache $skip_cache;',
      '    fastcgi_cache_use_stale error timeout updating invalid_header http_500 http_503;',
      '    fastcgi_cache_background_update on;',
      '    fastcgi_cache_lock on;',
    ] : []),
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
    `        fastcgi_read_timeout ${lim.readTimeout}s;`,
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
  // http-level (this file is included inside http {}): the site's own cache
  // zone, so it can be cleared on its own (lib/cache.js).
  if (cacheMode(s) === 'fastcgi') {
    out.push(`fastcgi_cache_path ${pageCacheDir(d)} keys_zone=${cacheZone(d)}:${cacheZoneSize} ${cacheZoneArgs};`);
  }
  // Whole-domain redirect: every request (both hosts, http and https) goes
  // straight to the target in one hop; only ACME challenges are still
  // answered here, so the certificate keeps renewing.
  const dr = s.domainRedirect;
  const redirectBody = dr ? [
    `access_log /var/log/nginx/${d}.access.log;`, `error_log /var/log/nginx/${d}.error.log;`,
    ...(s.realIp ? [`include ${REALIP_CONF};`] : []),
    `# Whole-domain redirect (set in wcloud)`, `location / { return ${dr.code} ${domainRedirectTarget(dr)}; }`,
  ] : null;
  if (https) {
    out.push(server(['listen 80;', 'listen [::]:80;', names, acme,
      dr ? `location / { return ${dr.code} ${domainRedirectTarget(dr)}; }` : `location / { return 301 https://${canon || '$host'}$request_uri; }`]));
    out.push(server(['listen 443 ssl http2;', 'listen [::]:443 ssl http2;', names,
      `ssl_certificate     ${fullchainPath(d)};`, `ssl_certificate_key ${keyPath(d)};`, '',
      ...(dr ? [acme, ...redirectBody] : [...toCanon('https'), ...siteBody(s)])]));
  } else {
    out.push(server(['listen 80;', 'listen [::]:80;', names, acme, '', ...(dr ? redirectBody : [...toCanon('http'), ...siteBody(s)])]));
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
    // Process manager + php_value lines: the site's own settings (lib/phpsettings.js).
    ...poolLines(s),
    `php_admin_value[error_log] = ${phpLogPath(d)}`,
    'php_admin_flag[log_errors] = on',
    `php_admin_value[upload_tmp_dir] = ${tmp}`,
    `php_admin_value[sys_temp_dir] = ${tmp}`,
    `php_admin_value[session.save_path] = ${tmp}`,
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
// A log file in root-owned /var/log/wcloud that the site's own user appends to
// (no one else can place a symlink there, so creating it as root is safe).
async function ensureSiteLog(file, user) {
  if (await pathExists(file)) return;
  await fs.mkdir('/var/log/wcloud', { recursive: true, mode: 0o755 });
  await (await fs.open(file, 'a', 0o640)).close();
  const { uid, gid } = await userIds(user);
  await fs.chown(file, uid, gid);
}

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
  if (cacheMode(s) === 'fastcgi') {
    // nginx's workers write the cache; nothing a site controls lives here.
    // The shared parent must be traversable (0711) — a 0700 parent made
    // nginx fail every cached request with a 500.
    await fs.mkdir(PAGE_CACHE_ROOT, { recursive: true });
    await fs.chmod(PAGE_CACHE_ROOT, 0o711);
    await fs.mkdir(pageCacheDir(d), { recursive: true, mode: 0o700 });
    const www = await userIds('www-data');
    await fs.chown(pageCacheDir(d), www.uid, www.gid);
    await fs.chmod(pageCacheDir(d), 0o700);
  }
  if (s.realIp) await ensureRealIpConf();
  const cron = renderCron(s);
  if (cron) {
    await ensureWrappers(s.php);
    await ensureSiteLog(cronLogPath(d), s.user); // the site's user appends to it
  }
  const https = s.ssl && (!!certs || (await pathExists(fullchainPath(d))));
  await fs.mkdir(SPEC_DIR, { recursive: true, mode: 0o700 });
  await stage(specPath(d), JSON.stringify(s, null, 2) + '\n', 0o600);
  await stage(vhostPath(d), renderVhost(s, { https }));
  if (s.php) await stage(poolPath(d, s.php), renderPool(s));
  if (prevPhp && prevPhp !== s.php) await stage(poolPath(d, prevPhp), null);
  await stage(cronFilePath(d), cron); // null = nothing scheduled → no file

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

  // php-fpm reloads are asynchronous: `systemctl reload` returns before the
  // old master has dropped a removed pool — and it then UNLINKS that pool's
  // socket path, ~½s later. On a version switch (same socket path) the new
  // version must therefore only bind once the old one has let go, or the old
  // master deletes the NEW socket and the site 502s until the next reload.
  const waitFor = async (want) => {
    for (let i = 0; i < 50 && (await pathExists(sockPath(d))) !== want; i++) await sleep(200);
  };
  if (prevPhp && prevPhp !== s.php && poolVersions.includes(prevPhp)) {
    await run(helpers, 'systemctl', ['reload-or-restart', fpmService(prevPhp)], { timeout: 60_000 });
    await waitFor(false);
  }
  if (poolVersions.includes(s.php)) {
    await run(helpers, 'systemctl', ['reload-or-restart', fpmService(s.php)], { timeout: 60_000 });
    await waitFor(true); // …and the first requests after "ready" must not 502
  }
  if (changed.some((e) => !e.path.startsWith('/etc/php/') && e.path !== specPath(d))) await nginxReload(helpers);
  // Any change (HTTPS, address, cache mode, PHP version…) can change what a
  // page renders: pages cached under the old config go.
  await clearPageCache(d);
  return { changed: true };
}

// HTTPS on, with the cert already in certDir or a new pair (joins the same
// transaction, so a chain nginx rejects restores the previous working cert).
export async function applySslConf(helpers, domain, { certs, sslDns } = {}) {
  const s = await requireSpec(domain);
  // Any other kind of certificate ends Cloudflare-DNS renewals for the site.
  await applySite(helpers, { ...s, ssl: true, sslDns: sslDns || undefined }, { certs });
  if (!sslDns) await removePath(cfDnsTokenPath(domain));
  logger(helpers).ok('Web server reloaded with the new certificate');
}

// Point WordPress's own address (home/siteurl) at what nginx now serves.
export async function syncWpAddress(helpers, s) {
  if (s.type !== 'wordpress') return true;
  const https = s.ssl && (await pathExists(fullchainPath(s.domain)));
  const host = !s.enableWww || s.canonical === 'root' ? s.domain : s.canonical === 'www' ? `www.${s.domain}` : undefined;
  const r = await pinWpUrls(helpers, s, { scheme: https ? 'https' : 'http', host });
  await clearPageCache(s.domain); // cached pages carry the old address
  return r;
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
  if (s.type === 'wordpress') {
    s.redisDb = await freeRedisDb();
    s.cache = CACHE_MODES.includes(o.cache) ? o.cache : 'fastcgi';
  }
  s.realIp = o.realIp !== false; // harmless without Cloudflare: only CF's own ranges are trusted
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
  await removePath(pageCacheDir(domain));
  await removePath(cfDnsTokenPath(domain));
  await removePath(cfCachePath(domain));
  await removePath(cronFilePath(domain));
  for (const f of [phpLogPath(domain), cronLogPath(domain), `/var/log/nginx/${domain}.access.log`, `/var/log/nginx/${domain}.error.log`]) await removePath(f);
  if (ids && ids.uid >= 1000) {
    const del = await run(helpers, 'userdel', [user], { timeout: 30_000 });
    if (del.code !== 0) warn(`The system user ${user} could not be removed.`);
  }

  // 3) Certificates (any issuer) + acme.sh's renewal config.
  for (const p of [certDir(domain), `/etc/letsencrypt/archive/${domain}`,
    `/etc/letsencrypt/renewal/${domain}`, `/etc/letsencrypt/renewal/${domain}_ecc`]) await removePath(p);

  await removePath(specPath(domain));
}
