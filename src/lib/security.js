import fs from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { run, withLock, pathExists } from './sys.js';

// ============================================================
//  security.js — a site's protection (spec.security), rendered into its vhost
// ============================================================
//   hardening  (on by default)  login / XML-RPC brute force rate-limited per IP,
//              backups, dumps, logs and install files not served
//   headers    (on by default)  X-Frame-Options, X-Content-Type-Options, Referrer-Policy
//   hsts       (off by default) Strict-Transport-Security on HTTPS — once a browser has
//              it, the site can't go back to plain HTTP for a year
//   xmlrpc     limit | block | allow
//   challenge  off | cookie | js — a first visit has to pass a check before it gets the
//              site: `cookie` sets a signed cookie and reloads (stops bots that don't keep
//              cookies), `js` makes the browser solve a small proof of work. Search engines,
//              cron, the REST API, payment callbacks and certificate checks pass straight.
//   waf        off | detect | block — ModSecurity with the OWASP Core Rule Set (WordPress
//              exclusions on). detect = matches are only logged in the site's error log
//              (rendered at info level then — ModSecurity's warnings are info lines).
// The challenge (nginx's njs module) and the WAF (ModSecurity) are Ubuntu packages
// that exist on 24.04 only; they are installed the first time a site turns one on.
// ============================================================

export const SECURITY_DEFAULTS = { hardening: true, headers: true, hsts: false, xmlrpc: 'limit', challenge: 'off', waf: 'off' };
export const securityOf = (s) => ({ ...SECURITY_DEFAULTS, ...(s.security || {}) });

/** A whole security object from the portal → { value } | { error }. */
export function cleanSecurity(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { error: 'security must be an object' };
  const out = {};
  for (const k of ['hardening', 'headers', 'hsts']) {
    if (v[k] == null) continue;
    if (typeof v[k] !== 'boolean') return { error: `security.${k} must be true or false` };
    out[k] = v[k];
  }
  const pick = (k, options) => {
    if (v[k] == null) return null;
    if (!options.includes(v[k])) return `security.${k} must be one of: ${options.join(', ')}`;
    out[k] = v[k];
    return null;
  };
  const e = pick('xmlrpc', ['limit', 'block', 'allow']) || pick('challenge', ['off', 'cookie', 'js']) || pick('waf', ['off', 'detect', 'block']);
  if (e) return { error: e };
  return { value: out };
}

// --- http-level config (one per server) ----------------------------------------

const HTTP_CONF = '/etc/nginx/conf.d/wcloud-security.conf';
const CHALLENGE_CONF = '/etc/nginx/conf.d/wcloud-challenge.conf';
const WAF_CONF = '/etc/nginx/conf.d/wcloud-waf.conf';
const NJS_DIR = '/etc/nginx/njs';
const MODSEC_DIR = '/etc/nginx/modsec';

// Login / XML-RPC POSTs keyed by client IP; every other request has an empty
// key, which limit_req never counts.
const HTTP_LINES = [
  '# Managed by wcloud (agent src/lib/security.js): rate limits sites use (security.hardening / xmlrpc).',
  'map $request_method$uri $wcloud_login_key { default ""; "POST/wp-login.php" $binary_remote_addr; }',
  'map $request_method$uri $wcloud_xmlrpc_key { default ""; "POST/xmlrpc.php" $binary_remote_addr; }',
  'limit_req_zone $wcloud_login_key zone=wcloud_login:10m rate=10r/m;',
  'limit_req_zone $wcloud_xmlrpc_key zone=wcloud_xmlrpc:10m rate=30r/m;',
  'limit_req_status 429;',
  '',
].join('\n');



const has = async (pkg) => (await run({ log() {}, err() {} }, 'dpkg-query', ['-W', '-f=${Status}', pkg], { quiet: true, timeout: 10_000 })).stdout.includes('install ok installed');
const offered = async (pkg) => /Candidate: (?!\(none\))/.test((await run({ log() {}, err() {} }, 'apt-cache', ['policy', pkg], { quiet: true, timeout: 30_000 })).stdout);

/** What this server can do: { challenge, waf } — false on Ubuntu 22.04 (no packages). */
export async function securityAvailable() {
  return { challenge: (await has('libnginx-mod-http-js')) || (await offered('libnginx-mod-http-js')),
    waf: (await has('libnginx-mod-http-modsecurity')) || (await offered('libnginx-mod-http-modsecurity')) };
}

async function aptInstall(helpers, pkgs) {
  await withLock('apt', async () => {
    const r = await run(helpers, 'apt-get', ['-y', '-q', '-o', 'DPkg::Lock::Timeout=600', 'install', ...pkgs],
      { timeout: 15 * 60_000, env: { DEBIAN_FRONTEND: 'noninteractive' } });
    if (r.code !== 0) throw new Error(`Installing ${pkgs.join(', ')} failed`);
  });
}

// --- challenge (njs) -----------------------------------------------------------

const NJS = String.raw`// Managed by wcloud (agent src/lib/security.js): the visitor check of sites with security.challenge.
import crypto from 'crypto';
import fs from 'fs';
const SECRET = fs.readFileSync('${NJS_DIR}/wcloud.secret').toString().trim();
const TTL = 86400;
// Never challenged: certificate checks, WordPress cron, the REST API and admin-ajax
// (webhooks, payment callbacks, logged-in editors), XML-RPC, our own endpoint.
const SKIP = /^\/(?:\.well-known\/|wp-cron\.php|wp-json\/|wp-admin\/admin-ajax\.php|xmlrpc\.php|\.wcloud-challenge)/;
// Static files (images, styles, fonts) never carry the check — a page does.
const STATIC = /\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|pdf|txt|xml)$/i;
// 32-bit FNV-1a: the proof-of-work hash. Plain JS, so it also runs on http:// pages
// (crypto.subtle needs HTTPS); the work only has to prove the page's script ran.
const fnv = (s) => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; };
const WORK = 0x3ffff;
const BOTS = /googlebot|bingbot|duckduckbot|baiduspider|yandex|applebot|facebookexternalhit|twitterbot|linkedinbot|slurp|petalbot|wcloud-uptime|uptimerobot/i;
const sign = (r, v) => crypto.createHmac('sha256', SECRET).update(r.remoteAddress + '|' + (r.headersIn['User-Agent'] || '') + '|' + v).digest('hex');
function passed(r) {
  const c = (r.variables.cookie_wcloud_pass || '').split('.');
  const t = Number(c[0]);
  return !!c[1] && Math.abs(Date.now() / 1000 - t) < TTL && c[1] === sign(r, 'pass' + c[0]).slice(0, 32);
}
const cookie = (r) => { const t = String(Math.floor(Date.now() / 1000)); return 'wcloud_pass=' + t + '.' + sign(r, 'pass' + t).slice(0, 32) + '; Path=/; Max-Age=' + TTL + '; HttpOnly; SameSite=Lax' + (r.variables.https === 'on' ? '; Secure' : ''); };
const back = (to) => (/^\/(?!\/)[^\s\\]*$/.test(to || '') ? to : '/');
// "1" = this request has to pass the check first.
function gate(r) {
  if (r.method !== 'GET' && r.method !== 'HEAD') return '';
  if (SKIP.test(r.uri) || STATIC.test(r.uri) || (r.args && r.args['wc-api'])) return '';
  if (BOTS.test(r.headersIn['User-Agent'] || '')) return '';
  return passed(r) ? '' : '1';
}
function page(r) {
  r.headersOut['Cache-Control'] = 'no-store';
  r.headersOut['Retry-After'] = '5';
  if (r.variables.wcloud_challenge !== 'js') {
    r.headersOut['Set-Cookie'] = cookie(r);
    r.return(302, back(r.variables.request_uri));
    return;
  }
  const t = String(Math.floor(Date.now() / 1000));
  const seed = t + '.' + sign(r, 'seed' + t).slice(0, 24);
  r.headersOut['Content-Type'] = 'text/html; charset=utf-8';
  r.return(503, '<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Checking your browser…</title>'
    + '<style>body{font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:90vh;color:#444;margin:0}</style>'
    + '<p id=m>Checking your browser before opening the site…</p><noscript><p>Please turn on JavaScript to continue.</p></noscript>'
    + '<script>(()=>{const s=' + JSON.stringify(seed) + ',f=(s)=>{let h=0x811c9dc5;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,0x01000193)}return h>>>0};for(let n=0;;n++){'
    + 'if((f(s+n)&' + WORK + ')===0){location.replace("/.wcloud-challenge?s="+encodeURIComponent(s)+"&n="+n+"&to="+encodeURIComponent(location.pathname+location.search));return}}})()</script>');
}
// The browser's answer: the seed is ours and fresh, and fnv(seed + n) has its low 18 bits zero.
function verify(r) {
  const s = r.args.s || '', n = r.args.n || '';
  const p = s.split('.');
  const fresh = Math.abs(Date.now() / 1000 - Number(p[0])) < 600 && p[1] === sign(r, 'seed' + p[0]).slice(0, 24);
  if (!fresh || !/^\d{1,12}$/.test(n) || (fnv(s + n) & WORK) !== 0) { r.return(403, 'The browser check failed — reload the page.'); return; }
  r.headersOut['Set-Cookie'] = cookie(r);
  r.return(302, back(r.args.to));
}
export default { gate, page, verify };
`;

/** Module, script, secret and http-level wiring for the challenge. */
export async function ensureChallenge(helpers) {
  if (!(await has('libnginx-mod-http-js'))) {
    if (!(await offered('libnginx-mod-http-js'))) throw new Error('The visitor check needs Ubuntu 24.04 (nginx\'s JavaScript module isn\'t packaged for this release).');
    await aptInstall(helpers, ['libnginx-mod-http-js']);
  }
  await fs.mkdir(NJS_DIR, { recursive: true, mode: 0o755 });
  const secret = `${NJS_DIR}/wcloud.secret`;
  if (!(await pathExists(secret))) {
    await fs.writeFile(secret, randomBytes(32).toString('hex'), { mode: 0o640 });
    // nginx's workers read it (www-data); nobody else.
    await run(helpers, 'chown', ['root:www-data', secret], { quiet: true });
  }
}

const CHALLENGE_LINES = [
  '# Managed by wcloud (agent src/lib/security.js): the visitor check (security.challenge).',
  `js_path ${NJS_DIR};`,
  'js_import wcloud from wcloud.js;',
  'js_set $wcloud_gate wcloud.gate;',
  '',
].join('\n');

// --- WAF (ModSecurity + OWASP CRS) ---------------------------------------------

const MODSEC_MAIN = [
  '# Managed by wcloud (agent src/lib/security.js): ModSecurity + OWASP Core Rule Set (security.waf).',
  'SecRuleEngine On',
  'SecRequestBodyAccess On',
  'SecRequestBodyLimit 536870912',
  'SecRequestBodyNoFilesLimit 13107200',
  'SecRequestBodyLimitAction ProcessPartial',
  'SecResponseBodyAccess Off',
  'SecPcreMatchLimit 500000',
  'SecTmpDir /tmp',
  'SecDataDir /tmp',
  'SecAuditEngine Off',
  'SecArgumentSeparator &',
  'SecCookieFormat 0',
  'SecStatusEngine Off',
  'Include /etc/modsecurity/crs/crs-setup.conf',
  'SecAction "id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1"',
  'Include /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf',
  'Include /usr/share/modsecurity-crs/rules/*.conf',
  'Include /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf',
  '',
].join('\n');

export async function ensureWaf(helpers) {
  if (!(await has('libnginx-mod-http-modsecurity')) || !(await has('modsecurity-crs'))) {
    if (!(await offered('libnginx-mod-http-modsecurity'))) throw new Error('The firewall (ModSecurity) needs Ubuntu 24.04 — it isn\'t packaged for this release.');
    await aptInstall(helpers, ['libnginx-mod-http-modsecurity', 'modsecurity-crs']);
  }
  await fs.mkdir(MODSEC_DIR, { recursive: true, mode: 0o755 });
}

// The rules are loaded ONCE for the whole server, switched on per site
// (rules per vhost would multiply memory and reload time by the site count).
const WAF_LINES = [
  '# Managed by wcloud (agent src/lib/security.js): the firewall\'s rules, on only in sites with security.waf.',
  'modsecurity off;',
  `modsecurity_rules_file ${MODSEC_DIR}/main.conf;`,
  '',
].join('\n');

/**
 * The server-wide files a site's vhost relies on, as [path, content]: staged by
 * applySite with the vhost (tested + reloaded together), so an agent update that
 * changes them takes effect on the next reconcile.
 */
export function securityFiles(s) {
  const sec = securityOf(s);
  return [
    [HTTP_CONF, HTTP_LINES],
    ...(sec.challenge !== 'off' ? [[`${NJS_DIR}/wcloud.js`, NJS], [CHALLENGE_CONF, CHALLENGE_LINES]] : []),
    ...(sec.waf !== 'off' ? [[`${MODSEC_DIR}/main.conf`, MODSEC_MAIN], [WAF_CONF, WAF_LINES]] : []),
  ];
}

// --- the vhost lines -------------------------------------------------------------

/** Server-level lines for a site's vhost (both site types). */
export function securityServerLines(s, { https }) {
  const sec = securityOf(s);
  const out = [];
  if (sec.headers) {
    out.push('# Security headers (security.headers).',
      'add_header X-Frame-Options SAMEORIGIN always;',
      'add_header X-Content-Type-Options nosniff always;',
      'add_header Referrer-Policy strict-origin-when-cross-origin always;');
  }
  if (sec.hsts && https) out.push('add_header Strict-Transport-Security "max-age=31536000" always;');
  if (sec.hardening) {
    out.push('# Not served: backups, dumps, logs, install files (security.hardening).',
      'location ~* \\.(?:sql|sql\\.gz|bak|old|orig|save|swp|log|ini|sh)$ { deny all; access_log off; log_not_found off; }',
      'location ~* ^/(?:readme\\.html|license\\.txt|wp-config-sample\\.php)$ { deny all; access_log off; log_not_found off; }');
  }
  if (s.type === 'wordpress' && sec.xmlrpc === 'block') out.push('location = /xmlrpc.php { deny all; access_log off; log_not_found off; }');
  if (sec.challenge !== 'off') {
    out.push(`# Visitor check (security.challenge = ${sec.challenge}).`,
      `set $wcloud_challenge ${sec.challenge};`,
      'error_page 418 = @wcloud_challenge;',
      'if ($wcloud_gate) { return 418; }',
      // Relative Location: behind Cloudflare the origin only sees http://.
      'location @wcloud_challenge { absolute_redirect off; js_content wcloud.page; }',
      'location = /.wcloud-challenge { absolute_redirect off; js_content wcloud.verify; }');
  }
  if (sec.waf !== 'off') {
    out.push(`# Firewall: OWASP Core Rule Set (security.waf = ${sec.waf}).`, 'modsecurity on;');
    if (sec.waf === 'detect') out.push("modsecurity_rules 'SecRuleEngine DetectionOnly';");
  }
  return out;
}

/** Lines inside the PHP location (WordPress): the brute-force limits. */
export function securityPhpLines(s) {
  const sec = securityOf(s);
  return [
    ...(sec.hardening ? ['    limit_req zone=wcloud_login burst=10 nodelay;'] : []),
    ...(sec.xmlrpc === 'limit' ? ['    limit_req zone=wcloud_xmlrpc burst=20 nodelay;'] : []),
  ];
}
