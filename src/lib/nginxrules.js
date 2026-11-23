import fs from 'node:fs/promises';
import { run, removePath, nginxReload, withLock } from './sys.js';
import { siteDir, clearPageCache } from './sites.js';

// ============================================================
//  nginxrules.js — a site's named custom nginx rules
// ============================================================
// Files in /var/www/<d>/conf/nginx/ (root-owned; the site's vhost includes
// *.conf inside its server block). Name in a header line; a disabled rule is
// the same file renamed to .conf.off. Every save is ONE transaction: write,
// `nginx -t`, and on failure the previous files come back and nginx's own
// error is shown — a bad rule never reaches the running server.
// ============================================================

const HEADER = '# wcloud-name: ';
export const RULE_MAX = 64 * 1024;
const dir = (d) => `${siteDir(d)}/conf/nginx`;
const ID = /^[a-z0-9][a-z0-9-]{0,39}$/;
const slug = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'rule';
const read = async (p) => { try { return await fs.readFile(p, 'utf8'); } catch { return null; } };

// Directives a rule may not use: nginx's root master opens their paths as root
// (include, *_log, *_temp_path, geoip/xslt files), they hand requests to other
// sockets or code (*_pass, fastcgi_param, perl, njs, lua), or they serve files
// outside the site (root, alias). An access_log into /etc/profile.d is root
// code execution. Matched as a word anywhere — quoted names count, and a false
// positive inside a header value only refuses the rule. `../` likewise: a
// try_files path can climb out of the site's root.
// ponytail: denylist, not a parser; switch to an allowlist if rules grow beyond
// locations/headers/rewrites.
const BANNED = /(?:^|[\s;{}'"])(include|load_module|root|alias|\w*_log|\w+_temp_path|\w+_cache_path|\w+_pass|fastcgi_param|fastcgi_\w+|ssl_\w+|auth_basic_user_file|geoip\w*|xslt_\w+|perl\w*|js_\w+|\w*lua\w*|modsecurity\w*|ssi|env|user|pid|working_directory)(?=[\s;{'"]|$)/m;
/** Why a rule's content is refused, or null. */
export function ruleProblem(content) {
  // `access_log off;`, `rewrite_log on;` open nothing.
  const m = content.replace(/(^|[\s;{}])\w*_log\s+(?:on|off)\s*;/gm, '$1;').match(BANNED);
  if (m) return `"${m[1]}" isn't allowed in a custom rule`;
  if (/\.\.[\/\\]|[\/\\]\.\./.test(content)) return '"../" isn\'t allowed in a custom rule';
  return null;
}

export async function listRules(d) {
  let files = [];
  try { files = await fs.readdir(dir(d)); } catch { return []; }
  const out = [];
  for (const f of files.sort()) {
    const m = f.match(/^([a-z0-9][a-z0-9-]*)\.conf(\.off)?$/);
    if (!m) continue;
    const text = (await read(`${dir(d)}/${f}`)) || '';
    const first = text.split('\n', 1)[0];
    const named = first.startsWith(HEADER);
    out.push({ id: m[1], name: named ? first.slice(HEADER.length).trim() : f, enabled: !m[2], content: named ? text.slice(first.length + 1) : text });
  }
  return out;
}

// The first nginx -t complaint, trimmed to the useful part.
async function nginxCheck(helpers) {
  const r = await run(helpers, 'nginx', ['-t'], { quiet: true, timeout: 30_000 });
  if (r.code === 0) return null;
  const line = `${r.stderr}\n${r.stdout}`.split('\n').find((l) => /\[emerg\]|\[alert\]/.test(l)) || 'the configuration test failed';
  return line.replace(/^.*?\[(emerg|alert)\]\s*\d+#\d+:\s*/, '').slice(0, 300);
}

// Apply edits { path: content | null } transactionally. Throws with nginx's
// complaint when the result doesn't pass `nginx -t`.
const commit = (helpers, d, edits) => withLock('config', () => commitNow(helpers, d, edits));
async function commitNow(helpers, d, edits) {
  // Cancelled while waiting for the 'config' lock: write nothing. An Error like
  // run() throws, because callers show e.message.
  if (helpers.signal?.aborted) throw new Error(`cancelled (${helpers.signal.reason ?? 'aborted'})`);
  const before = {};
  for (const p of Object.keys(edits)) before[p] = await read(p);
  const put = async (p, c) => { if (c === null) await removePath(p); else await fs.writeFile(p, c, { mode: 0o644 }); };
  const restore = async () => { for (const [p, c] of Object.entries(before)) await put(p, c); };
  await fs.mkdir(dir(d), { recursive: true });
  let err;
  try {
    for (const [p, c] of Object.entries(edits)) await put(p, c);
    err = await nginxCheck(helpers);
  } catch (e) {
    await restore(); // cancel, timeout or a failed write: an untested rule must not stay on disk
    throw e;
  }
  if (err) {
    await restore();
    throw new Error(`nginx rejected the rule, so nothing changed: ${err}`);
  }
  await nginxReload(helpers);
  await clearPageCache(d);
}

// { id?, name, content, enabled } — no id = new rule (id from the name).
export async function saveRule(helpers, d, { id, name, content, enabled }) {
  let ruleId = id;
  if (!ruleId) {
    const taken = new Set((await listRules(d)).map((r) => r.id));
    const base = slug(name);
    ruleId = base;
    for (let i = 2; taken.has(ruleId); i++) ruleId = `${base}-${i}`;
  }
  if (!ID.test(ruleId)) throw new Error('invalid rule id');
  const on = `${dir(d)}/${ruleId}.conf`;
  const off = `${on}.off`;
  const text = `${HEADER}${name}\n${content.endsWith('\n') ? content : `${content}\n`}`;
  await commit(helpers, d, enabled ? { [on]: text, [off]: null } : { [off]: text, [on]: null });
  return ruleId;
}

export async function deleteRule(helpers, d, id) {
  if (!ID.test(id)) throw new Error('invalid rule id');
  const on = `${dir(d)}/${id}.conf`;
  await commit(helpers, d, { [on]: null, [`${on}.off`]: null });
}

// Self-check: node src/lib/nginxrules.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const assert = (await import('node:assert')).strict;
  for (const ok of ['return 503;', 'location /old { return 301 /new; }', 'add_header Content-Security-Policy "default-src \'self\'; img-src *";',
    'location ~* \\.(png|jpg)$ { expires 30d; }', 'client_max_body_size 64m;', 'rewrite ^/a/(.*)$ /b/$1 permanent;', 'deny 1.2.3.4;\nallow all;',
    'location /x { try_files $uri $uri/ /index.php?$args; }', 'set $rootish 1;', 'proxy_set_header X-A b;', 'location / {access_log off;}', 'location /a { rewrite_log on; }']) assert.equal(ruleProblem(ok), null, ok);
  for (const bad of ['access_log /etc/profile.d/x.sh;', 'include /etc/shadow;', '"include" /etc/shadow;', "location /a {\n  alias /var/www/;\n}",
    'root /etc;', 'error_log /root/.bashrc;', 'client_body_temp_path /usr/bin;', 'fastcgi_pass unix:/run/php/x.sock;', 'proxy_pass http://127.0.0.1:8787;',
    'fastcgi_param PHP_VALUE "auto_prepend_file=php://input";', 'location /p { content_by_lua_block { os.execute("id") } }', 'js_import /tmp/x.js;',
    'try_files /../../../etc/passwd =404;', 'ssl_certificate_key /etc/letsencrypt/live/o/key.pem;', 'access_log off; access_log /tmp/x;']) assert.ok(ruleProblem(bad), bad);
  console.log('nginxrules self-check ok');
}
