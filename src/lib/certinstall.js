import fs from 'node:fs/promises';
import config from '../config.js';
import { run, pathExists, removePath, nginxTest, nginxReload } from './sys.js';
import { logger } from './log.js';

// ============================================================
//  certinstall.js — install a cert + wire nginx to it
// ============================================================
// The WordOps cert layout, issuer-agnostic: LE (wo --le), custom and
// manual-DNS certs all live at /etc/letsencrypt/live/<domain>/, so every
// consumer (canonical redirects, export, delete) keeps working unchanged.
// The private key only ever comes from the authenticated request body, is
// written 600 root:root, and never crosses a command line or log.

export const certDir = (domain) => `/etc/letsencrypt/live/${domain}`;
export const fullchainPath = (domain) => `${certDir(domain)}/fullchain.pem`;
export const keyPath = (domain) => `${certDir(domain)}/key.pem`;

// conf/nginx/ssl.conf is included INSIDE the site's server block (WordOps'
// sites-available ends with `include <webroot>/conf/nginx/*.conf;`), so it is
// bare directives: a port-443 listen + the cert pair. No server{} wrapper, no
// stapling (stapling needs the exact CA chain; custom chains vary).
export function sslConfContent(domain) {
  return [
    `# wcloud-managed SSL for ${domain}`,
    `listen 443 ssl;`,
    `listen [::]:443 ssl;`,
    `ssl_certificate     ${fullchainPath(domain)};`,
    `ssl_certificate_key ${keyPath(domain)};`,
    ``,
  ].join('\n');
}

// Marker: the current LE cert was issued via manual DNS-01 and will NOT be
// auto-renewed. Read by GET /api/sites/:domain/ssl; removed whenever a new
// cert is installed (le-http re-issue, custom, manual re-issue).
export const manualMarkerPath = (domain) => `${config.wwwDir}/${domain}/conf/nginx/.wcloud-ssl-manual`;

export async function writeManualMarker(domain) {
  const dir = `${config.wwwDir}/${domain}/conf/nginx`;
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(manualMarkerPath(domain), `manual dns-01 ${new Date().toISOString()}\n`, { mode: 0o600 });
}

export async function removeManualMarker(domain) {
  await removePath(manualMarkerPath(domain));
}

// Write fullchain + private key into the site's cert dir (700 dir, 600 files,
// root:root). Callers must have validated the pair BEFORE this point.
export async function installCertFiles(helpers, domain, { fullchain, key }) {
  const dir = certDir(domain);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const norm = (s) => (s.endsWith('\n') ? s : s + '\n');
  await fs.writeFile(`${dir}/fullchain.pem`, norm(fullchain), { mode: 0o600 });
  await fs.writeFile(`${dir}/key.pem`, norm(key), { mode: 0o600 });
  await run(helpers, 'chown', ['-R', 'root:root', dir]);
}

// Remove top-level `server { ... }` blocks that listen on 443 (old WordOps
// layout: both vhosts in sites-available/<domain>). Brace-matched; anything
// that doesn't parse as a clean block is left untouched.
export function stripSslServerBlocks(content) {
  let out = '';
  let i = 0;
  while (i < content.length) {
    const idx = content.indexOf('server', i);
    if (idx < 0) { out += content.slice(i); break; }
    const lineStart = content.lastIndexOf('\n', idx - 1) + 1;
    const atLineStart = content.slice(lineStart, idx).trim() === '';
    const brace = content.indexOf('{', idx);
    const cleanBlock =
      atLineStart &&
      brace > idx &&
      /^[ \t]*$/.test(content.slice(idx + 6, brace)) &&
      braceDepth(content.slice(0, idx)) === 0;
    if (cleanBlock) {
      const end = matchingBrace(content, brace);
      if (end > 0) {
        const block = content.slice(idx, end + 1);
        if (!/listen[ \t]+443\b/.test(block)) out += block;
        i = end + 1;
        continue;
      }
    }
    out += content.slice(i, idx + 6);
    i = idx + 6;
  }
  return out;
}

function braceDepth(s) {
  let d = 0;
  for (const ch of s) { if (ch === '{') d += 1; else if (ch === '}') d -= 1; }
  return d;
}

function matchingBrace(s, openIdx) {
  let d = 0;
  for (let i = openIdx; i < s.length; i++) {
    if (s[i] === '{') d += 1;
    else if (s[i] === '}') { d -= 1; if (d === 0) return i; }
  }
  return -1;
}

export const mainVhostPath = (domain) => `/etc/nginx/sites-available/${domain}`;

// Point the site's nginx at the cert in its cert dir. The port-443 config must
// live ONLY in conf/nginx/ssl.conf: if the main vhost still carries its own
// 443 `server` block (old WordOps layout), the bare `listen 443` from
// ssl.conf would be included into that block too and nginx -t fails with
// "duplicate listen" — so such blocks are stripped in the same step.
// Everything is ONE backup -> nginx -t -> rollback transaction: on failure
// each touched file returns to its exact prior state, including absence —
// a cert change can never leave the box with a broken nginx config.
export async function applySslConf(helpers, domain) {
  const { ok, err } = logger(helpers);
  const confDir = `${config.wwwDir}/${domain}/conf/nginx`;
  const conf = `${confDir}/ssl.conf`;
  const main = mainVhostPath(domain);

  await fs.mkdir(confDir, { recursive: true });

  const edits = []; // { path, before (null = absent), after }
  if (await pathExists(main)) {
    const before = await fs.readFile(main, 'utf8');
    const after = stripSslServerBlocks(before); // no-op when no 443 block
    if (after !== before) edits.push({ path: main, before, after });
  }
  edits.push({
    path: conf,
    before: (await pathExists(conf)) ? await fs.readFile(conf, 'utf8') : null,
    after: sslConfContent(domain),
  });

  for (const e of edits) await fs.writeFile(e.path, e.after, { mode: 0o644 });

  if (!(await nginxTest(helpers))) {
    for (const e of edits) {
      if (e.before === null) await removePath(e.path);
      else await fs.writeFile(e.path, e.before, { mode: 0o644 });
    }
    err('nginx -t FAILED with the new SSL config — previous config restored');
    throw new Error('nginx -t failed with the new SSL config — the previous config was restored, nothing was reloaded');
  }
  await nginxReload(helpers);
  ok('nginx validated + reloaded with the new SSL config');
}
