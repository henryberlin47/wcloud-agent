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

// Point the site's nginx at the cert in its cert dir: write conf/nginx/ssl.conf,
// nginx -t, reload. If nginx -t fails the previous conf is restored first —
// a cert change can never leave the box with a broken nginx config.
export async function applySslConf(helpers, domain) {
  const { ok, err } = logger(helpers);
  const confDir = `${config.wwwDir}/${domain}/conf/nginx`;
  const conf = `${confDir}/ssl.conf`;
  const backup = `${conf}.wcloud-bak`;

  await fs.mkdir(confDir, { recursive: true });
  if (await pathExists(conf)) await fs.copyFile(conf, backup);
  await fs.writeFile(conf, sslConfContent(domain), { mode: 0o644 });

  if (!(await nginxTest(helpers))) {
    if (await pathExists(backup)) {
      await fs.copyFile(backup, conf);
      await removePath(backup);
    }
    err('nginx -t FAILED with the new ssl.conf — previous config restored');
    throw new Error('nginx -t failed with the new SSL config — the previous config was restored, nothing was reloaded');
  }
  await removePath(backup);
  await nginxReload(helpers);
  ok('nginx validated + reloaded with the new SSL config');
}
