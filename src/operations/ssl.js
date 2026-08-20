import fs from 'node:fs/promises';
import { randomBytes, X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import config from '../config.js';
import {
  run, woSiteExists, pathExists, removePath,
  nginxTest, nginxReload, certCovers,
} from '../lib/sys.js';
import {
  certDir, fullchainPath, keyPath,
  sslConfContent, installCertFiles, applySslConf,
  removeManualMarker,
} from '../lib/certinstall.js';
import { logger } from '../lib/log.js';

// ============================================================
//  ssl — mode-driven SSL management for a site
// ============================================================
// The live cert on disk is the source of truth (see GET
// /api/sites/:domain/ssl); this op applies a mode:
//   off         → drop the port-443 include (certs stay on disk)
//   le-http     → wo site update <domain> --le --force (HTTP-01, auto-renews)
//   custom      → paste a fullchain + key; validated BEFORE anything is written
// ============================================================

export async function runSsl(job, helpers, p) {
  const domain = p.domain;
  if (!(await woSiteExists(helpers, domain))) {
    throw new Error(`Site not found: ${domain}`);
  }
  switch (p.mode) {
    case 'off': return runSslOff(helpers, domain);
    case 'le-http': return runSslLeHttp(helpers, domain);
    case 'custom': return runSslCustom(helpers, domain, p);
    default: throw new Error(`unknown SSL mode: ${p.mode}`);
  }
}

// --- off --------------------------------------------------------------------
// Remove the port-443 config but keep the certs on disk (WordOps may still
// reference them, e.g. the :22222 panel). Back up, edit, nginx -t, roll back
// on failure — the same contract as setCanonical's vhost edits.

async function runSslOff(helpers, domain) {
  const { step, ok } = logger(helpers);
  step('Remove SSL (certs stay on disk)');

  const edits = []; // { path, action: "remove" | "rewrite", content? }
  const sslConf = `${config.wwwDir}/${domain}/conf/nginx/ssl.conf`;
  if (await pathExists(sslConf)) {
    const c = await fs.readFile(sslConf, 'utf8');
    if (/listen[ \t]+443|ssl_certificate/.test(c)) edits.push({ path: sslConf, action: 'remove' });
  }
  const main = `/etc/nginx/sites-available/${domain}`;
  if (await pathExists(main)) {
    const c = await fs.readFile(main, 'utf8');
    if (/listen[ \t]+443/.test(c)) {
      const out = stripSslServerBlocks(c);
      if (out !== c) edits.push({ path: main, action: 'rewrite', content: out });
    }
  }

  if (!edits.length) {
    ok(`No port-443 config found for ${domain} — SSL already off`);
    return;
  }

  const backups = new Map();
  for (const e of edits) {
    await fs.copyFile(e.path, `${e.path}.wcloud-bak`);
    backups.set(e.path, `${e.path}.wcloud-bak`);
    if (e.action === 'remove') await removePath(e.path);
    else await fs.writeFile(e.path, e.content, { mode: 0o644 });
  }

  if (await nginxTest(helpers)) {
    for (const b of backups.values()) await removePath(b);
    await nginxReload(helpers);
    ok(`HTTPS disabled for ${domain} — certs kept on disk`);
  } else {
    for (const [path, bak] of backups) await fs.copyFile(bak, path);
    for (const b of backups.values()) await removePath(b);
    throw new Error('nginx -t FAILED after removing the SSL config — reverted, nothing was reloaded; inspect the vhost manually');
  }
}

// Remove top-level `server { ... }` blocks that listen on 443 (old WordOps
// layout: both vhosts in sites-available/<domain>). Brace-matched; anything
// that doesn't parse as a clean block is left untouched.
function stripSslServerBlocks(content) {
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

// --- le-http ----------------------------------------------------------------
// Current HTTP-01 issuance via WordOps (auto-renews). After a success the
// vhost must point at the LE paths — rewrite conf/nginx/ssl.conf only when it
// is missing or stale (WordOps itself won't overwrite an existing one).

async function runSslLeHttp(helpers, domain) {
  const { step, ok, warn } = logger(helpers);
  step('Issue Let\'s Encrypt certificate (HTTP-01)');
  const r = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force']);
  if (r.code !== 0) {
    throw new Error(`SSL issuance failed for ${domain} — ensure its DNS points to this server and port 80 is reachable`);
  }
  ok(`Let's Encrypt cert issued for ${domain}`);

  // This cert auto-renews again: drop any manual-DNS marker.
  await removeManualMarker(domain);

  const conf = `${config.wwwDir}/${domain}/conf/nginx/ssl.conf`;
  if (await pathExists(conf)) {
    const c = await fs.readFile(conf, 'utf8');
    if (!c.includes(fullchainPath(domain)) || !c.includes(keyPath(domain))) {
      await fs.writeFile(conf, sslConfContent(domain), { mode: 0o644 });
      warn('ssl.conf was not pointing at the new cert — rewrote it');
    }
  } else {
    await fs.mkdir(`${config.wwwDir}/${domain}/conf/nginx`, { recursive: true });
    await fs.writeFile(conf, sslConfContent(domain), { mode: 0o644 });
    warn('no ssl.conf found — wrote one pointing at the new cert');
  }

  if (await nginxTest(helpers)) {
    await nginxReload(helpers);
    ok('nginx validated + reloaded');
  } else {
    throw new Error('nginx -t FAILED after SSL issuance — review the config before the next reload');
  }
}

// --- custom -----------------------------------------------------------------
// Pasted fullchain + key. Every check happens BEFORE any file is touched; a
// bad pair never reaches disk (a mismatched pair would break nginx box-wide).

async function runSslCustom(helpers, domain, p) {
  const { step, ok, warn, log } = logger(helpers);
  const { cert, key } = p;

  step('Validate the pasted certificate + key');
  const tmp = `/tmp/wcloud_sslcheck_${Date.now()}_${randomBytes(4).toString('hex')}`;
  await fs.mkdir(tmp, { recursive: true, mode: 0o700 });
  const certFile = `${tmp}/cert.pem`;
  try {
    // Node crypto, not openssl: identical behavior on LibreSSL, OpenSSL 1.1.1
    // and 3.x, and public-key compare covers RSA/EC/Ed25519. The key is
    // parsed in memory only — it never touches disk before installCertFiles.
    let certSpki;
    try {
      certSpki = new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' });
    } catch {
      throw new Error('cert is not a valid PEM certificate — nothing was written');
    }
    let keySpki;
    try {
      keySpki = createPublicKey(createPrivateKey(key)).export({ type: 'spki', format: 'der' });
    } catch {
      throw new Error('key is not a valid PEM private key — nothing was written');
    }
    if (!certSpki.equals(keySpki)) {
      throw new Error('cert and key do not match (different public keys) — nothing was written');
    }
    ok('cert and key are a matching pair');

    await fs.writeFile(certFile, cert, { mode: 0o600 });
    if (!(await certCovers(helpers, certFile, domain))) {
      throw new Error(`cert does not cover ${domain} (no matching SAN) — nothing was written`);
    }
    ok(`cert covers ${domain}`);
    const www = `www.${domain}`;
    if (await vhostServesHost(domain, www)) {
      if (!(await certCovers(helpers, certFile, www))) {
        warn(`cert does not cover ${www} — the www version will not work over HTTPS`);
      }
    }
  } finally {
    await removePath(tmp); // key material never lingers on disk
  }

  step('Install certificate + key');
  await installCertFiles(helpers, domain, { fullchain: cert, key });
  ok(`installed 600 root:root in ${certDir(domain)}`);
  await removeManualMarker(domain);

  step('Wire nginx + validate');
  await applySslConf(helpers, domain);
  log(`Custom SSL installed for ${domain}`);
}

// True if the vhost serves www.<domain> (a cert without it would break that
// version over HTTPS). Probes the same files setCanonical edits.
async function vhostServesHost(domain, host) {
  for (const f of [`/etc/nginx/sites-available/${domain}`, `${config.wwwDir}/${domain}/conf/nginx/ssl.conf`]) {
    if (await pathExists(f)) {
      const c = await fs.readFile(f, 'utf8');
      if (c.includes(host)) return true;
    }
  }
  return false;
}
