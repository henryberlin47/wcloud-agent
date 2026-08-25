import fs from 'node:fs/promises';
import { randomBytes, X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import config from '../config.js';
import {
  run, woSiteExists, pathExists, removePath,
  nginxTest, nginxReload, certCovers, pinWpUrls, WO_SITE_TIMEOUT_MS,
} from '../lib/sys.js';
import {
  certDir, fullchainPath, keyPath,
  sslConfContent, installCertFiles, applySslConf,
  removeManualMarker, stripSslServerBlocks, mainVhostPath,
} from '../lib/certinstall.js';
import { logger } from '../lib/log.js';
import { startManualDns, verifyManualDns } from '../lib/acmedns.js';

// ============================================================
//  ssl — mode-driven SSL management for a site
// ============================================================
// The live cert on disk is the source of truth (see GET
// /api/sites/:domain/ssl); this op applies a mode:
//   off            → drop the port-443 include (certs stay on disk)
//   le-http        → wo site update <domain> --le --force (HTTP-01, auto-renews)
//   le-dns-manual  → step 1 of manual DNS-01: start the challenge, print TXT
//                    records (verified later by the sslDnsVerify op)
//   custom         → paste a fullchain + key; validated BEFORE anything is written
// ============================================================

export async function runSsl(job, helpers, p) {
  const domain = p.domain;
  if (!(await woSiteExists(helpers, domain))) {
    throw new Error(`Site not found: ${domain}`);
  }
  switch (p.mode) {
    case 'off': return runSslOff(helpers, domain);
    case 'le-http': return runSslLeHttp(helpers, domain);
    case 'le-dns-manual': {
      const state = await startManualDns(helpers, domain);
      job.result = { pending: true, txt_records: state.txt_records };
      return state;
    }
    case 'custom': return runSslCustom(helpers, domain, p);
    default: throw new Error(`unknown SSL mode: ${p.mode}`);
  }
}

// Step 2 of manual DNS-01 — a standalone op (POST /api/op/sslDnsVerify):
// the TXT records are already in place, verify them against the CA.
export async function runSslDnsVerify(job, helpers, p) {
  const domain = p.domain;
  if (!(await woSiteExists(helpers, domain))) {
    throw new Error(`Site not found: ${domain}`);
  }
  return verifyManualDns(helpers, domain);
}

// --- off --------------------------------------------------------------------
// Remove the port-443 config but keep the certs on disk (WordOps may still
// reference them, e.g. the :22222 panel). Back up, edit, nginx -t, roll back
// on failure — the same contract as setCanonical's vhost edits.

async function runSslOff(helpers, domain) {
  const { step, ok } = logger(helpers);
  step('Turn off HTTPS');

  const edits = []; // { path, action: "remove" | "rewrite", content? }
  const sslConf = `${config.wwwDir}/${domain}/conf/nginx/ssl.conf`;
  if (await pathExists(sslConf)) {
    const c = await fs.readFile(sslConf, 'utf8');
    if (/listen[ \t]+443|ssl_certificate/.test(c)) edits.push({ path: sslConf, action: 'remove' });
  }
  const main = mainVhostPath(domain);
  if (await pathExists(main)) {
    const c = await fs.readFile(main, 'utf8');
    if (/listen[ \t]+443/.test(c)) {
      const out = stripSslServerBlocks(c);
      if (out !== c) edits.push({ path: main, action: 'rewrite', content: out });
    }
  }

  if (!edits.length) {
    ok(`HTTPS was already off for ${domain}`);
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
    await pinWpUrls(helpers, domain, { scheme: 'http' });
    ok(`HTTPS turned off — ${domain} now serves over HTTP. The certificate is kept, so turning it back on is instant.`);
  } else {
    for (const [path, bak] of backups) await fs.copyFile(bak, path);
    for (const b of backups.values()) await removePath(b);
    throw new Error('Turning HTTPS off would have left the web server with an invalid configuration, so the change was reverted and nothing was reloaded. The site is untouched.');
  }
}

// --- le-http ----------------------------------------------------------------
// Current HTTP-01 issuance via WordOps (auto-renews). After a success the
// vhost must point at the LE paths — rewrite conf/nginx/ssl.conf only when it
// is missing or stale (WordOps itself won't overwrite an existing one).

async function runSslLeHttp(helpers, domain) {
  const { step, ok, warn } = logger(helpers);
  step('Request a Let\'s Encrypt certificate');
  const r = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force'], { timeout: WO_SITE_TIMEOUT_MS });
  if (r.code !== 0) {
    const detail = r.timedOut
      ? `timed out after ${WO_SITE_TIMEOUT_MS}ms`
      : `code ${r.code}`;
    throw new Error(r.timedOut
      ? `The certificate request for ${domain} timed out. Try again in a few minutes.`
      : `Could not issue a certificate for ${domain}. Check that its DNS points to this server and that port 80 is reachable, then try again.`);
  }
  ok(`Certificate issued for ${domain}`);

  // This cert auto-renews again: drop any manual-DNS marker.
  await removeManualMarker(domain);

  const conf = `${config.wwwDir}/${domain}/conf/nginx/ssl.conf`;
  if (await pathExists(conf)) {
    const c = await fs.readFile(conf, 'utf8');
    if (!c.includes(fullchainPath(domain)) || !c.includes(keyPath(domain))) {
      await fs.writeFile(conf, sslConfContent(domain), { mode: 0o644 });
      warn('The site was pointing at an old certificate — updated it');
    }
  } else {
    await fs.mkdir(`${config.wwwDir}/${domain}/conf/nginx`, { recursive: true });
    await fs.writeFile(conf, sslConfContent(domain), { mode: 0o644 });
    warn('The site had no HTTPS configuration — created one');
  }

  if (await nginxTest(helpers)) {
    await nginxReload(helpers);
    ok('Web server reloaded');
  } else {
    throw new Error('The certificate was issued but the resulting web server configuration is invalid, so it was not reloaded. The site keeps running on its previous configuration.');
  }

  // WordPress still points at http:// until told otherwise — leaving it would
  // make nginx and WordPress redirect at each other (ERR_TOO_MANY_REDIRECTS).
  await pinWpUrls(helpers, domain, { scheme: 'https' });
}

// --- custom -----------------------------------------------------------------
// Pasted fullchain + key. Every check happens BEFORE any file is touched; a
// bad pair never reaches disk (a mismatched pair would break nginx box-wide).

async function runSslCustom(helpers, domain, p) {
  const { step, ok, warn, log , done } = logger(helpers);
  const { cert, key } = p;

  step('Check the certificate and key');
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
      throw new Error('That does not look like a valid certificate. Paste the full-chain certificate in PEM format (it starts with "-----BEGIN CERTIFICATE-----"). Nothing was changed.');
    }
    let keySpki;
    try {
      keySpki = createPublicKey(createPrivateKey(key)).export({ type: 'spki', format: 'der' });
    } catch {
      throw new Error('That does not look like a valid private key. Paste the key in PEM format (it starts with "-----BEGIN PRIVATE KEY-----"). Nothing was changed.');
    }
    if (!certSpki.equals(keySpki)) {
      throw new Error('The certificate and private key do not belong together. Re-copy both from your certificate provider. Nothing was changed.');
    }
    ok('Certificate and key match');

    await fs.writeFile(certFile, cert, { mode: 0o600 });
    if (!(await certCovers(helpers, certFile, domain))) {
      throw new Error(`This certificate is not valid for ${domain} — it was issued for a different domain. Nothing was changed.`);
    }
    ok(`Certificate covers ${domain}`);
    const www = `www.${domain}`;
    if (await vhostServesHost(domain, www)) {
      if (!(await certCovers(helpers, certFile, www))) {
        warn(`This certificate does not cover ${www}, so that address will show a security warning over HTTPS.`);
      }
    }
  } finally {
    await removePath(tmp); // key material never lingers on disk
  }

  step('Install the certificate');
  await installCertFiles(helpers, domain, { fullchain: cert, key });
  ok(`installed 600 root:root in ${certDir(domain)}`);
  await removeManualMarker(domain);

  step('Point the site at the new certificate');
  await applySslConf(helpers, domain);
  await pinWpUrls(helpers, domain, { scheme: 'https' });
  done(`HTTPS is now using your certificate — ${domain}`);
}

// True if the vhost serves www.<domain> (a cert without it would break that
// version over HTTPS). Probes the same files setCanonical edits.
async function vhostServesHost(domain, host) {
  for (const f of [mainVhostPath(domain), `${config.wwwDir}/${domain}/conf/nginx/ssl.conf`]) {
    if (await pathExists(f)) {
      const c = await fs.readFile(f, 'utf8');
      if (c.includes(host)) return true;
    }
  }
  return false;
}
