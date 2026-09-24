import { logger } from '../lib/log.js';
import { requireSpec, applySite, applySslConf, syncWpAddress, certDir } from '../lib/sites.js';
import { issueHttp, startManualDns, verifyManualDns, removeManualMarker } from '../lib/acme.js';
import { checkCustomCert } from '../lib/certcheck.js';

// ============================================================
//  ssl — mode-driven SSL management for a site
// ============================================================
// The site spec's `ssl` flag says whether HTTPS is served; the cert on disk
// (sites.certDir) says with what. This op applies a mode:
//   off            → HTTP only (the cert stays on disk: turning it back on is instant)
//   le-http        → Let's Encrypt over HTTP-01 (auto-renews)
//   le-dns-manual  → step 1 of manual DNS-01: start the challenge, print TXT
//                    records (verified later by the sslDnsVerify op)
//   custom         → pasted fullchain + key; validated BEFORE anything is written
// ============================================================

export async function runSsl(job, helpers, p) {
  const domain = p.domain;
  await requireSpec(domain);
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
  await requireSpec(p.domain);
  return verifyManualDns(helpers, p.domain);
}

async function runSslOff(helpers, domain) {
  const { step, ok } = logger(helpers);
  step('Turn off HTTPS');
  const s = await requireSpec(domain);
  if (!s.ssl) { ok(`HTTPS was already off for ${domain}`); return; }
  const next = { ...s, ssl: false };
  await applySite(helpers, next);
  await syncWpAddress(helpers, next);
  ok(`HTTPS turned off — ${domain} now serves over HTTP. The certificate is kept, so turning it back on is instant.`);
}

async function runSslLeHttp(helpers, domain) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(domain);
  step('Request a Let\'s Encrypt certificate');
  const r = await issueHttp(helpers, domain, { www: s.enableWww });
  if (!r.ok) {
    throw new Error(r.timedOut
      ? `The certificate request for ${domain} timed out. Try again in a few minutes.`
      : `Could not issue a certificate for ${domain}. Check that its DNS points to this server and that port 80 is reachable, then try again.`);
  }
  ok(`Certificate issued for ${r.www ? `${domain} and www.${domain}` : domain} — it renews automatically`);
  // WordPress still points at http:// until told otherwise — leaving it would
  // make nginx and WordPress redirect at each other (ERR_TOO_MANY_REDIRECTS).
  await syncWpAddress(helpers, await requireSpec(domain));
  done(`HTTPS enabled for ${domain}`);
}

// Pasted fullchain + key. Every check happens BEFORE any file is touched; a
// bad pair never reaches disk (a mismatched pair would break nginx box-wide).
async function runSslCustom(helpers, domain, p) {
  const { step, ok, warn, done } = logger(helpers);
  const s = await requireSpec(domain);

  step('Check the certificate and key');
  const { warnings } = checkCustomCert(domain, p.cert, p.key, { www: s.enableWww });
  ok(`Certificate and key match, and cover ${domain}`);
  for (const w of warnings) warn(w);

  step('Install the certificate and point the site at it');
  // One transaction: if nginx rejects the new pair, the previous cert files
  // come back along with the config (installed 600 root:root in certDir).
  await applySslConf(helpers, domain, { certs: { fullchain: p.cert, key: p.key } });
  ok(`Installed in ${certDir(domain)}`);
  await removeManualMarker(domain);
  await syncWpAddress(helpers, await requireSpec(domain));
  done(`HTTPS is now using your certificate — ${domain}`);
}
