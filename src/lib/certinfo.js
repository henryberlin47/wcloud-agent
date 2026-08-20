import { run, pathExists } from './sys.js';
import { fullchainPath, manualMarkerPath } from './certinstall.js';

// ============================================================
//  certinfo.js — read live certificate state
// ============================================================
// The cert on disk is the source of truth for a site's SSL state: nothing is
// stored per-site, everything is parsed on demand with openssl.
//
// source:      none | letsencrypt | letsencrypt-manual | custom
// auto_renew:  true only for letsencrypt (a WordOps-issued HTTP-01 cert).
//              custom + manual-DNS certs lapse silently — the portal shows why.

// Parse subject/issuer/SAN/expiry from a PEM cert (quiet probe).
// Returns null when the file is not a readable x509 cert.
export async function readCertInfo(helpers, certPath) {
  const r = await run(helpers, 'openssl', [
    'x509', '-in', certPath, '-noout',
    '-subject', '-issuer', '-enddate', '-ext', 'subjectAltName',
  ], { quiet: true, timeout: 15_000 });
  if (r.code !== 0) return null;

  const subject = (r.stdout.match(/^subject=(.*)$/m) || [])[1] || '';
  const issuer = (r.stdout.match(/^issuer=(.*)$/m) || [])[1] || '';
  const enddate = (r.stdout.match(/^notAfter=(.*)$/m) || [])[1] || '';
  const notAfter = enddate ? Date.parse(enddate) : NaN;
  const sans = [...r.stdout.matchAll(/DNS:([^,\s]+)/g)].map((m) => m[1]);

  return {
    subject: subject.trim().replace(/\s{2,}/g, ' '),
    issuer: issuer.trim().replace(/\s{2,}/g, ' '),
    sans,
    not_after: Number.isNaN(notAfter) ? null : new Date(notAfter).toISOString(),
    days_left: Number.isNaN(notAfter) ? null : Math.ceil((notAfter - Date.now()) / 86_400_000),
    self_signed: subject.trim() !== '' && subject.trim() === issuer.trim(),
  };
}

// Full live SSL state for a site (feeds GET /api/sites/:domain/ssl).
export async function readSiteSsl(helpers, domain) {
  const base = { domain };
  const fc = fullchainPath(domain);
  if (!(await pathExists(fc))) {
    return { ...base, enabled: false, source: 'none', auto_renew: false };
  }
  const info = await readCertInfo(helpers, fc);
  if (!info) {
    return { ...base, enabled: false, source: 'none', auto_renew: false, note: 'cert on disk could not be parsed' };
  }
  const isLe = /let['’]?s? ?encrypt/i.test(info.issuer);
  const manual = isLe && (await pathExists(manualMarkerPath(domain)));
  const source = isLe ? (manual ? 'letsencrypt-manual' : 'letsencrypt') : 'custom';
  return {
    ...base,
    enabled: true,
    source,
    auto_renew: source === 'letsencrypt',
    issuer: info.issuer,
    subject: info.subject,
    sans: info.sans,
    not_after: info.not_after,
    days_left: info.days_left,
    self_signed: info.self_signed,
  };
}
