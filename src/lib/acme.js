import fs from 'node:fs/promises';
import config from '../config.js';
import { run, pathExists, removePath, withLock } from './sys.js';
import { logger } from './log.js';
import { certDir, applySslConf, requireSpec, syncWpAddress, cfDnsTokenPath } from './sites.js';

// ============================================================
//  acme.js — Let's Encrypt certificates via acme.sh
// ============================================================
// init.sh installs acme.sh at /etc/letsencrypt (config home
// /etc/letsencrypt/config, cert home /etc/letsencrypt/renewal, ec-256 keys →
// the domain conf lives in <D>_ecc/) with its daily renewal cron. Every
// issuer's cert ends up at /etc/letsencrypt/live/<D>/ (sites.certDir).
//
// HTTP-01 (issueHttp): the challenge is answered from /var/www/html, which
// every vhost serves at /.well-known/acme-challenge/ even when it redirects to
// HTTPS. acme.sh stores the install paths + reload command, so renewals land
// in place and reload nginx on their own.
//
// Manual DNS-01 (two-step):
//
//   start  --issue --dns -d D --force --yes-I-know...  → prints the TXT
//                                                        records, saves the
//                                                        ACME order (Le_Vlist)
//                                                        in the domain conf,
//                                                        exits 3
//   verify --renew  -d D --force --yes-I-know...       → checks the TXT
//                                                        against the CA,
//                                                        downloads the cert
//
// acme.sh clears Le_Vlist after EVERY verification attempt — without it the
// next run would start a NEW order (a new TXT the user must re-add). We keep
// the vlist in our own state file and restore it into the conf before each
// verify, so the same token stays valid for as long as propagation takes.

const ACME = '/etc/letsencrypt/acme.sh';
const ACME_OPTS = ['--config-home', '/etc/letsencrypt/config'];
// acme.sh one call at a time (shared account.conf) — sys.withLock.
const acme = (helpers, args, opts) => withLock('acme', () => run(helpers, ACME, args, opts));
const MANUAL_FLAG = '--yes-I-know-dns-manual-mode-enough-go-ahead-please';
const CODE_DNS_MANUAL = 3;
const STATE_DIR = '/var/lib/wcloud/ssl-challenge';
const ACME_WEBROOT = '/var/www/html';

// Marker: the current cert was issued via manual DNS-01 and will NOT be
// auto-renewed. Read by certinfo; removed whenever a new cert is installed.
export const manualMarkerPath = (domain) => `${config.wwwDir}/${domain}/conf/nginx/.wcloud-ssl-manual`;
const writeManualMarker = (domain) =>
  fs.writeFile(manualMarkerPath(domain), `manual dns-01 ${new Date().toISOString()}\n`, { mode: 0o600 });
export const removeManualMarker = (domain) => removePath(manualMarkerPath(domain));

// Copy an issued cert into certDir (600 root:root). With a reload command
// acme.sh repeats this after every renewal.
async function installCert(helpers, domain, { renew }) {
  const dir = certDir(domain);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const inst = await withLock('config', () => run(helpers, ACME, [
    ...ACME_OPTS, '--install-cert', '-d', domain, '--ecc',
    '--cert-file', `${dir}/cert.pem`,
    '--key-file', `${dir}/key.pem`,
    '--fullchain-file', `${dir}/fullchain.pem`,
    '--ca-file', `${dir}/ca.pem`,
    ...(renew ? ['--reloadcmd', 'systemctl reload nginx'] : []),
  ], { quiet: true, timeout: 60_000 }));
  if (inst.code !== 0) {
    throw new Error('The certificate was issued but could not be installed on this server. See the details above.');
  }
  await run(helpers, 'chmod', ['600', `${dir}/cert.pem`, `${dir}/key.pem`, `${dir}/fullchain.pem`, `${dir}/ca.pem`]);
  await run(helpers, 'chown', ['-R', 'root:root', dir]);
}

// --- DNS-01 through the Cloudflare API (auto-renewing, by the agent) ------------
// acme.sh's dns_cf plugin sets the TXT records itself — works behind
// Cloudflare's proxy, no port 80 needed. acme.sh keeps ONE Cloudflare token
// per server (account.conf), but sites may use different tokens: so the
// domain is taken off acme.sh's renewal list, acme.sh's saved copy is wiped,
// and the site's own token is kept root-only for the agent's renewer
// (startDnsRenewer) instead.
export async function issueDnsCloudflare(helpers, domain, { www = false, token, zoneId }) {
  const { err } = logger(helpers);
  // Issue + wipe the token acme.sh saved, together: no other acme.sh call in between.
  const r = await withLock('acme', async () => {
    const res = await run(helpers, ACME, [...ACME_OPTS, '--issue', '--server', 'letsencrypt', '--dns', 'dns_cf',
      '-d', domain, ...(www ? ['-d', `www.${domain}`] : []), '--keylength', 'ec-256', '--force'],
    { env: { CF_Token: token, CF_Zone_ID: zoneId }, quiet: true, timeout: 600_000 });
    await forgetAcmeCfToken();
    return res;
  });
  if (r.code !== 0) {
    for (const l of `${r.stdout}\n${r.stderr}`.trim().split('\n').slice(-6)) err(`    ${stripAnsi(l)}`);
    return { ok: false, timedOut: !!r.timedOut };
  }
  await installCert(helpers, domain, { renew: false });
  await acme(helpers, [...ACME_OPTS, '--remove', '-d', domain, '--ecc'], { quiet: true, timeout: 60_000 });
  await fs.mkdir('/etc/wcloud/cf-dns', { recursive: true, mode: 0o700 });
  await fs.writeFile(cfDnsTokenPath(domain), JSON.stringify({ token, zoneId, www }), { mode: 0o600 });
  await removeManualMarker(domain);
  await applySslConf(helpers, domain, { sslDns: 'cloudflare' });
  return { ok: true };
}

// acme.sh saves the dns_cf credentials it was given into account.conf.
async function forgetAcmeCfToken() {
  const conf = '/etc/letsencrypt/config/account.conf';
  const c = await fs.readFile(conf, 'utf8').catch(() => null);
  if (c && /^SAVED_CF_/m.test(c)) await fs.writeFile(conf, c.split('\n').filter((l) => !/^SAVED_CF_/.test(l)).join('\n'), { mode: 0o600 });
}

// Renew Cloudflare-DNS certificates with 30 days or less left. `enqueue`
// (jobs.js) runs them like any other operation (one job per site at a time).
export function startDnsRenewer(enqueue, { listSites, readCertInfo, fullchainPath }) {
  const tick = async () => {
    for (const s of await listSites()) {
      if (s.sslDns !== 'cloudflare') continue;
      const info = await readCertInfo({ log() {}, err() {} }, fullchainPath(s.domain));
      if (info && info.days_left != null && info.days_left > 30) continue;
      enqueue('ssl-renew', { domain: s.domain }, async (job, helpers) => {
        const { step, ok } = logger(helpers);
        step(`Renew the Let's Encrypt certificate for ${s.domain} (Cloudflare DNS)`);
        let t;
        try { t = JSON.parse(await fs.readFile(cfDnsTokenPath(s.domain), 'utf8')); } catch { throw new Error('The Cloudflare token for this site is missing — issue the certificate again from the site page.'); }
        const r = await issueDnsCloudflare(helpers, s.domain, { www: t.www, token: t.token, zoneId: t.zoneId });
        if (!r.ok) throw new Error('Renewal failed — check that the Cloudflare token still works.');
        ok('Certificate renewed');
      });
    }
  };
  setTimeout(() => tick().catch((e) => console.error('[agent] dns renewer:', e.message)), 120_000).unref();
  setInterval(() => tick().catch((e) => console.error('[agent] dns renewer:', e.message)), 12 * 3600_000).unref();
}

// --- HTTP-01 (auto-renewing) --------------------------------------------------
// Issue for <domain> (+ www.<domain> when the site serves it), install it and
// switch the site to HTTPS. www failing (no DNS record yet) falls back to the
// bare domain rather than failing outright. Returns { ok, www, timedOut }.
export async function issueHttp(helpers, domain, { www = false } = {}) {
  const { warn } = logger(helpers);
  const issue = (withWww) => acme(helpers, [...ACME_OPTS, '--issue', '--server', 'letsencrypt',
    '-w', ACME_WEBROOT, '-d', domain, ...(withWww ? ['-d', `www.${domain}`] : []),
    '--keylength', 'ec-256', '--force'], { quiet: true, timeout: 300_000 });

  let r = await issue(www);
  let covered = www;
  if (r.code !== 0 && www && !r.timedOut) {
    warn(`www.${domain} could not be verified (does its DNS point here?) — issuing for ${domain} only`);
    r = await issue(false);
    covered = false;
  }
  if (r.code !== 0) {
    const tail = `${r.stdout}\n${r.stderr}`.trim().split('\n').slice(-6);
    for (const l of tail) helpers.err?.(`    ${stripAnsi(l)}`);
    return { ok: false, www: false, timedOut: !!r.timedOut };
  }
  await installCert(helpers, domain, { renew: true });
  await removeManualMarker(domain);
  await applySslConf(helpers, domain);
  return { ok: true, www: covered };
}

const stripAnsi = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '');

export const statePath = (domain) => `${STATE_DIR}/${domain}.json`;

export async function readChallenge(domain) {
  try {
    const s = JSON.parse(await fs.readFile(statePath(domain), 'utf8'));
    return s && s.domain === domain && Array.isArray(s.txt_records) ? s : null;
  } catch {
    return null;
  }
}

async function writeChallenge(domain, state) {
  await fs.mkdir(STATE_DIR, { recursive: true, mode: 0o755 });
  await fs.writeFile(statePath(domain), JSON.stringify(state, null, 2), { mode: 0o644 });
}

export async function clearChallenge(domain) {
  await fs.rm(statePath(domain), { force: true });
}

// "Domain: '_acme-challenge.d'" / "TXT value: 'v'" pairs from the issue output.
export function parseTxtRecords(stdout) {
  const records = [];
  let current = null;
  for (const line of stripAnsi(stdout).split('\n')) {
    const d = line.match(/Domain:\s*'([^']+)'/);
    if (d) { current = d[1]; continue; }
    const t = line.match(/TXT value:\s*'([^']+)'/);
    if (t && current) { records.push({ domain: current, value: t[1] }); current = null; }
  }
  return records;
}

// acme.sh v3 defaults to ec-256 → <D>_ecc dir; probe the plain <D> dir too
// (legacy RSA domains).
async function findDomainConf(domain) {
  for (const dir of [`${domain}_ecc`, domain]) {
    const conf = `/etc/letsencrypt/renewal/${dir}/${domain}.conf`;
    if (await pathExists(conf)) return conf;
  }
  return null;
}

async function readVlist(domain) {
  const conf = await findDomainConf(domain);
  if (!conf) return '';
  const m = (await fs.readFile(conf, 'utf8')).match(/^Le_Vlist='([^']*)'$/m);
  return m ? m[1] : '';
}

async function restoreVlist(domain, vlist) {
  const conf = await findDomainConf(domain);
  if (!conf || !vlist) return false;
  const c = await fs.readFile(conf, 'utf8');
  const next = /^Le_Vlist='[^']*'$/m.test(c)
    ? c.replace(/^Le_Vlist='[^']*'$/m, `Le_Vlist='${vlist}'`)
    : `${c}${c.endsWith('\n') ? '' : '\n'}Le_Vlist='${vlist}'\n`;
  await fs.writeFile(conf, next);
  return true;
}

// --- step 1: start the challenge ------------------------------------------------
export async function startManualDns(helpers, domain) {
  const { step, ok, err } = logger(helpers);
  if (!(await pathExists(ACME))) {
    throw new Error('This server has no certificate tool installed. Re-run the server install command.');
  }
  await clearChallenge(domain); // a fresh start supersedes any stale pending challenge

  // Pin the key type: verify/install below always pass --ecc, so the order must
  // live in <D>_ecc no matter what this box's acme.sh default keylength is.
  step('Start DNS verification');
  const r = await acme(helpers, [...ACME_OPTS, '--issue', '--server', 'letsencrypt', '--dns', '-d', domain, '--keylength', 'ec-256', '--force', MANUAL_FLAG],
    { quiet: true, timeout: 180_000 });
  if (r.code !== CODE_DNS_MANUAL) {
    err('The certificate authority did not return the DNS records to add.');
    throw new Error('Could not start the DNS verification. See the details above, then try again.');
  }
  const records = parseTxtRecords(`${r.stdout}\n${r.stderr}`);
  const vlist = await readVlist(domain);
  if (!records.length || !vlist) {
    throw new Error('The DNS records to add could not be read back. See the details above, then try again.');
  }
  const state = { domain, started_at: new Date().toISOString(), txt_records: records, vlist };
  await writeChallenge(domain, state);
  ok(`Add the ${records.length} DNS record${records.length === 1 ? '' : 's'} shown in Manage SSL at your DNS provider, then click Verify.`);
  return state;
}

// --- step 2: verify the TXT records ---------------------------------------------
// Exit codes: 0 = issued · 3 = acme.sh (re)entered manual mode (new order) ·
// 1 + "DNS problem" = the CA can't see the record yet (soft — retry) ·
// any other 1 = the order is dead (hard — start over).
const DNS_NOT_VISIBLE = /DNS problem|NXDOMAIN|no DNS|does not match/i;

export async function verifyManualDns(helpers, domain) {
  const { step, warn, err, done } = logger(helpers);
  if (!(await pathExists(ACME))) throw new Error('This server has no certificate tool installed.');
  const state = await readChallenge(domain);
  if (!state) throw new Error('There is no DNS verification in progress for this site. Start one from Manage SSL.');

  // A previous failed verify cleared Le_Vlist — restore it so acme.sh resumes
  // the SAME order (same TXT) instead of starting over.
  if (!(await restoreVlist(domain, state.vlist))) {
    await clearChallenge(domain);
    throw new Error('The pending verification could not be resumed. Start it again from Manage SSL.');
  }

  step('Check your DNS records');
  const r = await acme(helpers, [...ACME_OPTS, '--renew', '-d', domain, '--ecc', '--force', MANUAL_FLAG],
    { quiet: true, timeout: 300_000 });
  const out = `${r.stdout}\n${r.stderr}`;

  if (r.code === CODE_DNS_MANUAL) {
    const records = parseTxtRecords(out);
    const vlist = await readVlist(domain);
    if (records.length && vlist) {
      await writeChallenge(domain, { ...state, started_at: new Date().toISOString(), txt_records: records, vlist });
      warn('The previous request expired, so new DNS records were issued — add the new ones shown in Manage SSL, then verify again.');
      return { pending: true, new_records: true };
    }
    throw new Error('New DNS records were issued but could not be read back. Start the verification again from Manage SSL.');
  }
  if (r.code !== 0) {
    if (DNS_NOT_VISIBLE.test(out)) {
      warn('The certificate authority cannot see your DNS record yet — DNS changes can take a few minutes to spread.');
      // Soft failure: state + the same TXT stay valid, the user retries.
      throw new Error('Your DNS record is not visible yet. Confirm it is published at your DNS provider, wait a few minutes, then click Verify again.');
    }
    err('The certificate authority rejected the verification.');
    await clearChallenge(domain); // retrying the same dead order is pointless
    throw new Error('Certificate verification failed. See the details above, then start the verification again from Manage SSL.');
  }

  step('Install the certificate');
  await installCert(helpers, domain, { renew: false });
  await writeManualMarker(domain); // this cert will NOT auto-renew
  await applySslConf(helpers, domain);
  await syncWpAddress(helpers, await requireSpec(domain));
  await clearChallenge(domain);
  done(`HTTPS enabled for ${domain} via DNS verification`);
  return { pending: false };
}
