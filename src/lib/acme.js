import fs from 'node:fs/promises';
import { Resolver } from 'node:dns/promises';
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
// The CA checks an order once and a failed check is final: verify looks the
// TXT records up itself first, and only asks the CA once they are visible.

const ACME = '/etc/letsencrypt/acme.sh';
const ACME_OPTS = ['--config-home', '/etc/letsencrypt/config'];
// acme.sh one call at a time (shared account.conf) — sys.withLock.
const acme = (helpers, args, opts) => withLock('acme', () => run(helpers, ACME, args, opts));
// Take a domain off acme.sh's renewal list: its cron would otherwise renew over
// whatever certificate is installed. A later --issue puts it back.
export async function forgetAcmeDomain(helpers, domain) {
  if (!(await pathExists(ACME))) return;
  await acme(helpers, [...ACME_OPTS, '--remove', '-d', domain, '--ecc'], { quiet: true, timeout: 60_000 });
}
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
    // acme.sh rewrites the domain's entry (to dns_cf) before it validates. Keep
    // a copy: an attempt that ends without a certificate must leave the entry
    // as it was, or the certificate in place would stop renewing.
    const before = await readEccConf(domain);
    let res;
    try {
      res = await run(helpers, ACME, [...ACME_OPTS, '--issue', '--server', 'letsencrypt', '--dns', 'dns_cf',
        '-d', domain, ...(www ? ['-d', `www.${domain}`] : []), '--keylength', 'ec-256', '--force'],
      { env: { CF_Token: token, CF_Zone_ID: zoneId }, quiet: true, timeout: 600_000 });
      return res;
    } finally {
      // Files only, so this also runs after a cancel (run rejects) or a timeout.
      if (res?.code !== 0) {
        if (before != null) await fs.writeFile(eccConfPath(domain), before, { mode: 0o600 });
        else await removePath(eccConfPath(domain)); // no entry before: leave none
      }
      await forgetAcmeCfToken(domain);
    }
  });
  if (r.code !== 0) {
    for (const l of `${r.stdout}\n${r.stderr}`.trim().split('\n').slice(-6)) err(`    ${stripAnsi(l)}`);
    return { ok: false, timedOut: !!r.timedOut };
  }
  await installCert(helpers, domain, { renew: false });
  await forgetAcmeDomain(helpers, domain);
  await fs.mkdir('/etc/wcloud/cf-dns', { recursive: true, mode: 0o700 });
  await fs.writeFile(cfDnsTokenPath(domain), JSON.stringify({ token, zoneId, www }), { mode: 0o600 });
  await removeManualMarker(domain);
  await clearChallenge(domain); // a pending manual DNS verification is no longer wanted
  await applySslConf(helpers, domain, { sslDns: 'cloudflare' });
  return { ok: true };
}

// acme.sh saves the dns_cf credentials it was given: as SAVED_CF_* in
// account.conf, or as plain CF_* in the domain's entry when a zone id is
// passed (--remove keeps that file as .conf.removed).
async function forgetAcmeCfToken(domain) {
  for (const conf of ['/etc/letsencrypt/config/account.conf', eccConfPath(domain), `${eccConfPath(domain)}.removed`]) {
    const c = await fs.readFile(conf, 'utf8').catch(() => null);
    if (c && /^(SAVED_)?CF_/m.test(c)) await fs.writeFile(conf, c.split('\n').filter((l) => !/^(SAVED_)?CF_/.test(l)).join('\n'), { mode: 0o600 });
  }
}

// Renew Cloudflare-DNS certificates with 30 days or less left. `enqueue`
// (jobs.js) runs them like any other operation (one job per site at a time).
export function startDnsRenewer(enqueue, { listSites, readCertInfo, fullchainPath }) {
  const tick = async () => {
    for (const s of await listSites()) {
      // HTTPS turned off keeps sslDns + the token: renewing would switch it back on.
      if (s.sslDns !== 'cloudflare' || !s.ssl) continue;
      const info = await readCertInfo({ log() {}, err() {} }, fullchainPath(s.domain));
      if (info && info.days_left != null && info.days_left > 30) continue;
      enqueue('ssl-renew', { domain: s.domain }, async (job, helpers) => {
        const { step, ok } = logger(helpers);
        step(`Renew the Let's Encrypt certificate for ${s.domain} (Cloudflare DNS)`);
        // The job may have waited behind another one on this site: look again.
        const cur = await requireSpec(s.domain);
        if (!cur.ssl || cur.sslDns !== 'cloudflare') { ok('HTTPS is off or no longer uses Cloudflare DNS for this site — renewal skipped'); return; }
        let t;
        try { t = JSON.parse(await fs.readFile(cfDnsTokenPath(s.domain), 'utf8')); } catch { throw new Error('The Cloudflare token for this site is missing — issue the certificate again from the site page.'); }
        const r = await issueDnsCloudflare(helpers, s.domain, { www: t.www, token: t.token, zoneId: t.zoneId });
        if (!r.ok) throw new Error('Renewal failed — check that the Cloudflare token still works.');
        ok('Certificate renewed');
      });
    }
    // A manual DNS verification nobody finished: the CA drops the request after
    // 7 days, and the certificate in place must renew again (abortChallenge).
    for (const f of await fs.readdir(STATE_DIR).catch(() => [])) {
      const domain = f.replace(/\.json$/, '');
      const st = await readChallenge(domain);
      if (!st?.prevConf || !(Date.now() - Date.parse(st.started_at) > 7 * 86_400_000)) continue;
      enqueue('ssl-challenge-expire', { domain }, async (job, helpers) => {
        // The job may have waited behind a verify on this site: look again.
        const cur = await readChallenge(domain);
        if (!cur?.prevConf || cur.started_at !== st.started_at) return;
        await abortChallenge(domain, cur.prevConf);
        logger(helpers).ok(`The DNS verification for ${domain} was never finished and has expired — the certificate in place renews on its own again`);
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
  await clearChallenge(domain); // a pending manual DNS verification is no longer wanted
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
  // Root-only: the state carries a copy of the acme.sh entry (prevConf).
  await fs.writeFile(statePath(domain), JSON.stringify(state, null, 2), { mode: 0o600 });
}

export async function clearChallenge(domain) {
  await fs.rm(statePath(domain), { force: true });
}

// The acme.sh entry step 1 writes to (it pins ec-256) — the same one an
// HTTP-01 certificate renews from, so step 1 stops that renewal.
const MANUAL_ENTRY = /^Le_Webroot='dns'$/m;
const eccConfPath = (domain) => `/etc/letsencrypt/renewal/${domain}_ecc/${domain}.conf`;
const readEccConf = (domain) => fs.readFile(eccConfPath(domain), 'utf8').catch(() => null);

// The challenge ended without a certificate: put back the entry step 1
// overwrote, so the certificate in place renews again, then drop the state.
// Only while the entry is still step 1's — a certificate issued since owns it.
async function abortChallenge(domain, prevConf) {
  if (prevConf && MANUAL_ENTRY.test((await readEccConf(domain)) || '')) {
    await fs.writeFile(eccConfPath(domain), prevConf, { mode: 0o600 });
  }
  await clearChallenge(domain);
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
export async function findDomainConf(domain) {
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
// www.<domain> is included when the site serves it (one TXT record per name):
// HTTPS is switched on for both names, so the certificate must cover both.
export async function startManualDns(helpers, domain, { www = false } = {}) {
  const { step, ok, err } = logger(helpers);
  if (!(await pathExists(ACME))) {
    throw new Error('This server has no certificate tool installed. Re-run the server install command.');
  }
  // Keep a copy of the acme.sh entry step 1 is about to overwrite, to put back
  // if this ends without a certificate. Already a manual-DNS entry (a pending
  // flow started again) → keep the copy that flow took.
  const old = await readChallenge(domain);
  const cur = await readEccConf(domain);
  const prevConf = !cur ? null : MANUAL_ENTRY.test(cur) ? (old?.prevConf ?? null) : cur;
  await clearChallenge(domain); // a fresh start supersedes any stale pending challenge

  // Pin the key type: verify/install below always pass --ecc, so the order must
  // live in <D>_ecc no matter what this box's acme.sh default keylength is.
  step('Start DNS verification');
  const r = await acme(helpers, [...ACME_OPTS, '--issue', '--server', 'letsencrypt', '--dns', '-d', domain, ...(www ? ['-d', `www.${domain}`] : []), '--keylength', 'ec-256', '--force', MANUAL_FLAG],
    { quiet: true, timeout: 180_000 }).catch(async (e) => { await abortChallenge(domain, prevConf); throw e; });
  if (r.code !== CODE_DNS_MANUAL) {
    err('The certificate authority did not return the DNS records to add.');
    await abortChallenge(domain, prevConf);
    throw new Error('Could not start the DNS verification. See the details above, then try again.');
  }
  const records = parseTxtRecords(`${r.stdout}\n${r.stderr}`);
  const vlist = await readVlist(domain);
  if (!records.length || !vlist) {
    await abortChallenge(domain, prevConf);
    throw new Error('The DNS records to add could not be read back. See the details above, then try again.');
  }
  const state = { domain, started_at: new Date().toISOString(), txt_records: records, vlist, prevConf };
  await writeChallenge(domain, state);
  ok(`Add the ${records.length} DNS record${records.length === 1 ? '' : 's'} shown in Manage SSL at your DNS provider, then click Verify.`);
  return state;
}

// --- step 2: verify the TXT records ---------------------------------------------
// A record our own lookup cannot see yet is a soft failure: the CA was not
// asked, so the same TXT stays valid and the user retries.
// Exit codes: 0 = issued · 3 = acme.sh (re)entered manual mode (new order) ·
// anything else = the CA refused, the order is dead (hard — start over).

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
  // ponytail: public resolvers, which may keep a "no such record" answer for a
  // few minutes after the record is added; ask the zone's own name servers if
  // that wait is a problem. A resolver we cannot reach decides nothing.
  const resolver = new Resolver({ timeout: 5000, tries: 2 });
  resolver.setServers(['1.1.1.1', '8.8.8.8']);
  for (const rec of state.txt_records) {
    const seen = await resolver.resolveTxt(rec.domain).then(
      (rows) => rows.map((chunks) => chunks.join('')),
      (e) => (['ENOTFOUND', 'ENODATA'].includes(e.code) ? [] : null));
    if (seen && !seen.includes(rec.value)) {
      warn(`${rec.domain} is not visible yet — DNS changes can take a few minutes to spread.`);
      throw new Error('Your DNS record is not visible yet. Confirm it is published at your DNS provider, wait a few minutes, then click Verify again.');
    }
  }
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
    err('The certificate authority rejected the verification.');
    await abortChallenge(domain, state.prevConf); // retrying the same dead order is pointless
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
