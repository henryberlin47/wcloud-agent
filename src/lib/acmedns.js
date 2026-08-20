import fs from 'node:fs/promises';
import { run, pathExists } from './sys.js';
import { logger } from './log.js';
import { certDir, applySslConf, writeManualMarker } from './certinstall.js';

// ============================================================
//  acmedns.js — Let's Encrypt via manual DNS-01 (two-step)
// ============================================================
// WordOps ships acme.sh at /etc/letsencrypt (config home
// /etc/letsencrypt/config, cert home /etc/letsencrypt/renewal, default key
// ec-256 → the domain conf lives in <D>_ecc/). The manual flow:
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
const MANUAL_FLAG = '--yes-I-know-dns-manual-mode-enough-go-ahead-please';
const CODE_DNS_MANUAL = 3;
const STATE_DIR = '/var/lib/wcloud/ssl-challenge';

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
    throw new Error(`${ACME} not found — this server has no WordOps acme.sh (deploy a site with SSL first)`);
  }
  await clearChallenge(domain); // a fresh start supersedes any stale pending challenge

  step('Request a new ACME order (manual DNS-01)');
  const r = await run(helpers, ACME, [...ACME_OPTS, '--issue', '--dns', '-d', domain, '--force', MANUAL_FLAG],
    { quiet: true, timeout: 180_000 });
  if (r.code !== CODE_DNS_MANUAL) {
    err(`acme.sh exited ${r.code} (expected ${CODE_DNS_MANUAL} — "add the TXT records")`);
    throw new Error(`could not start the DNS-01 challenge (acme.sh exit ${r.code}) — see the log above`);
  }
  const records = parseTxtRecords(`${r.stdout}\n${r.stderr}`);
  const vlist = await readVlist(domain);
  if (!records.length || !vlist) {
    throw new Error('acme.sh entered manual mode but the TXT records / order could not be parsed — see the log above');
  }
  const state = { domain, started_at: new Date().toISOString(), txt_records: records, vlist };
  await writeChallenge(domain, state);
  ok(`challenge started — add ${records.length} TXT record${records.length === 1 ? '' : 's'} at your DNS provider`);
  return state;
}

// --- step 2: verify the TXT records ---------------------------------------------
// Exit codes: 0 = issued · 3 = acme.sh (re)entered manual mode (new order) ·
// 1 + "DNS problem" = the CA can't see the record yet (soft — retry) ·
// any other 1 = the order is dead (hard — start over).
const DNS_NOT_VISIBLE = /DNS problem|NXDOMAIN|no DNS|does not match/i;

export async function verifyManualDns(helpers, domain) {
  const { step, ok, warn, err } = logger(helpers);
  if (!(await pathExists(ACME))) throw new Error(`${ACME} not found`);
  const state = await readChallenge(domain);
  if (!state) throw new Error('no pending DNS-01 challenge for this site — start one from Manage SSL');

  // A previous failed verify cleared Le_Vlist — restore it so acme.sh resumes
  // the SAME order (same TXT) instead of starting over.
  if (!(await restoreVlist(domain, state.vlist))) {
    await clearChallenge(domain);
    throw new Error('the saved ACME order could not be restored — start the challenge again from Manage SSL');
  }

  step('Verify the TXT records against the CA');
  const r = await run(helpers, ACME, [...ACME_OPTS, '--renew', '-d', domain, '--ecc', '--force', MANUAL_FLAG],
    { quiet: true, timeout: 300_000 });
  const out = `${r.stdout}\n${r.stderr}`;

  if (r.code === CODE_DNS_MANUAL) {
    const records = parseTxtRecords(out);
    const vlist = await readVlist(domain);
    if (records.length && vlist) {
      await writeChallenge(domain, { ...state, started_at: new Date().toISOString(), txt_records: records, vlist });
      warn('the saved order had expired — new TXT records were issued (see Manage SSL)');
      return { pending: true, new_records: true };
    }
    throw new Error('acme.sh re-entered manual mode but could not be parsed — start the challenge again');
  }
  if (r.code !== 0) {
    if (DNS_NOT_VISIBLE.test(out)) {
      warn('the CA cannot see the TXT record yet — it may still be propagating');
      // Soft failure: state + the same TXT stay valid, the user retries.
      throw new Error('DNS record not found by the CA yet — make sure the TXT record is published, then Verify again');
    }
    err(`acme.sh exited ${r.code}`);
    await clearChallenge(domain); // retrying the same dead order is pointless
    throw new Error(`certificate verification failed (acme.sh exit ${r.code}) — see the log above, then start the challenge again`);
  }

  step('Install the certificate + wire nginx');
  const dir = certDir(domain);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const inst = await run(helpers, ACME, [
    ...ACME_OPTS, '--install-cert', '-d', domain, '--ecc',
    '--cert-file', `${dir}/cert.pem`,
    '--key-file', `${dir}/key.pem`,
    '--fullchain-file', `${dir}/fullchain.pem`,
    '--ca-file', `${dir}/ca.pem`,
  ], { quiet: true, timeout: 60_000 });
  if (inst.code !== 0) {
    throw new Error(`certificate issued but install-cert failed (exit ${inst.code}) — see the log above`);
  }
  await run(helpers, 'chmod', ['600', `${dir}/cert.pem`, `${dir}/key.pem`, `${dir}/fullchain.pem`, `${dir}/ca.pem`]);
  await run(helpers, 'chown', ['-R', 'root:root', dir]);
  await writeManualMarker(domain); // this cert will NOT auto-renew
  await applySslConf(helpers, domain);
  await clearChallenge(domain);
  ok(`certificate issued via manual DNS-01 for ${domain}`);
  return { pending: false };
}
