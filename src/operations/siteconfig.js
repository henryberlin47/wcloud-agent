import { logger } from '../lib/log.js';
import { requireSpec, applySite } from '../lib/sites.js';
import { saveRule, deleteRule } from '../lib/nginxrules.js';

// ============================================================
//  siteconfig / nginxrule — per-site nginx settings
// ============================================================

// params: { domain, realIp?, redirects? } — rendered into the vhost (tested
// transaction; the page cache is cleared by applySite).
export async function runSiteconfig(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  const next = { ...s };
  if (p.realIp != null) {
    step(p.realIp ? 'Show real visitor IPs behind Cloudflare' : 'Stop using Cloudflare\'s visitor IP header');
    next.realIp = p.realIp;
  }
  if (p.redirects != null) {
    step(`Save ${p.redirects.length} redirect${p.redirects.length === 1 ? '' : 's'}`);
    next.redirects = p.redirects;
  }
  await applySite(helpers, next);
  ok('Web server updated');
  done(`Settings saved for ${p.domain}`);
}

// params: { domain, action: save|delete, id?, name?, content?, enabled? }
export async function runNginxrule(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  await requireSpec(p.domain);
  if (p.action === 'delete') {
    step(`Delete the custom rule "${p.id}"`);
    await deleteRule(helpers, p.domain, p.id);
    done('Rule deleted');
    return;
  }
  step(`Save the custom rule "${p.name}"${p.enabled ? '' : ' (turned off)'}`);
  const id = await saveRule(helpers, p.domain, p);
  job.result = { id };
  ok('nginx accepted it and was reloaded');
  done(`Rule "${p.name}" saved`);
}
