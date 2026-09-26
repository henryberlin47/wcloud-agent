import { logger } from '../lib/log.js';
import { requireSpec, applySite } from '../lib/sites.js';
import { saveRule, deleteRule } from '../lib/nginxrules.js';

// ============================================================
//  siteconfig / nginxrule — per-site nginx settings
// ============================================================

// params: { domain, realIp?, redirects?, domainRedirect?, phpSettings?, fpm? } — rendered into the vhost / PHP pool (tested
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
  if (p.domainRedirect !== undefined) {
    if (p.domainRedirect) {
      step(`Redirect all of ${p.domain} to ${p.domainRedirect.to}${p.domainRedirect.keepPath ? ' (keeping the path)' : ''} — ${p.domainRedirect.code}`);
      next.domainRedirect = p.domainRedirect;
    } else {
      step(`Stop redirecting ${p.domain} — serve the site again`);
      delete next.domainRedirect;
    }
  }
  if (p.phpSettings || p.fpm) {
    if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — it doesn't run PHP.`);
    if (p.phpSettings) { step('Save the PHP settings'); next.phpSettings = p.phpSettings; }
    if (p.fpm) { step('Save the PHP-FPM process settings'); next.fpm = p.fpm; }
  }
  await applySite(helpers, next);
  ok(p.phpSettings || p.fpm ? 'PHP-FPM and nginx accepted it and were reloaded' : 'Web server updated');
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
