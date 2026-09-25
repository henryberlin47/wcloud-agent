import { logger } from '../lib/log.js';
import { requireSpec, applySite } from '../lib/sites.js';
import { syncCachePlugin } from '../lib/cache.js';
import { saveCfCache, forgetCfCache, purgeCloudflare } from '../lib/cfcache.js';

// ============================================================
//  cfcache — Cloudflare cache for a site (purge side; lib/cfcache.js)
// ============================================================
// params: { domain, enabled, cfToken?, cfZoneId?, hosts? }. The portal has
// already written the zone's Cache Rules; here the purge credentials are kept
// (root-only), the spec flag set, and — for WordPress — the helper plugin
// rewritten so content changes and the toolbar purge Cloudflare too.
// ============================================================
export async function runCfCache(job, helpers, p) {
  const { step, ok, warn, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (p.enabled) {
    step('Keep the Cloudflare purge credentials on this server (root-only)');
    await saveCfCache(p.domain, { token: p.cfToken, zoneId: p.cfZoneId, hosts: p.hosts });
    const next = { ...s, cfCache: true };
    await applySite(helpers, next);
    if (s.type === 'wordpress') {
      step('Purge Cloudflare when content changes, and from the wp-admin toolbar');
      await syncCachePlugin(helpers, next);
      ok('Helper plugin updated');
    }
    const r = await purgeCloudflare(p.domain, { force: true });
    r.ok ? ok(`Cloudflare cache purged for ${p.hosts.join(', ')}`) : warn(r.error);
    return done('Cloudflare cache is on');
  }
  step('Stop purging Cloudflare from this server');
  await forgetCfCache(p.domain);
  const next = { ...s, cfCache: false };
  await applySite(helpers, next);
  if (s.type === 'wordpress') await syncCachePlugin(helpers, next);
  done('Cloudflare cache is off');
}
