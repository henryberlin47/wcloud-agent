import { logger } from '../lib/log.js';
import { requireSpec } from '../lib/sites.js';
import { clearWpCaches } from '../lib/wp.js';

// Purge a site's caches on demand: WP Rocket page cache + object cache.
export async function runPurge(job, helpers, p, opts = {}) {
  const { step, ok, warn } = logger(helpers, opts);
  const domain = p.domain;
  const s = await requireSpec(domain);
  if (s.type !== 'wordpress') throw new Error(`${domain} is a static site — there's no cache to clear.`);

  step('Clear the site caches');
  const r = await clearWpCaches(helpers, s);
  // Both failing means wp-cli itself is broken — worth failing the job over.
  // Rocket alone failing is normal (plugin inactive) and already disk-cleaned.
  if (!r.rocketOk && !r.objectFlushed) {
    throw new Error(`Could not clear the caches for ${domain}. WordPress may not be responding on this site.`);
  }
  r.rocketOk ? ok('Page cache cleared') : warn('WP Rocket is not active — cleared the cached files on disk instead');
  r.objectFlushed ? ok('Object cache flushed') : warn('Object cache could not be flushed — it may not be enabled on this site');
}
