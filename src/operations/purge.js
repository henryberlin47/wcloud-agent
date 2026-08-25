import { resolveWpRoot, clearWpCaches } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// Purge a site's caches on demand: WP Rocket page cache + object cache.
export async function runPurge(job, helpers, p, opts = {}) {
  const { step, ok, warn } = logger(helpers, opts);
  const domain = p.domain;
  const wpRoot = await resolveWpRoot(domain);

  step('Clear the site caches');
  const r = await clearWpCaches(helpers, wpRoot);
  // Both failing means wp-cli itself is broken — worth failing the job over.
  // Rocket alone failing is normal (plugin inactive) and already disk-cleaned.
  if (!r.rocketOk && !r.objectFlushed) {
    throw new Error(`Could not clear the caches for ${domain}. WordPress may not be responding on this site.`);
  }
  r.rocketOk ? ok('Page cache cleared') : warn('WP Rocket is not active — cleared the cached files on disk instead');
  r.objectFlushed ? ok('Object cache flushed') : warn('Object cache could not be flushed — it may not be enabled on this site');
}
