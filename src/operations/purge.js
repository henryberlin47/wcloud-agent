import { resolveWpRoot, clearWpCaches } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// Purge a site's caches on demand: WP Rocket page cache + object cache.
export async function runPurge(job, helpers, p, opts = {}) {
  const { step, ok, warn } = logger(helpers, opts);
  const domain = p.domain;
  const wpRoot = await resolveWpRoot(domain);

  step(`Purge caches for ${domain}`);
  const r = await clearWpCaches(helpers, wpRoot);
  // Both failing means wp-cli itself is broken — worth failing the job over.
  // Rocket alone failing is normal (plugin inactive) and already disk-cleaned.
  if (!r.rocketOk && !r.objectFlushed) {
    throw new Error(`cache purge failed for ${domain} — wp-cli returned an error for both rocket and object cache`);
  }
  r.rocketOk ? ok('WP Rocket page cache cleared') : warn('WP Rocket not active (disk cache wiped)');
  r.objectFlushed ? ok('object cache flushed') : warn('object cache not flushed');
}
