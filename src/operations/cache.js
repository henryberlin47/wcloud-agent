import { logger } from '../lib/log.js';
import { requireSpec, applySite } from '../lib/sites.js';
import { clearPageCache, syncCachePlugin, setObjectCache, wpRocketStatus } from '../lib/cache.js';

// ============================================================
//  cache — a WordPress site's page cache mode and Redis object cache
// ============================================================
// mode: 'fastcgi' (nginx caches pages; the wcloud-cache must-use plugin clears
// it on content changes) | 'wprocket' (nginx serves WP Rocket's files — only
// accepted once WP Rocket is installed, active and set up: wpRocketStatus) | 'off'.
// The vhost is re-rendered in the usual tested transaction.
// ============================================================

const LABEL = { fastcgi: 'Server page cache (nginx)', wprocket: 'WP Rocket (served by nginx)', off: 'Off' };

// params: { domain, mode?, objectCache?: boolean }
export async function runCache(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — it has nothing to cache.`);

  if (p.mode && p.mode !== (s.cache || 'off')) {
    if (p.mode === 'wprocket') {
      // nginx would look for cache files nothing writes — refuse instead.
      step('Check WP Rocket');
      const st = await wpRocketStatus(helpers, s);
      if (!st.ready) throw new Error(st.error || st.problem);
      ok(`WP Rocket${st.version ? ` ${st.version}` : ''} is active and its page cache is set up`);
    }
    step(`Page cache: ${LABEL[p.mode]}`);
    const next = { ...s, cache: p.mode };
    await applySite(helpers, next);
    ok('Web server updated');
    await syncCachePlugin(helpers, next); // page cache and/or Cloudflare purges
    if (p.mode === 'fastcgi') ok('Pages are cleared from the cache automatically when content changes');
    else await clearPageCache(s.domain);
  }

  if (typeof p.objectCache === 'boolean') {
    step(`${p.objectCache ? 'Turn on' : 'Turn off'} the object cache (Redis)`);
    await setObjectCache(helpers, s, p.objectCache);
  }
  done(`Caching updated for ${p.domain}`);
}
