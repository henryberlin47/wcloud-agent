import { logger } from '../lib/log.js';
import { requireSpec, applySite } from '../lib/sites.js';
import { ensurePhp } from '../lib/stack.js';

// ============================================================
//  php — move a site to another PHP version
// ============================================================
// Installs the version if the server doesn't have it yet, then moves the
// site's pool from the old version's php-fpm to the new one in one tested
// transaction (the socket path doesn't change, so nginx isn't touched).
// A few seconds of 502s while the new pool starts is the whole downtime.
// ============================================================

// params: { domain, php }
export async function runPhp(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — it doesn't run PHP.`);
  if (s.php === p.php) { done(`${p.domain} already runs PHP ${p.php}`); return; }

  step(`Make PHP ${p.php} available`);
  await ensurePhp(helpers, p.php);
  ok(`PHP ${p.php} is ready`);

  step(`Move the site from PHP ${s.php} to PHP ${p.php}`);
  await applySite(helpers, { ...s, php: p.php }, { prevPhp: s.php });
  ok('PHP pool moved and reloaded');
  done(`${p.domain} now runs PHP ${p.php}`);
}
