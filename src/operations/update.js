import { systemctl } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { requireSpec } from '../lib/sites.js';
import { wpCli } from '../lib/wp.js';
import { fpmService } from '../lib/stack.js';

// ============================================================
//  update — update WordPress core on an existing site
// ============================================================
// Three steps:
//   1) wp core update                    (upgrade WP files)
//   2) wp core update-db                (run DB migrations if needed)
//   3) reload the site's PHP-FPM        (clears OPcache)
// ============================================================

export async function runUpdate(job, helpers, p) {
  const { step, ok, warn, err, done } = logger(helpers);
  const domain = p.domain;

  const s = await requireSpec(domain);
  if (s.type !== 'wordpress') throw new Error(`${domain} is a static site — there's no WordPress to update.`);

  // Verify WordPress installation exists before attempting update
  step('Check the WordPress installation');
  const wp = await wpCli(helpers, s);
  const versionCheck = await wp(['core', 'version']);
  if (versionCheck.code !== 0) {
    err('WordPress is not installed correctly on this site');
    throw new Error(`WordPress installation invalid for ${domain}`);
  }
  ok('WordPress installation looks healthy');

  // 1) Update WordPress core files.
  step('Update WordPress');
  const coreResult = await wp(['core', 'update', '--minor']);
  if (coreResult.code !== 0) {
    err(`wp core update failed (code ${coreResult.code})`);
    throw new Error(`WordPress core update failed for ${domain}`);
  } else {
    ok('WordPress updated to the latest version');
  }

  // 2) Update database schema if needed.
  step('Update the database');
  const dbResult = await wp(['core', 'update-db']);
  if (dbResult.code !== 0) {
    warn(`wp core update-db failed (code ${dbResult.code}) — may already be current`);
  } else {
    ok('Database schema updated');
  }

  // 3) Fresh code must not be served from OPcache. Reload is graceful.
  step('Reload PHP so the new code is used');
  await systemctl(helpers, 'reload', fpmService(s.php));
  ok(`PHP ${s.php} reloaded`);

  done(`WordPress is up to date — ${domain}`);
}
