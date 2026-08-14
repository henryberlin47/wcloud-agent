import { wpCli, resolveWpRoot, systemctl, nginxTest, nginxReload, getPhpVersion } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// ============================================================
//  update — update WordPress core on an existing site
// ============================================================
// Three steps:
//   1) wp core update                    (upgrade WP files)
//   2) wp core update-db                (run DB migrations if needed)
//   3) restart php-fpm + reload nginx   (clear OPcache, apply new config)
// ============================================================

export async function runUpdate(job, helpers, p) {
  const { log, step, ok, warn, err } = logger(helpers);
  const domain = p.domain;

  const wpRoot = await resolveWpRoot(domain);

  // Verify WordPress installation exists before attempting update
  step('Verify WordPress installation');
  const wp = wpCli(helpers, wpRoot);
  const versionCheck = await wp(['core', 'version']);
  if (versionCheck.code !== 0) {
    err(`WordPress not found or not properly installed at ${wpRoot}`);
    throw new Error(`WordPress installation invalid for ${domain}`);
  }
  ok('WordPress installation verified');

  // 1) Update WordPress core files.
  step('Update WordPress core');
  const coreResult = await wp(['core', 'update', '--minor']);
  if (coreResult.code !== 0) {
    err(`wp core update failed (code ${coreResult.code})`);
    throw new Error(`WordPress core update failed for ${domain}`);
  } else {
    ok('WordPress core updated');
  }

  // 2) Update database schema if needed.
  step('Update database');
  const dbResult = await wp(['core', 'update-db']);
  if (dbResult.code !== 0) {
    warn(`wp core update-db failed (code ${dbResult.code}) — may already be current`);
  } else {
    ok('Database updated');
  }

  // 3) Restart php-fpm + reload nginx.
  step('Restart php-fpm, reload nginx');
  const php = getPhpVersion();
  await systemctl(helpers, 'restart', php.service);
  if (await nginxTest(helpers)) {
    await nginxReload(helpers);
    ok('nginx reloaded');
  } else {
    err('nginx -t failed — not reloading');
    throw new Error(`nginx validation failed for ${domain}`);
  }

  log(`Update completed for ${domain}`);
}
