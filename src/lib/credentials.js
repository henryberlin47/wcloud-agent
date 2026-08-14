// ============================================================
//  credentials.js — read a site's DB credentials on demand
// ============================================================
// wp-config.php is the durable source of truth (always present, always current
// even if creds rotate), so nothing is cached — this reads live whenever the
// portal asks. Works for any site, not just ones deployed through the portal,
// and survives agent restarts. The WP admin password is NOT here: WordPress only
// keeps a bcrypt hash, so it can't be read back (use the reset-password op).
// ============================================================

import { resolveWpRoot, wpCli, pathExists } from './sys.js';

export async function readDbCredentials(helpers, domain) {
  // Defense-in-depth: the route is already token-gated, but this value lands in a
  // filesystem path, so reject anything that isn't a plain hostname.
  if (!/^[a-z0-9.-]+$/i.test(domain) || domain.includes('..')) return null;

  const wpRoot = await resolveWpRoot(domain);
  if (!(await pathExists(`${wpRoot}/wp-load.php`))) return null; // not a WP site → 404

  const wp = wpCli(helpers, wpRoot);
  const [name, user, pass] = await Promise.all(
    ['DB_NAME', 'DB_USER', 'DB_PASSWORD'].map((k) => wp(['config', 'get', k]))
  );
  if (name.code !== 0) return null;
  return {
    db_name: name.stdout.trim(),
    db_user: user.code === 0 ? user.stdout.trim() : '',
    db_password: pass.code === 0 ? pass.stdout.trim() : '',
  };
}
