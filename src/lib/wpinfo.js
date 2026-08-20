import config from '../config.js';
import { pathExists, wpCli, resolveWpRoot } from './sys.js';

// ============================================================
//  wpinfo.js — WordPress info, read live (nothing stored)
// ============================================================

// WordPress core version for a site (wp-cli `core version`), or null when the
// site is not a readable WordPress install.
export async function readWpVersion(helpers, domain) {
  const base = `${config.wwwDir}/${domain}`;
  if (!(await pathExists(`${base}/htdocs/wp-load.php`)) && !(await pathExists(`${base}/wp-load.php`))) return null;
  const r = await wpCli(helpers, await resolveWpRoot(domain))(['core', 'version'], { timeout: 30_000 });
  if (r.code !== 0) return null;
  const v = (r.stdout || '').trim().split(/\s+/).filter(Boolean).pop() || '';
  return /^\d+\.\d+(\.\d+)?$/.test(v) ? v : null;
}
