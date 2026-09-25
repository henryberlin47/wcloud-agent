import { logger } from '../lib/log.js';
import { requireSpec, clearPageCache } from '../lib/sites.js';
import { wpCli } from '../lib/wp.js';

// ============================================================
//  indexing — let search engines index a WordPress site, or not
// ============================================================
// WordPress's own "Discourage search engines" setting (option blog_public):
// off → a noindex robots meta tag on every page + Disallow in its robots.txt.
// Same setting as Settings → Reading in wp-admin, so the two never disagree.
// The page cache is cleared, since cached pages carry the old tag.
// ============================================================

// params: { domain, enabled: boolean }
export async function runIndexing(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — use a robots.txt file instead.`);
  step(p.enabled ? 'Let search engines index the site' : 'Ask search engines not to index the site');
  const r = await (await wpCli(helpers, s))(['option', 'update', 'blog_public', p.enabled ? '1' : '0'], { timeout: 60_000 });
  if (r.code !== 0) throw new Error('WordPress on this site didn\'t respond — is it installed and working?');
  await clearPageCache(s.domain);
  ok('Setting saved and page cache cleared');
  done(p.enabled ? `${p.domain} is visible to search engines` : `${p.domain} now asks search engines not to index it`);
}
