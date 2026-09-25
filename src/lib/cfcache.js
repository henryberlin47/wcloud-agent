import fs from 'node:fs/promises';
import config from '../config.js';
import { removePath } from './sys.js';
import { cfCachePath } from './sites.js';

// ============================================================
//  cfcache.js — purging a site's Cloudflare cache
// ============================================================
// The portal manages the zone's Cache Rules (it holds the workspace's
// Cloudflare tokens); purging happens here, because it must also happen when
// WordPress asks for it (content changed, or "Purge Cloudflare cache" in the
// wp-admin toolbar) — and WordPress must never hold the token. The token +
// zone + hosts live in /etc/wcloud/cf-cache/<d>.json (root, 0600); the site's
// helper plugin only drops a marker file (lib/cache.js watcher).
// ============================================================

export async function saveCfCache(domain, { token, zoneId, hosts }) {
  await fs.mkdir('/etc/wcloud/cf-cache', { recursive: true, mode: 0o700 });
  await fs.writeFile(cfCachePath(domain), JSON.stringify({ token, zoneId, hosts }), { mode: 0o600 });
  await fs.chmod(cfCachePath(domain), 0o600);
}
export const forgetCfCache = (domain) => removePath(cfCachePath(domain));

const lastPurge = new Map(); // domain → ms: WordPress can fire bursts of changes

/** Purge the site's hostnames from Cloudflare. → { ok, error? }. Never throws. */
export async function purgeCloudflare(domain, { force = false } = {}) {
  let c;
  try { c = JSON.parse(await fs.readFile(cfCachePath(domain), 'utf8')); } catch { return { ok: false, error: 'Cloudflare cache is not set up for this site.' }; }
  if (!force && Date.now() - (lastPurge.get(domain) || 0) < 10_000) return { ok: true, skipped: true };
  lastPurge.set(domain, Date.now());
  try {
    const r = await fetch(`${config.cloudflareApi}/zones/${c.zoneId}/purge_cache`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${c.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ hosts: c.hosts }),
      signal: AbortSignal.timeout(20_000),
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.success !== false) return { ok: true };
    const msg = j.errors?.[0]?.message || `HTTP ${r.status}`;
    return { ok: false, error: r.status === 401 || r.status === 403 ? `Cloudflare refused the purge (${msg}) — the token needs Zone → Cache Purge: Purge.` : `Cloudflare: ${msg}` };
  } catch (e) {
    return { ok: false, error: `Cloudflare couldn't be reached (${e.cause?.code || e.message}).` };
  }
}
