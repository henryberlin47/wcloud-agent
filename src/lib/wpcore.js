import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

// ============================================================
//  wpcore.js — one verified copy of WordPress per server, shared by deploys
// ============================================================
// wp-cli caches downloads per user, and every site is its own user, so each
// deploy used to fetch WordPress again. Instead root keeps the latest release
// here (root-owned, world-readable — never writable by a site, so no site can
// tamper with what the next one gets), checked against wordpress.org's SHA-1,
// and a new site's user just unpacks it. Only a tiny version check goes out
// per deploy; the archive is downloaded once per WordPress release.
// Anything failing here → the caller falls back to `wp core download`.
// ============================================================

export const WP_CORE_DIR = '/var/cache/wcloud-wp';
const KEEP = 2; // newest releases kept
const VERSION_API = 'https://api.wordpress.org/core/version-check/1.7/';
const tarball = (v) => `${WP_CORE_DIR}/wordpress-${v}.tar.gz`;
const VERSION = /^\d+\.\d+(\.\d+)?$/;
const byVersion = (a, b) => { // newest first
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((y[i] || 0) !== (x[i] || 0)) return (y[i] || 0) - (x[i] || 0);
  return 0;
};

async function cachedVersions() {
  let names = [];
  try { names = await fs.readdir(WP_CORE_DIR); } catch { return []; }
  return names.map((n) => n.match(/^wordpress-(.+)\.tar\.gz$/)?.[1]).filter((v) => v && VERSION.test(v)).sort(byVersion);
}

async function latestVersion() {
  const r = await fetch(VERSION_API, { signal: AbortSignal.timeout(10_000) });
  if (!r.ok) throw new Error(`version check answered ${r.status}`);
  const v = String((await r.json())?.offers?.[0]?.current || '');
  if (!VERSION.test(v)) throw new Error('version check gave no version');
  return v;
}

async function download(v) {
  const url = `https://wordpress.org/wordpress-${v}.tar.gz`;
  const sumRes = await fetch(`${url}.sha1`, { signal: AbortSignal.timeout(15_000) });
  const want = sumRes.ok ? (await sumRes.text()).trim().slice(0, 40) : '';
  if (!/^[0-9a-f]{40}$/.test(want)) throw new Error('no checksum published for this release');
  const r = await fetch(url, { signal: AbortSignal.timeout(300_000) });
  if (!r.ok || !r.body) throw new Error(`download answered ${r.status}`);
  const part = `${tarball(v)}.${process.pid}.part`;
  const hash = createHash('sha1');
  try {
    await pipeline(Readable.fromWeb(r.body), new Transform({ transform(c, _e, cb) { hash.update(c); cb(null, c); } }), createWriteStream(part, { mode: 0o644 }));
    if (hash.digest('hex') !== want) throw new Error('checksum mismatch');
    await fs.rename(part, tarball(v));
  } finally {
    await fs.rm(part, { force: true });
  }
  for (const old of (await cachedVersions()).slice(KEEP)) await fs.rm(tarball(old), { force: true });
}

let inflight = null; // concurrent deploys share one check/download
/**
 * The newest WordPress available as a verified local archive:
 * → { version, path, fresh } (fresh = downloaded just now). Falls back to the
 * newest cached release when wordpress.org can't be reached. Throws when there
 * is nothing usable.
 */
export function wordpressCore() {
  inflight ||= (async () => {
    await fs.mkdir(WP_CORE_DIR, { recursive: true, mode: 0o755 });
    await fs.chmod(WP_CORE_DIR, 0o755);
    let latest = null;
    try { latest = await latestVersion(); } catch { /* offline → newest cached */ }
    const have = await cachedVersions();
    if (latest && !have.includes(latest)) {
      try {
        await download(latest);
        return { version: latest, path: tarball(latest), fresh: true };
      } catch (e) {
        if (!have.length) throw e;
      }
    }
    const v = latest && have.includes(latest) ? latest : have[0];
    if (!v) throw new Error('no WordPress release cached and wordpress.org unreachable');
    return { version: v, path: tarball(v), fresh: false };
  })().finally(() => { inflight = null; });
  return inflight;
}

// Self-check: node src/lib/wpcore.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const assert = (await import('node:assert')).strict;
  assert.deepEqual(['6.7', '6.10.1', '6.9.2', '6.10'].sort(byVersion), ['6.10.1', '6.10', '6.9.2', '6.7']);
  console.log('wpcore ok');
}
