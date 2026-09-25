import fs from 'node:fs/promises';
import { constants as FS } from 'node:fs';
import path from 'node:path';
import { logger } from './log.js';
import { listSites, siteTmp, webRoot, clearPageCache } from './sites.js';
import { wpCli } from './wp.js';
import { spawnWorker, settle } from './files.js';

// ============================================================
//  cache.js — page cache (nginx FastCGI) + Redis object cache for a site
// ============================================================
// The page cache is written by nginx (www-data) into a root/www-data-owned
// dir the site can't touch, so a site can't clear it itself. Instead the
// must-use plugin below drops a marker file in the site's own tmp/ when
// content changes, and the agent's watcher clears that site's cache within a
// few seconds. The "Purge cache" operation clears it directly.
// ============================================================

const PURGE_MARKER = 'wcloud-purge';
export { clearPageCache }; // lives in sites.js (applySite clears on config changes)


// Poll each page-cached site's tmp/ for the marker. lstat + unlink never
// follow a symlink, so a site can't point this at anything else.
// ponytail: polls every site every 3s (cheap stat calls); inotify if a server
// ever holds thousands of sites.
export function startPurgeWatcher() {
  let domains = [];
  let listedAt = 0;
  const tick = async () => {
    try {
      if (Date.now() - listedAt > 30_000) {
        domains = (await listSites()).filter((s) => s.type === 'wordpress' && s.cache === 'fastcgi').map((s) => s.domain);
        listedAt = Date.now();
      }
      for (const d of domains) {
        const marker = path.join(siteTmp(d), PURGE_MARKER);
        try { await fs.lstat(marker); } catch { continue; }
        await fs.unlink(marker).catch(() => {});
        await clearPageCache(d);
      }
    } catch (e) {
      console.error('[agent] purge watcher:', e.message);
    }
  };
  setInterval(tick, 3000).unref();
}

// Clears the page cache (via the marker above) whenever content changes. Uses
// the site root's tmp/ — the same path under PHP-FPM and wp-cli.
const MU_CACHE = `<?php
/**
 * Plugin Name: wcloud page cache
 * Description: Clears this site's server page cache when content changes. Managed by wcloud — edits are overwritten.
 */
defined( 'ABSPATH' ) || exit;

function wcloud_request_purge() {
	static $done = false;
	if ( $done ) {
		return;
	}
	$done = true;
	@touch( dirname( rtrim( ABSPATH, '/' ) ) . '/tmp/${PURGE_MARKER}' );
}
add_action( 'save_post', function ( $id ) {
	if ( ! wp_is_post_revision( $id ) && ! wp_is_post_autosave( $id ) ) {
		wcloud_request_purge();
	}
} );
foreach ( array( 'deleted_post', 'trashed_post', 'untrashed_post', 'comment_post', 'edit_comment', 'wp_set_comment_status',
	'switch_theme', 'customize_save_after', 'wp_update_nav_menu', 'activated_plugin', 'deactivated_plugin',
	'upgrader_process_complete', 'edited_term', 'delete_term', 'update_option_permalink_structure',
	'update_option_blogname', 'update_option_blogdescription', 'woocommerce_product_set_stock' ) as $hook ) {
	add_action( $hook, 'wcloud_request_purge' );
}
`;

// Write a must-use plugin AS THE SITE USER (never as root into a directory
// the site controls). muDir: WPMU_PLUGIN_DIR if already known.
export async function installMuPlugin(helpers, s, file, content, muDir = null) {
  let dir = muDir;
  if (!dir) {
    const r = await (await wpCli(helpers, s))(['eval', 'echo WPMU_PLUGIN_DIR;'], { quiet: true, timeout: 60_000 });
    dir = (r.stdout || '').trim().split('\n').pop();
    if (r.code !== 0 || !dir) throw new Error('WordPress on this site didn\'t respond — is it installed and working?');
  }
  const root = webRoot(s.domain);
  const target = path.join(dir, file);
  if (!target.startsWith(`${root}/`)) throw new Error('This site keeps its plugins outside its web root, so wcloud can\'t add its helper.');
  const w = await spawnWorker(s, 'write', { path: path.relative(root, target), max: 64 * 1024 });
  w.stdin.end(content);
  const r = await settle(w);
  if (!r.ok) throw new Error(`wcloud's helper plugin couldn't be installed: ${r.message}`);
}
export const installCachePlugin = (helpers, s) => installMuPlugin(helpers, s, 'wcloud-cache.php', MU_CACHE);
export const removeCachePlugin = async (helpers, s) => {
  const w = await spawnWorker(s, 'delete', { paths: ['wp-content/mu-plugins/wcloud-cache.php'] });
  await settle(w); // gone already is fine
};

// Is the Redis object cache active? Its drop-in is wp-content/object-cache.php.
// Read as root, so: no symlinks (O_NOFOLLOW), regular file only, first 4 KB.
export async function objectCacheActive(s) {
  if (s.type !== 'wordpress') return false;
  let fh;
  try {
    fh = await fs.open(`${webRoot(s.domain)}/wp-content/object-cache.php`, FS.O_RDONLY | FS.O_NOFOLLOW);
    if (!(await fh.stat()).isFile()) return false;
    const { buffer, bytesRead } = await fh.read(Buffer.alloc(4096), 0, 4096, 0);
    return /Redis Object Cache/i.test(buffer.subarray(0, bytesRead).toString('utf8'));
  } catch {
    return false;
  } finally {
    await fh?.close();
  }
}

// Turn the Redis object cache on/off (plugin + its drop-in). The site's
// wp-config.php already carries its own Redis login and database (wp.js).
export async function setObjectCache(helpers, s, on) {
  const { ok } = logger(helpers);
  const wp = await wpCli(helpers, s);
  const must = async (args, what) => {
    const r = await wp(args, { timeout: 300_000 });
    if (r.code !== 0) {
      const why = `${r.stderr}\n${r.stdout}`.split('\n').map((l) => l.trim()).filter((l) => /^Error:/.test(l)).pop();
      throw new Error(`${what} failed${why ? ` — ${why.replace(/^Error:\s*/, '')}` : '.'}`);
    }
  };
  if (on) {
    if ((await wp(['plugin', 'is-installed', 'redis-cache'], { quiet: true })).code !== 0) {
      await must(['plugin', 'install', 'redis-cache'], 'Installing Redis Object Cache');
    }
    await must(['plugin', 'activate', 'redis-cache'], 'Activating Redis Object Cache');
    if (!(await objectCacheActive(s))) await must(['redis', 'enable'], 'Turning on the object cache');
    ok('Object cache (Redis) is on');
  } else {
    if (await objectCacheActive(s)) await must(['redis', 'disable'], 'Turning off the object cache');
    await wp(['plugin', 'deactivate', 'redis-cache'], { quiet: true });
    ok('Object cache (Redis) is off');
  }
}
