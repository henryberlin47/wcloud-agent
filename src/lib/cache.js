import fs from 'node:fs/promises';
import { constants as FS } from 'node:fs';
import path from 'node:path';
import { logger } from './log.js';
import { listSites, readSpec, siteTmp, webRoot, clearPageCache } from './sites.js';
import { wpCli } from './wp.js';
import { spawnWorker, settle } from './files.js';
import { purgeCloudflare } from './cfcache.js';

// ============================================================
//  cache.js — page cache (nginx FastCGI) + Redis object cache for a site
// ============================================================
// The page cache is written by nginx (www-data) into a root/www-data-owned
// dir the site can't touch, so a site can't clear it itself. Instead the
// must-use plugin below drops a marker file in the site's own tmp/ when
// content changes, and the agent's watcher clears that site's cache within a
// few seconds. The "Purge cache" operation clears it directly.
// ============================================================

// Markers the helper plugin drops in the site's own tmp/ (the agent can't be
// reached from PHP, and WordPress never holds a Cloudflare token):
//   wcloud-purge       content changed → page cache + Cloudflare (whichever are on)
//   wcloud-purge-page  toolbar "Purge page cache"
//   wcloud-purge-cf    toolbar "Purge Cloudflare cache"
const MARKERS = { 'wcloud-purge': ['page', 'cf'], 'wcloud-purge-page': ['page'], 'wcloud-purge-cf': ['cf'] };
export { clearPageCache }; // lives in sites.js (applySite clears on config changes)

const wantsHelper = (s) => s.type === 'wordpress' && (s.cache === 'fastcgi' || !!s.cfCache);

// Poll each such site's tmp/ for the markers. lstat + unlink never follow a
// symlink, so a site can't point this at anything else.
// ponytail: polls every site every 3s (cheap stat calls); inotify if a server
// ever holds thousands of sites.
// Every WordPress site is scanned and its spec re-read only when a marker is
// found: a cached spec made a just-enabled Cloudflare cache ignore purges for
// up to 30s.
export function startPurgeWatcher() {
  let domains = [];
  let listedAt = 0;
  const tick = async () => {
    try {
      if (Date.now() - listedAt > 30_000) {
        domains = (await listSites()).filter((x) => x.type === 'wordpress').map((x) => x.domain);
        listedAt = Date.now();
      }
      for (const d of domains) {
        const what = new Set();
        for (const [marker, kinds] of Object.entries(MARKERS)) {
          const f = path.join(siteTmp(d), marker);
          try { await fs.lstat(f); } catch { continue; }
          await fs.unlink(f).catch(() => {});
          kinds.forEach((k) => what.add(k));
        }
        if (!what.size) continue;
        const s = await readSpec(d);
        if (!s) continue;
        if (what.has('page') && s.cache === 'fastcgi') await clearPageCache(s.domain);
        if (what.has('cf') && s.cfCache) {
          const r = await purgeCloudflare(s.domain);
          if (!r.ok) console.error(`[agent] Cloudflare purge for ${s.domain}: ${r.error}`);
        }
      }
    } catch (e) {
      console.error('[agent] purge watcher:', e.message);
    }
  };
  setInterval(tick, 3000).unref();
}

// The helper must-use plugin, generated per site: purge on content changes,
// plus a toolbar "Cache" menu for administrators. Only what the site has on is
// included (page cache, Cloudflare) — no settings are read at runtime.
function muHelper({ page, cf }) {
  const items = [
    ...(page && cf ? [['all', 'Purge all caches', 'wcloud-purge']] : []),
    ...(page ? [['page', 'Purge page cache', 'wcloud-purge-page']] : []),
    ...(cf ? [['cloudflare', 'Purge Cloudflare cache', 'wcloud-purge-cf']] : []),
  ];
  const map = items.map(([k, , m]) => `'${k}' => '${m}'`).join(', ');
  const nodes = items.map(([k, label]) => `\t$bar->add_node( array( 'parent' => 'wcloud-cache', 'id' => 'wcloud-purge-${k}', 'title' => '${label}', 'href' => wp_nonce_url( admin_url( 'admin-post.php?action=wcloud_purge&what=${k}' ), 'wcloud_purge' ) ) );`).join('\n');
  return `<?php
/**
 * Plugin Name: wcloud cache
 * Description: Clears this site's caches when content changes${cf ? ' (server page cache and Cloudflare)' : ''}, and adds a Cache menu to the toolbar. Managed by wcloud — edits are overwritten.
 */
defined( 'ABSPATH' ) || exit;

function wcloud_cache_marker( $name ) {
	@touch( dirname( rtrim( ABSPATH, '/' ) ) . '/tmp/' . $name );
}
function wcloud_request_purge() {
	static $done = false;
	if ( ! $done ) {
		$done = true;
		wcloud_cache_marker( 'wcloud-purge' );
	}
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

// Toolbar → Cache → Purge … (administrators only; nonce-checked).
add_action( 'admin_bar_menu', function ( $bar ) {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$bar->add_node( array( 'id' => 'wcloud-cache', 'title' => '<span class="ab-icon dashicons dashicons-cloud" style="top:2px"></span>Cache', 'href' => false ) );
${nodes}
}, 100 );
add_action( 'admin_post_wcloud_purge', function () {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Sorry, you are not allowed to do that.', 403 );
	}
	check_admin_referer( 'wcloud_purge' );
	$markers = array( ${map} );
	$what    = isset( $_GET['what'] ) ? sanitize_key( wp_unslash( $_GET['what'] ) ) : '';
	if ( isset( $markers[ $what ] ) ) {
		wcloud_cache_marker( $markers[ $what ] );
	}
	wp_safe_redirect( add_query_arg( 'wcloud_purged', $what, wp_get_referer() ? wp_get_referer() : admin_url() ) );
	exit;
} );
add_action( 'admin_notices', function () {
	if ( isset( $_GET['wcloud_purged'] ) && current_user_can( 'manage_options' ) ) {
		echo '<div class="notice notice-success is-dismissible"><p>Cache purge requested — it completes within a few seconds.</p></div>';
	}
} );
`;
}

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

/** Install, rewrite or remove the helper plugin to match the site's spec. */
export async function syncCachePlugin(helpers, s) {
  if (wantsHelper(s)) return installMuPlugin(helpers, s, 'wcloud-cache.php', muHelper({ page: s.cache === 'fastcgi', cf: !!s.cfCache }));
  const w = await spawnWorker(s, 'delete', { paths: ['wp-content/mu-plugins/wcloud-cache.php'] });
  await settle(w); // gone already is fine
}

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
