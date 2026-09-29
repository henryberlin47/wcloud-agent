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

export const wantsHelper = (s) => s.type === 'wordpress' && (s.cache === 'fastcgi' || !!s.cfCache);

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
  // Sites whose Cloudflare purge was held back (too soon after the last one).
  // Their marker is gone already, so it is asked again on every tick until it
  // goes out: a burst of changes ends with one purge, never with none.
  const owed = new Set();
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
        if (owed.delete(d)) what.add('cf');
        if (!what.size) continue;
        const s = await readSpec(d);
        if (!s) continue;
        if (what.has('page') && s.cache === 'fastcgi') await clearPageCache(s.domain);
        if (what.has('cf') && s.cfCache) {
          const r = await purgeCloudflare(s.domain);
          if (r.skipped) owed.add(d);
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
  if (wantsHelper(s)) {
    // Already current (the usual case at startup) → no wp-cli round trip.
    const want = muHelper({ page: s.cache === 'fastcgi', cf: !!s.cfCache });
    const file = `${webRoot(s.domain)}/wp-content/mu-plugins/wcloud-cache.php`;
    if ((await readHead(file, Buffer.byteLength(want) + 1)) === want) return;
    return installMuPlugin(helpers, s, 'wcloud-cache.php', want);
  }
  const w = await spawnWorker(s, 'delete', { paths: ['wp-content/mu-plugins/wcloud-cache.php'] });
  await settle(w); // gone already is fine
}

// First `n` bytes of a site-owned file, read as root: no symlinks (O_NOFOLLOW),
// never waits on a FIFO (O_NONBLOCK — a blocked open holds one of the agent's
// few fs threads for good), regular files only. null = not readable.
async function readHead(file, n) {
  let fh;
  try {
    fh = await fs.open(file, FS.O_RDONLY | FS.O_NOFOLLOW | FS.O_NONBLOCK);
    if (!(await fh.stat()).isFile()) return null;
    const { buffer, bytesRead } = await fh.read(Buffer.alloc(n), 0, n, 0);
    return buffer.subarray(0, bytesRead).toString('utf8');
  } catch {
    return null;
  } finally {
    await fh?.close();
  }
}

// Is the Redis object cache active? Its drop-in is wp-content/object-cache.php
// (first 4 KB, see readHead).
export async function objectCacheActive(s) {
  return s.type === 'wordpress'
    && /Redis Object Cache/i.test((await readHead(`${webRoot(s.domain)}/wp-content/object-cache.php`, 4096)) ?? '');
}

// Can nginx serve WP Rocket's cache for this site? Only when WP Rocket is
// installed AND active AND its page cache is set up: WP_CACHE on and WP
// Rocket's advanced-cache.php drop-in in place (it writes both on activation).
// Asked through wp-cli as the site's user. → { installed, active, version,
// ready, problem } — problem is a sentence for the user when not ready;
// { error } when WordPress itself didn't answer.
const ROCKET_PHP = `$f = WP_CONTENT_DIR . '/advanced-cache.php';
echo "\n" . json_encode(array(
  'installed' => file_exists(WP_PLUGIN_DIR . '/wp-rocket/wp-rocket.php'),
  'active' => defined('WP_ROCKET_VERSION'),
  'version' => defined('WP_ROCKET_VERSION') ? WP_ROCKET_VERSION : null,
  'wpCache' => defined('WP_CACHE') && WP_CACHE,
  'dropin' => is_file($f) && strpos((string) file_get_contents($f, false, null, 0, 8192), 'WP_ROCKET') !== false,
));`;
export async function wpRocketStatus(helpers, s) {
  const r = await (await wpCli(helpers, s))(['eval', ROCKET_PHP], { quiet: true, timeout: 60_000 });
  let st = null;
  try { st = JSON.parse(r.stdout.trim().split('\n').pop()); } catch { /* below */ }
  if (r.code !== 0 || !st) return { error: 'WordPress on this site didn\'t respond — is it installed and working?' };
  const problem = !st.installed ? 'WP Rocket isn\'t installed on this site. Install and activate it first (Plugins tab).'
    : !st.active ? 'WP Rocket is installed but not active. Activate it first (Plugins tab).'
    : !st.wpCache || !st.dropin ? `WP Rocket is active but its page cache isn't set up (${[!st.wpCache && 'WP_CACHE is off', !st.dropin && 'its advanced-cache.php is missing'].filter(Boolean).join(', ')}). Open WP Rocket's settings in wp-admin and save them once (or deactivate and reactivate it), then try again.`
    : null;
  return { installed: !!st.installed, active: !!st.active, version: st.version || null, ready: !problem, problem };
}

// LiteSpeed Cache only caches on a LiteSpeed web server. A site moving in from
// one (RunCloud's OpenLiteSpeed stack) arrives with it active and with its
// drop-ins in wp-content: on nginx it caches nothing, and its object-cache
// drop-in points at a cache server that isn't here. Remove the drop-ins it
// wrote (checked by content — read as root, so no symlinks, first 8 KB), then
// deactivate it without loading any plugin. → { active, removed[] }
const LSCACHE_DROPINS = ['object-cache.php', 'advanced-cache.php'];
const isLiteSpeedDropin = async (file) => /litespeed/i.test((await readHead(file, 8192)) ?? '');
export async function retireLiteSpeedCache(helpers, s) {
  const removed = [];
  for (const f of LSCACHE_DROPINS) if (await isLiteSpeedDropin(`${webRoot(s.domain)}/wp-content/${f}`)) removed.push(`wp-content/${f}`);
  if (removed.length) await settle(await spawnWorker(s, 'delete', { paths: removed }));
  const wp = await wpCli(helpers, s);
  const quiet = ['--skip-plugins', '--skip-themes'];
  const active = (await wp(['plugin', 'is-active', 'litespeed-cache', ...quiet], { quiet: true })).code === 0;
  if (active && (await wp(['plugin', 'deactivate', 'litespeed-cache', ...quiet], { quiet: true })).code !== 0) {
    throw new Error('LiteSpeed Cache could not be deactivated');
  }
  return { active, removed };
}

// Keeps LiteSpeed Cache off for good on every WordPress site (a must-use
// plugin: always loaded, can't be switched off in wp-admin). It only caches on
// a LiteSpeed server; on nginx it does nothing useful and its drop-ins break
// things. Never loaded even if the DB says active; activation (wp-admin, bulk,
// WP-CLI) skips its activation hook and never lands in active_plugins — with a
// notice/warning instead of an error, so "activate all" still does the rest;
// its Activate link is replaced by an explanation; its drop-ins are removed
// (admin requests, at most hourly). Installed on deploy/import and by the
// startup reconcile (so an agent update reaches every site).
export const LSCACHE_GUARD_FILE = 'wcloud-litespeed-guard.php';
const LSCACHE_GUARD = `<?php
/**
 * Plugin Name: wcloud — LiteSpeed Cache guard
 * Description: LiteSpeed Cache only works on a LiteSpeed web server. This site runs on nginx (wcloud) and uses wcloud's server page cache, so LiteSpeed Cache stays off.
 * Managed by wcloud — it is put back if removed.
 */
defined( 'ABSPATH' ) || exit;

const WCLOUD_LSCACHE = 'litespeed-cache/litespeed-cache.php';
const WCLOUD_LSCACHE_WHY = 'LiteSpeed Cache only works on a LiteSpeed web server. This site runs on nginx (wcloud), which caches pages itself — turn caching on or off on the site page in wcloud.';

// Never loaded, whatever the database says (e.g. restored from elsewhere).
add_filter( 'option_active_plugins', function ( $v ) { return is_array( $v ) ? array_values( array_diff( $v, array( WCLOUD_LSCACHE ) ) ) : $v; } );
add_filter( 'site_option_active_sitewide_plugins', function ( $v ) { if ( is_array( $v ) ) { unset( $v[ WCLOUD_LSCACHE ] ); } return $v; } );
// Never saved as active.
add_filter( 'pre_update_option_active_plugins', function ( $v ) { return is_array( $v ) ? array_values( array_diff( $v, array( WCLOUD_LSCACHE ) ) ) : $v; } );
add_filter( 'pre_update_site_option_active_sitewide_plugins', function ( $v ) { if ( is_array( $v ) ) { unset( $v[ WCLOUD_LSCACHE ] ); } return $v; } );

// Activation attempt: its activation hook must not run (it writes drop-ins).
add_action( 'activate_plugin', function ( $plugin ) {
	if ( WCLOUD_LSCACHE !== $plugin ) { return; }
	remove_all_actions( 'activate_' . WCLOUD_LSCACHE );
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		WP_CLI::warning( 'LiteSpeed Cache was left inactive — ' . WCLOUD_LSCACHE_WHY );
	} else {
		set_transient( 'wcloud_lscache_blocked', 1, 120 );
	}
} );
add_action( 'admin_notices', function () {
	if ( get_transient( 'wcloud_lscache_blocked' ) ) {
		delete_transient( 'wcloud_lscache_blocked' );
		echo '<div class="notice notice-warning"><p><strong>LiteSpeed Cache was not activated.</strong> ' . esc_html( WCLOUD_LSCACHE_WHY ) . '</p></div>';
	}
} );
// No Activate link for it.
add_filter( 'plugin_action_links_' . WCLOUD_LSCACHE, function ( $links ) {
	unset( $links['activate'] );
	$links['wcloud'] = '<span style="color:#646970">Not available on wcloud (nginx)</span>';
	return $links;
} );
// Its drop-ins, if they turn up (copied in by hand, an old backup).
add_action( 'admin_init', function () {
	if ( get_transient( 'wcloud_lscache_dropins_checked' ) ) { return; }
	set_transient( 'wcloud_lscache_dropins_checked', 1, HOUR_IN_SECONDS );
	foreach ( array( 'object-cache.php', 'advanced-cache.php' ) as $f ) {
		$p = WP_CONTENT_DIR . '/' . $f;
		if ( is_file( $p ) && ! is_link( $p ) && false !== stripos( (string) file_get_contents( $p, false, null, 0, 8192 ), 'litespeed' ) ) {
			@unlink( $p );
		}
	}
} );
`;
export async function syncLiteSpeedGuard(helpers, s) {
  if (s.type !== 'wordpress') return;
  // Already current (the usual case at startup) → no wp-cli round trip.
  // One byte more than the guard is read: a longer file never compares equal.
  const file = `${webRoot(s.domain)}/wp-content/mu-plugins/${LSCACHE_GUARD_FILE}`;
  if ((await readHead(file, Buffer.byteLength(LSCACHE_GUARD) + 1)) === LSCACHE_GUARD) return;
  await installMuPlugin(helpers, s, LSCACHE_GUARD_FILE, LSCACHE_GUARD);
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
