import { wpCli } from './wp.js';

// ============================================================
//  plugins.js — read a WordPress site's plugins and themes (changes: operations/plugin.js)
// ============================================================
// Everything goes through wp-cli as the site's own user (wp.wpCli).

// Plugin "names" are wp-cli's identifiers: the folder (or single file) name.
export const PLUGIN_NAME = /^(?!-)[A-Za-z0-9._-]{1,100}$/;
// A zip the upload endpoint put in the site's tmp/ (see server.js).
export const UPLOAD_NAME = /^wcloud-upload-[a-f0-9]{16}\.zip$/;

const parse = (r) => { try { return JSON.parse(r.stdout.trim().split('\n').pop()); } catch { return null; } };

// [{ name, title, status, version, update, update_version, auto_update }]
// status: active | inactive | active-network | must-use | dropin
export async function listPlugins(helpers, s) {
  const r = await (await wpCli(helpers, s))(['plugin', 'list', '--format=json',
    '--fields=name,title,status,version,update,update_version,auto_update'], { quiet: true, timeout: 90_000 });
  const list = r.code === 0 ? parse(r) : null;
  if (!Array.isArray(list)) throw new Error('WordPress on this site didn\'t respond — is it installed and working?');
  return list;
}

// WordPress.org directory search.
export async function searchPlugins(helpers, s, q) {
  // wp-cli reads --anything, anywhere on the command line, as an option
  // (incl. the global --exec/--require): the term must never start with a dash.
  q = String(q ?? '').replace(/^[\s-]+/, '').trim();
  if (!q) throw new Error('Type something to search for.');
  const r = await (await wpCli(helpers, s))(['plugin', 'search', q, '--per-page=24', '--format=json',
    '--fields=name,slug,version,author,rating,num_ratings,active_installs,short_description'], { quiet: true, timeout: 60_000 });
  const list = r.code === 0 ? parse(r) : null;
  if (!Array.isArray(list)) throw new Error('The WordPress.org plugin directory couldn\'t be reached from this server.');
  return list;
}

// Themes, read in PHP (themes off, so none of their code runs) — wp-cli's list
// has no screenshot. Broken themes (e.g. a missing parent) are listed too.
// [{ name, title, version, author, status: active|parent|inactive, parent,
//    update_version, auto_update: on|off, screenshot (URL), error }]
const themesPhp = `<?php
wp_update_themes();
$upd = get_site_transient( 'update_themes' );
$auto = (array) get_site_option( 'auto_update_themes', array() );
$out = array();
foreach ( wp_get_themes( array( 'errors' => null ) ) as $slug => $t ) {
	$err = $t->errors();
	$out[] = array(
		'name' => $slug, 'title' => $t->get( 'Name' ), 'version' => $t->get( 'Version' ), 'author' => wp_strip_all_tags( $t->get( 'Author' ) ),
		'status' => $slug === get_stylesheet() ? 'active' : ( $slug === get_template() ? 'parent' : 'inactive' ),
		'parent' => $t->get_stylesheet() !== $t->get_template() ? $t->get_template() : '',
		'update_version' => isset( $upd->response[ $slug ]['new_version'] ) ? $upd->response[ $slug ]['new_version'] : '',
		'auto_update' => in_array( $slug, $auto, true ) ? 'on' : 'off',
		'screenshot' => (string) $t->get_screenshot(),
		'error' => is_wp_error( $err ) ? $err->get_error_message() : '',
	);
}
echo json_encode( $out );
`;
export async function listThemes(helpers, s) {
  const r = await (await wpCli(helpers, s))(['eval-file', '-', '--skip-plugins', '--skip-themes'], { stdin: themesPhp, quiet: true, timeout: 90_000 });
  const list = r.code === 0 ? parse(r) : null;
  if (!Array.isArray(list)) throw new Error('WordPress on this site didn\'t respond — is it installed and working?');
  return list;
}

export async function searchThemes(helpers, s, q) {
  q = String(q ?? '').replace(/^[\s-]+/, '').trim(); // never an option (see searchPlugins)
  if (!q) throw new Error('Type something to search for.');
  const r = await (await wpCli(helpers, s))(['theme', 'search', q, '--per-page=24', '--format=json',
    '--fields=name,slug,version,author,rating,num_ratings,screenshot_url'], { quiet: true, timeout: 60_000 });
  const list = r.code === 0 ? parse(r) : null;
  if (!Array.isArray(list)) throw new Error('The WordPress.org theme directory couldn\'t be reached from this server.');
  return list;
}
