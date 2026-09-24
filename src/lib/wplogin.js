import { randomBytes, createHash } from 'node:crypto';
import path from 'node:path';
import { wpCli } from './wp.js';
import { spawnWorker, settle } from './files.js';
import { webRoot } from './sites.js';

// ============================================================
//  wplogin.js — one-click (passwordless) login to wp-admin
// ============================================================
// The agent mints a random single-use token; WordPress only ever stores its
// SHA-256 (a 2-minute transient naming the first administrator). A small
// must-use plugin, kept in place by the agent, redeems it on wp-login.php:
// deletes it first (single use, even when invalid), sets the auth cookie,
// redirects to wp-admin. The token never appears on a command line (argv is
// readable by every local user): the PHP that stores the hash arrives on stdin.

export const LINK_TTL_S = 120;

const MU_PLUGIN = `<?php
/**
 * Plugin Name: wcloud one-click login
 * Description: Lets your wcloud panel sign you in with a single-use link. Managed by wcloud — edits are overwritten.
 */
defined( 'ABSPATH' ) || exit;

add_action( 'login_init', function () {
	if ( empty( $_GET['wcloud_login'] ) || ! is_string( $_GET['wcloud_login'] ) ) {
		return;
	}
	$key  = 'wcloud_login_' . hash( 'sha256', wp_unslash( $_GET['wcloud_login'] ) );
	$data = get_transient( $key );
	delete_transient( $key ); // single use, even when invalid
	$user = is_array( $data ) && ! empty( $data['user'] ) ? get_user_by( 'id', (int) $data['user'] ) : false;
	if ( ! $user ) {
		wp_die( 'This login link has expired or was already used. Open a new one from your wcloud panel.', 'Login link expired', array( 'response' => 403 ) );
	}
	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID, false, is_ssl() );
	do_action( 'wp_login', $user->user_login, $user );
	wp_safe_redirect( admin_url() );
	exit;
} );
`;

// Returns { url, user } or throws with a plain-words message.
export async function createLoginLink(helpers, s) {
  const token = randomBytes(32).toString('hex');
  const hash = createHash('sha256').update(token).digest('hex');
  const php = `<?php
$u = get_users( array( 'role' => 'administrator', 'orderby' => 'ID', 'order' => 'ASC', 'number' => 1 ) );
if ( ! $u ) { echo json_encode( array( 'error' => 'no-admin' ) ); return; }
set_transient( 'wcloud_login_${hash}', array( 'user' => $u[0]->ID ), ${LINK_TTL_S} );
echo json_encode( array( 'user' => $u[0]->user_login, 'login' => site_url( 'wp-login.php', 'login' ), 'mu' => WPMU_PLUGIN_DIR ) );
`;
  const r = await (await wpCli(helpers, s))(['eval-file', '-'], { stdin: php, quiet: true, timeout: 60_000 });
  let out = {};
  try { out = JSON.parse((r.stdout || '').trim().split('\n').pop()); } catch { /* wp-cli failed */ }
  if (out.error === 'no-admin') throw new Error('This site has no administrator account to sign in as.');
  if (r.code !== 0 || !out.login) throw new Error('WordPress on this site didn\'t respond — is it installed and working?');

  // (Re)install the redeeming plugin as the SITE's user (never as root inside
  // a directory the site controls). Rewritten every time, so it self-heals.
  const root = webRoot(s.domain);
  const file = path.join(out.mu, 'wcloud-login.php');
  if (!file.startsWith(`${root}/`)) throw new Error('This site keeps its plugins outside its web root, so one-click login can\'t be set up.');
  const w = await spawnWorker(s, 'write', { path: path.relative(root, file), max: 64 * 1024 });
  w.stdin.end(MU_PLUGIN);
  const wr = await settle(w);
  if (!wr.ok) throw new Error(`The login helper couldn't be installed: ${wr.message}`);

  return { url: `${out.login}?wcloud_login=${token}`, user: out.user, expires_in: LINK_TTL_S };
}
