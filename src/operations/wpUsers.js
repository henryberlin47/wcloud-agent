import { requireSpec } from '../lib/sites.js';
import { wpCli, wpSetPassword } from '../lib/wp.js';
import { logger } from '../lib/log.js';

// ============================================================
//  WordPress users of one site — list them, rotate their passwords
// ============================================================
// Both run wp-cli with plugins and themes off: none of the site's own code
// runs. Sessions (WordPress's login tokens) carry the time and IP of each
// login, which is the closest WordPress gets to "last login".

const LIST_MAX = 1000;
const listPhp = `<?php
$out = array();
$users = get_users( array( 'orderby' => 'ID', 'order' => 'ASC', 'number' => ${LIST_MAX + 1} ) );
foreach ( array_slice( $users, 0, ${LIST_MAX} ) as $u ) {
	$sessions = array_values( WP_Session_Tokens::get_instance( $u->ID )->get_all() );
	$last = null;
	foreach ( $sessions as $s ) if ( ! $last || $s['login'] > $last['login'] ) $last = $s;
	$out[] = array(
		'id' => (int) $u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'name' => $u->display_name,
		'roles' => array_values( (array) $u->roles ), 'registered' => $u->user_registered,
		'sessions' => count( $sessions ), 'last_login' => $last ? (int) $last['login'] : null, 'last_ip' => $last && isset( $last['ip'] ) ? $last['ip'] : null,
		'app_passwords' => class_exists( 'WP_Application_Passwords' ) ? count( WP_Application_Passwords::get_user_application_passwords( $u->ID ) ) : 0,
	);
}
echo json_encode( array( 'users' => $out, 'more' => count( $users ) > ${LIST_MAX} ) );
`;

const lastJson = (r) => { try { return JSON.parse(r.stdout.trim().split('\n').pop()); } catch { return null; } };

export async function listWpUsers(helpers, s) {
  const r = await (await wpCli(helpers, s))(['eval-file', '-', '--skip-plugins', '--skip-themes'], { stdin: listPhp, quiet: true, timeout: 120_000 });
  const j = lastJson(r);
  if (r.code !== 0 || !Array.isArray(j?.users)) throw new Error('WordPress on this site didn\'t respond — is it installed and working?');
  return j;
}

// ids are validated integers (operations/index.js), so they can be written into the code.
// password: the ids already have their new known password — only log out (+ app passwords).
const rotatePhp = (ids, { random, appPasswords }) => `<?php
$done = array(); $missing = array();
foreach ( array(${ids.join(',')}) as $id ) {
	$u = get_userdata( $id );
	if ( ! $u ) { $missing[] = $id; continue; }
	${random ? 'wp_set_password( wp_generate_password( 32, true, true ), $id );' : ''}
	WP_Session_Tokens::get_instance( $id )->destroy_all();
	${appPasswords ? "if ( class_exists( 'WP_Application_Passwords' ) ) WP_Application_Passwords::delete_all_application_passwords( $id );" : ''}
	$done[] = $u->user_login;
}
echo json_encode( array( 'done' => $done, 'missing' => $missing ) );
`;

// p: { domain, user_ids: [int], password?: string (exactly one id), appPasswords?: boolean }
export async function runWpUsers(job, helpers, p) {
  const { step, ok, warn, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — it has no WordPress users.`);
  const ids = p.user_ids;
  if (p.password) {
    step(`Set a new password for user #${ids[0]}`);
    const r = await wpSetPassword(helpers, s, String(ids[0]), p.password);
    if (r.code !== 0) throw new Error(`The password of user #${ids[0]} could not be set — does the user still exist?`);
  } else {
    step(`New random passwords for ${ids.length} user${ids.length === 1 ? '' : 's'}`);
  }
  const r = await (await wpCli(helpers, s))(['eval-file', '-', '--skip-plugins', '--skip-themes'],
    { stdin: rotatePhp(ids, { random: !p.password, appPasswords: p.appPasswords }), quiet: true, timeout: 300_000 });
  const j = lastJson(r);
  if (r.code !== 0 || !Array.isArray(j?.done)) throw new Error((r.stderr || r.stdout).trim().split('\n').pop() || 'WordPress did not respond');
  for (const login of j.done) ok(`${login}: ${p.password ? 'new password set' : 'new random password'}, logged out${p.appPasswords ? ', application passwords removed' : ''}`);
  if (j.missing.length) warn(`No such user: #${j.missing.join(', #')}`);
  job.result = { done: j.done, missing: j.missing };
  if (!j.done.length) throw new Error('None of those users exist on this site any more.');
  done(`${j.done.length} user${j.done.length === 1 ? '' : 's'} updated`);
}
