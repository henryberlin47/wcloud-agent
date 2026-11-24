import { listSites } from '../lib/sites.js';
import { wpCli } from '../lib/wp.js';
import { logger } from '../lib/log.js';

// ============================================================
//  resetpasswords — every WordPress user on the server, locked out of old logins
// ============================================================
// Each user of each WordPress site gets a new random password that nobody
// learns (made and hashed inside WordPress; it never leaves PHP) and is logged
// out everywhere. Administrators sign in again with the portal's one-click
// login (lib/wplogin.js needs no password) and can set a known one with
// "Reset admin password"; everyone else uses "Lost your password?".
// appPasswords: application passwords go too (they log in without a password,
// so a reset alone leaves them working).
// Runs with plugins and themes off: none of the sites' own code runs.
// ============================================================

const php = (appPasswords) => `<?php
$n = 0;
foreach ( get_users( array( 'fields' => 'ID' ) ) as $id ) {
	wp_set_password( wp_generate_password( 32, true, true ), $id );
	WP_Session_Tokens::get_instance( $id )->destroy_all();
	${appPasswords ? 'WP_Application_Passwords::delete_all_application_passwords( $id );' : ''}
	$n++;
}
echo json_encode( array( 'users' => $n ) );
`;

export async function runResetPasswords(job, helpers, p) {
  const { step, ok, err, done } = logger(helpers);
  const sites = (await listSites()).filter((s) => s.type === 'wordpress');
  if (!sites.length) throw new Error('There is no WordPress site on this server.');
  step(`New passwords for every user of ${sites.length} WordPress site${sites.length === 1 ? '' : 's'}${p.appPasswords ? ', application passwords removed' : ''}`);
  const reset = [];
  const failed = [];
  for (const s of sites) {
    try {
      const r = await (await wpCli(helpers, s))(['eval-file', '-', '--skip-plugins', '--skip-themes'],
        { stdin: php(p.appPasswords), quiet: true, timeout: 300_000 });
      const users = (() => { try { return JSON.parse(r.stdout.trim().split('\n').pop()).users; } catch { return null; } })();
      if (r.code !== 0 || !Number.isInteger(users)) throw new Error((r.stderr || r.stdout).trim().split('\n').pop() || 'WordPress did not respond');
      ok(`${s.domain}: ${users} user${users === 1 ? '' : 's'}`);
      reset.push({ domain: s.domain, users });
    } catch (e) {
      err(`${s.domain}: ${e.message}`);
      failed.push(s.domain);
    }
  }
  job.result = { reset, failed };
  if (failed.length) throw new Error(`${failed.length} of ${sites.length} sites were not reset: ${failed.join(', ')}`);
  const users = reset.reduce((a, x) => a + x.users, 0);
  done(`${users} user${users === 1 ? '' : 's'} on ${reset.length} site${reset.length === 1 ? '' : 's'}: new passwords, logged out`);
}
