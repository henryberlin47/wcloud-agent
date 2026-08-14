import { wpCli, resolveWpRoot } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// ============================================================
//  resetPassword — set a new, known WordPress admin password
// ============================================================
// The WP admin password can never be read back after the fact (WordPress
// only keeps a bcrypt hash), so "show me the current password" isn't
// possible. This sets a new one the operator already knows (they typed or
// generated it), applied via wp-cli — same tool update.js/deploy.js use.
// ============================================================

export async function runResetPassword(job, helpers, p) {
  const { step, ok, err } = logger(helpers);
  const domain = p.domain;
  const newPassword = p.wp_password;

  step('Locate WordPress admin user');
  const wpRoot = await resolveWpRoot(domain);
  const wp = wpCli(helpers, wpRoot);
  const userList = await wp(['user', 'list', '--role=administrator', '--field=user_login']);
  const wpUser = userList.code === 0 ? (userList.stdout.trim().split('\n')[0] || '').trim() : '';
  if (!wpUser) {
    err(`No administrator user found at ${wpRoot} (code ${userList.code})`);
    throw new Error(`Could not find a WordPress admin user for ${domain}`);
  }
  ok(`Found admin user: ${wpUser}`);

  step('Set new password');
  const setPass = await wp(['user', 'update', wpUser, `--user_pass=${newPassword}`]);
  if (setPass.code !== 0) {
    throw new Error(`Failed to set password for ${wpUser} (code ${setPass.code})`);
  }
  ok(`Password updated for ${wpUser}`);
}
