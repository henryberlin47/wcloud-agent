import { requireSpec } from '../lib/sites.js';
import { wpCli, wpSetPassword } from '../lib/wp.js';
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

  step('Find the administrator account');
  const s = await requireSpec(domain);
  if (s.type !== 'wordpress') throw new Error(`${domain} is a static site — it has no WordPress login.`);
  const wp = await wpCli(helpers, s);
  const userList = await wp(['user', 'list', '--role=administrator', '--field=user_login']);
  const wpUser = userList.code === 0 ? (userList.stdout.trim().split('\n')[0] || '').trim() : '';
  if (!wpUser) {
    err('No administrator account was found on this site');
    throw new Error(`Could not find a WordPress admin user for ${domain}`);
  }
  ok(`Administrator account: ${wpUser}`);

  step('Set the new password');
  const setPass = await wpSetPassword(helpers, s, wpUser, newPassword);
  if (setPass.code !== 0) {
    throw new Error(`Failed to set password for ${wpUser} (code ${setPass.code})`);
  }
  ok(`Password changed for ${wpUser}`);
}
