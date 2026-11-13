import { logger } from '../lib/log.js';
import { setPasswordLogin, setFail2ban, removeKeys } from '../lib/ssh.js';

// ============================================================
//  sshsecurity — SSH settings of the whole server (lib/ssh.js)
// ============================================================
// params: { passwordLogin?: bool, fail2ban?: bool, removeKeys?: [{ user, fingerprint }] }
// Each part runs only when given. Keys go first, so the lockout checks of
// password login see what's left.
export async function runSshSecurity(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const did = [];
  if (p.removeKeys?.length) {
    step(`Remove ${p.removeKeys.length === 1 ? 'an SSH key' : `${p.removeKeys.length} SSH keys`}`);
    const n = await removeKeys(helpers, p.removeKeys);
    ok(n ? `Removed ${n} line${n === 1 ? '' : 's'} from authorized_keys (a .bak copy is kept next to each file)` : 'Those keys were already gone');
    did.push(n === 1 ? 'removed 1 key' : `removed ${n} keys`);
  }
  if (typeof p.passwordLogin === 'boolean') {
    step(p.passwordLogin ? 'Allow password login' : 'Turn password login off (keys only)');
    await setPasswordLogin(helpers, p.passwordLogin);
    ok('sshd reloaded — open sessions stay connected');
    did.push(p.passwordLogin ? 'password login on' : 'password login off');
  }
  if (typeof p.fail2ban === 'boolean') {
    step(p.fail2ban ? 'Turn on brute-force protection (fail2ban)' : 'Turn off brute-force protection (fail2ban)');
    await setFail2ban(helpers, p.fail2ban);
    ok(p.fail2ban ? 'An IP with 5 failed logins in 10 minutes is blocked for an hour' : 'fail2ban no longer watches SSH');
    did.push(p.fail2ban ? 'fail2ban on' : 'fail2ban off');
  }
  done(did.length ? `SSH: ${did.join(', ')}` : 'Nothing to change');
}
