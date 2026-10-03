import fs from 'node:fs/promises';
import { run, userIds } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { requireSpec, siteDir, webRoot, siteTmp, phpLogPath } from '../lib/sites.js';

// ============================================================
//  permissions — put a site's files back to wcloud's layout (sites.js header)
// ============================================================
//   /var/www/<d>/                root:root 0711
//   /var/www/<d>/conf/nginx/     root:root 0755
//   /var/www/<d>/wp-config.php   <user> 0600
//   /var/www/<d>/htdocs/ …       <user>:www-data, folders 2750, files u+rw g+r o-
//   /var/www/<d>/tmp/ …          <user>:<user>, nothing for anyone else
// Files uploaded over SFTP as root, copied in by hand or unpacked by a plugin
// end up with other owners or world-readable modes: PHP can't write them, or
// other sites' users can read them. Nothing here follows a link the site made:
// the top folders sit in root's 0711 folder (the site can't replace them), and
// inside them `chown -h` / `chmod -R` change links themselves, never their targets.
// ============================================================

/** The top-level folders and files only — cheap, run for every site at agent start. */
export async function fixSiteStructure(s) {
  const { uid, gid } = await userIds(s.user);
  const www = (await userIds('www-data')).gid;
  const set = async (p, u, g, mode, kind) => {
    const st = await fs.lstat(p).catch(() => null);
    if (!st || (kind === 'dir' ? !st.isDirectory() : !st.isFile())) return;
    if (st.uid !== u || st.gid !== g) await fs.chown(p, u, g);
    if ((st.mode & 0o7777) !== mode) await fs.chmod(p, mode);
  };
  await set(siteDir(s.domain), 0, 0, 0o711, 'dir');
  await set(`${siteDir(s.domain)}/conf/nginx`, 0, 0, 0o755, 'dir');
  await set(webRoot(s.domain), uid, www, 0o2750, 'dir');
  await set(siteTmp(s.domain), uid, gid, 0o700, 'dir');
  await set(`${siteDir(s.domain)}/wp-config.php`, uid, gid, 0o600, 'file');
  await set(phpLogPath(s.domain), uid, gid, 0o640, 'file');
}

export async function runPermissions(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  const root = webRoot(s.domain), tmp = siteTmp(s.domain);
  step('Check the site folders');
  await fixSiteStructure(s);
  ok('Site folders as they should be');

  step(`Owner and permissions of every file (${s.user}:www-data)`);
  // How many had another owner, for the log: one pass of find, nothing changed by it.
  const off = await run(helpers, 'find', [root, '(', '!', '-user', s.user, '-o', '!', '-group', 'www-data', ')', '-printf', '.'], { quiet: true, timeout: 30 * 60_000 });
  const must = async (what, cmd, args) => {
    const r = await run(helpers, cmd, args, { timeout: 30 * 60_000 });
    if (r.code !== 0) throw new Error(`${what} failed`);
  };
  await must('Setting the owner', 'chown', ['-R', '-P', '-h', `${s.user}:www-data`, root]);
  await must('Setting the permissions', 'chmod', ['-R', 'u+rwX,g+rX,g-w,o-rwx', root]);
  await must('Setting the folder group bit', 'find', [root, '-type', 'd', '-exec', 'chmod', 'g+s', '{}', '+']);
  const n = (off.stdout || '').length;
  ok(n ? `Owner corrected on ${n} file${n === 1 ? '' : 's'} or folder${n === 1 ? '' : 's'}; permissions set on all` : 'Owners were already correct; permissions set on all');

  if ((await fs.lstat(tmp).catch(() => null))?.isDirectory()) {
    step('The site\'s private tmp folder');
    await must('Setting the owner', 'chown', ['-R', '-P', '-h', `${s.user}:${s.user}`, tmp]);
    await must('Setting the permissions', 'chmod', ['-R', 'u+rwX,go-rwx', tmp]);
    ok('tmp folder private to the site');
  }
  done(`File permissions of ${s.domain} are correct`);
}
