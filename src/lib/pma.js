import { randomBytes, createHash } from 'node:crypto';
import { run, pathExists, userIds } from './sys.js';
import { applySite, siteTmp, fullchainPath, PMA_DIR, PMA_PATH } from './sites.js';
import { readDbCredentials } from './wp.js';

// ============================================================
//  pma.js — single-use sign-in links to phpMyAdmin for a site
// ============================================================
// phpMyAdmin is installed once per server (init.sh) and served by each
// WordPress site at /.wcloud-pma/ through that site's own PHP pool, signed in
// with that site's own DB login — so it can only ever see that database.
// There is no login form (auth_type=signon): the agent writes a token file —
// { user, password, db, expires } — into the site's own tmp/ AS THE SITE USER,
// named by the token's SHA-256; wcloud-signon.php redeems it once. The
// password travels on stdin, never argv.

export const LINK_TTL_S = 120;

// Runs as the site user: prune stale token files, then create this one (O_EXCL, 0600).
const WRITE_TOKEN = `
const fs = require('fs'), path = require('path');
const [dir, name] = process.argv.slice(1);
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
for (const f of fs.readdirSync(dir)) {
  try { if (Date.now() - fs.statSync(path.join(dir, f)).mtimeMs > 600000) fs.unlinkSync(path.join(dir, f)); } catch {}
}
fs.writeFileSync(path.join(dir, name), fs.readFileSync(0), { flag: 'wx', mode: 0o600 });
`;

// Returns { url, db, expires_in } or throws with a plain-words message.
export async function createPmaLink(helpers, s) {
  if (!(await pathExists(`${PMA_DIR}/index.php`))) {
    throw new Error('phpMyAdmin isn\'t installed on this server yet — re-run the install command on it to add it.');
  }
  const creds = await readDbCredentials(helpers, s);
  if (!creds?.db_user) throw new Error('This site\'s database login couldn\'t be read from wp-config.php.');

  // Vhosts rendered before phpMyAdmin existed don't serve /.wcloud-pma/ yet;
  // re-applying is a no-op when they already do.
  await applySite(helpers, s);

  const token = randomBytes(32).toString('hex');
  const { uid, gid } = await userIds(s.user);
  const r = await run(helpers, process.execPath, ['-e', WRITE_TOKEN, `${siteTmp(s.domain)}/wcloud-pma`, createHash('sha256').update(token).digest('hex')], {
    as: { uid, gid, home: siteTmp(s.domain) },
    stdin: JSON.stringify({ user: creds.db_user, password: creds.db_password, db: creds.db_name, expires: Math.floor(Date.now() / 1000) + LINK_TTL_S }),
    quiet: true, timeout: 30_000,
  });
  if (r.code !== 0) throw new Error('The phpMyAdmin sign-in couldn\'t be prepared on the server.');

  const https = s.ssl && (await pathExists(fullchainPath(s.domain)));
  const host = s.enableWww && s.canonical === 'www' ? `www.${s.domain}` : s.domain;
  return { url: `${https ? 'https' : 'http'}://${host}${PMA_PATH}wcloud-signon.php?t=${token}`, db: creds.db_name, https, expires_in: LINK_TTL_S };
}
