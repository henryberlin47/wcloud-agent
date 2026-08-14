import config from '../config.js';
import { run, woSiteExists, nginxTest, nginxReload, wpCli, resolveWpRoot, getPhpVersion } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { setCredentials } from '../lib/credentials.js';

// ============================================================
//  deploy — create a vanilla WordPress site on this server
// ============================================================
// Three steps:
//   1) wo site create <domain> --wp [--user --pass --email]  (provisions WP
//      + local MySQL; --user/--pass are wo's own flags — see
//      https://docs.wordops.net/commands/site/#site-create)
//   2) wo site update <domain> --le --force  (issue/renew SSL)
//   3) record DB credentials for the DB button on the portal's Sites page
//      (the WP password isn't re-read here — the portal already showed it to
//      the operator right after they submitted the deploy form, since it's
//      the one who chose it; see resetPassword.js for changing it later)
// ============================================================

export async function runDeploy(job, helpers, p) {
  const { log, step, ok, warn } = logger(helpers);
  const domain = p.domain;
  const requestedUser = p.wp_user || '';
  const requestedPassword = p.wp_password || '';
  const isNewSite = !(await woSiteExists(helpers, domain));

  // 1) Create WordPress site.
  step('Create WordPress site');
  if (!isNewSite) {
    warn(`Already exists in WordOps: ${domain} — skipping creation`);
  } else {
    const php = getPhpVersion();
    const args = ['site', 'create', domain, '--wp', `--php${php.flag}`];
    if (requestedUser && requestedPassword) {
      args.push(`--user=${requestedUser}`, `--pass=${requestedPassword}`, `--email=admin@${domain}`);
    }
    const r = await run(helpers, 'wo', args);
    if (r.code !== 0) {
      throw new Error(`wo site create failed (code ${r.code})`);
    }
    ok(`Created ${domain}`);
  }

  // 2) Issue SSL certificate.
  step('Issue SSL certificate');
  const ssl = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force']);
  if (ssl.code === 0) {
    ok(`SSL installed for ${domain}`);
    // Reload nginx after cert install.
    if (await nginxTest(helpers)) {
      await nginxReload(helpers);
      ok('nginx reloaded');
    }
  } else {
    warn(`SSL failed (DNS/propagation?) — run "wo site update ${domain} --le --force" later`);
  }

  // 3) Record DB credentials — always readable straight from wp-config.php
  // via `wp config get`, unlike the WP admin password (WordPress only keeps
  // a bcrypt hash, so it can never be read back after the fact).
  step('Recording DB credentials');
  try {
    const wpRoot = await resolveWpRoot(domain);
    const wp = wpCli(helpers, wpRoot);
    const dbResults = await Promise.all(
      ['DB_NAME', 'DB_USER', 'DB_PASSWORD'].map((key) => wp(['config', 'get', key]))
    );
    const [dbName, dbUser, dbPassword] = dbResults.map((r) => (r.code === 0 ? r.stdout.trim() : ''));

    setCredentials(domain, { db_name: dbName, db_user: dbUser, db_password: dbPassword });
    dbName ? ok('DB credentials recorded') : warn(`Could not read DB config at ${wpRoot}`);
  } catch (e) {
    warn(`Could not record DB credentials: ${e.message}`);
  }

  log(`Deploy completed: ${domain}`);
}
