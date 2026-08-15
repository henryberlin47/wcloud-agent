import { run, woSiteExists, nginxTest, nginxReload, getPhpVersion } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// ============================================================
//  deploy — create a vanilla WordPress site on this server
// ============================================================
// Two steps:
//   1) wo site create <domain> --wp [--user --pass --email]  (provisions WP
//      + local MySQL; --user/--pass are wo's own flags — see
//      https://docs.wordops.net/commands/site/#site-create)
//   2) wo site update <domain> --le --force  (issue/renew SSL)
// DB credentials are NOT recorded here — the portal reads them live from
// wp-config.php on demand (see lib/credentials.js). The WP admin password can't
// be read back (WordPress keeps only a bcrypt hash); see resetPassword.js.
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


  log(`Deploy completed: ${domain}`);
}
