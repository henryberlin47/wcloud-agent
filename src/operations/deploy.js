import { run, woSiteExists, woSiteDelete, nginxTest, nginxReload, getPhpVersion, setCanonical } from '../lib/sys.js';
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
  const { log, step, ok, warn, skip } = logger(helpers);
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
    const r = await run(helpers, 'wo', args, { timeout: 300000 });
    if (r.code !== 0) {
      const detail = r.timedOut ? `timed out after ${process.env.AGENT_DEFAULT_OP_TIMEOUT_MS ?? 300000}ms` : `code ${r.code}`;
      throw new Error(`wo site create failed (${detail})`);
    }
    ok(`Created ${domain}`);

    // Roll back a half-created site if later steps fail — same pattern as import.js.
    try {
      await doSslAndPrefs(helpers, ok, warn, skip, log, domain, p);
    } catch (e) {
      warn(`Deploy failed for ${domain} — rolling back half-created site`);
      await woSiteDelete(helpers, domain);
      throw e;
    }
    log(`Deploy completed: ${domain}`);
    return;
  }

  // Existing site (re-issue SSL): no rollback needed.
  await doSslAndPrefs(helpers, ok, warn, skip, log, domain, p);
  log(`Deploy completed: ${domain}`);
}

// Issue SSL + apply domain preferences. Extracted to share the code path between
// the new-site (rollback-wrapped) and existing-site (no rollback) branches.
async function doSslAndPrefs(helpers, ok, warn, skip, log, domain, p) {
  if (p.issueSsl === false) {
    skip('Issue SSL certificate — "No SSL" selected');
  } else {
    log('Issue SSL certificate');
    const ssl = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force'], { timeout: 300000 });
    if (ssl.code === 0) {
      ok(`SSL installed for ${domain}`);
      if (await nginxTest(helpers)) {
        await nginxReload(helpers);
        ok('nginx reloaded');
      }
    } else {
      warn(`SSL failed (DNS/propagation?) — run the SSL op from the site page later`);
    }
  }

  log('Apply domain preferences');
  await setCanonical(helpers, domain, p.canonical, p.enableWww);
}
