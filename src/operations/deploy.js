import { run, woSiteExists, nginxTest, nginxReload, getPhpVersion, setCanonical, WO_SITE_TIMEOUT_MS } from '../lib/sys.js';
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
  const lg = logger(helpers);
  const { log, step, ok, warn, skip, done } = lg;
  const domain = p.domain;
  const requestedUser = p.wp_user || '';
  const requestedPassword = p.wp_password || '';
  const isNewSite = !(await woSiteExists(helpers, domain));

  // 1) Create WordPress site.
  step('Create the WordPress site');
  if (!isNewSite) {
    warn(`${domain} already exists on this server — leaving it in place and continuing`);
  } else {
    const php = getPhpVersion();
    const args = ['site', 'create', domain, '--wp', `--php${php.flag}`];
    if (requestedUser && requestedPassword) {
      args.push(`--user=${requestedUser}`, `--pass=${requestedPassword}`, `--email=admin@${domain}`);
    }
    const r = await run(helpers, 'wo', args, { timeout: WO_SITE_TIMEOUT_MS });
    if (r.code !== 0) {
      const detail = r.timedOut
        ? `timed out after ${WO_SITE_TIMEOUT_MS}ms`
        : `code ${r.code}`;
      throw new Error(`wo site create failed (${detail})`);
    }
    ok(`Site created — ${domain}`);
  }

  // 2) Issue SSL certificate (explicit choice from the portal; default on).
  if (p.issueSsl === false) {
    skip('Issue the HTTPS certificate — you chose "No SSL"');
  } else {
    step('Issue the HTTPS certificate');
    const ssl = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force'], { timeout: WO_SITE_TIMEOUT_MS });
    if (ssl.code === 0) {
      ok(`HTTPS enabled for ${domain}`);
      // Reload nginx after cert install.
      if (await nginxTest(helpers)) {
        await nginxReload(helpers);
        ok('Web server reloaded');
      }
    } else {
      warn(ssl.timedOut
        ? `Certificate request timed out after ${Math.round(WO_SITE_TIMEOUT_MS / 1000)}s. The site is live over HTTP — issue HTTPS from the site page once it settles.`
        : `Could not issue the certificate yet — this usually means ${domain}'s DNS does not point here, or port 80 is blocked. The site is live over HTTP; enable HTTPS from the site page once DNS is ready.`);
    }
  }

  // Apply domain preferences (canonical redirect + www enablement). Handles
  // none/enable-www itself and reloads nginx only if it changed something.
  step('Apply the www / non-www preference');
  await setCanonical(helpers, domain, p.canonical, p.enableWww);

  done(`Site ready — https://${domain}`);
}
