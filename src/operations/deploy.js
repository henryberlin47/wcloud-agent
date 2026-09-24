import { logger } from '../lib/log.js';
import { checkCustomCert } from '../lib/certcheck.js';
import { createSite, applySslConf, syncWpAddress, requireSpec } from '../lib/sites.js';
import { issueHttp } from '../lib/acme.js';

// ============================================================
//  deploy — create a site (WordPress or static) on this server
// ============================================================
//   0) own certificate: checked BEFORE anything is created
//   1) create the site: system user, directories, (WordPress: database,
//      wp-config, core install), vhost + PHP pool — rolled back on failure
//   2) HTTPS: the user's certificate, Let's Encrypt, or none
//   3) WordPress: pin its address to what nginx serves
// DB credentials are NOT recorded here — the portal reads them live from
// wp-config.php on demand. The WP admin password can't be read back
// (WordPress keeps only a hash); see resetPassword.js.
// ============================================================

export async function runDeploy(job, helpers, p) {
  const { step, ok, warn, skip, done } = logger(helpers);
  const domain = p.domain;
  const custom = p.cert && p.key;

  if (custom) {
    step('Check your certificate');
    const { warnings } = checkCustomCert(domain, p.cert, p.key, { www: p.enableWww });
    ok(`Certificate and key match, and cover ${domain}`);
    for (const w of warnings) warn(w);
  }

  step(p.type === 'wordpress' ? `Create the WordPress site (PHP ${p.php})` : 'Create the static site');
  await createSite(helpers, {
    domain, type: p.type, php: p.php, enableWww: p.enableWww, canonical: p.canonical,
    wp: { adminUser: p.wp_user, adminPassword: p.wp_password },
  });
  ok(`Site created — ${domain}`);

  if (custom) {
    step('Install your certificate');
    try {
      await applySslConf(helpers, domain, { certs: { fullchain: p.cert, key: p.key } });
      ok(`HTTPS enabled for ${domain} with your certificate`);
    } catch (e) {
      warn(`The site is live over HTTP, but the certificate couldn't be enabled: ${e?.message || e} Try again from the site page.`);
    }
  } else if (p.issueSsl) {
    step('Issue the HTTPS certificate');
    const r = await issueHttp(helpers, domain, { www: p.enableWww });
    if (r.ok) ok(`HTTPS enabled for ${r.www ? `${domain} and www.${domain}` : domain}`);
    else warn(r.timedOut
      ? 'The certificate request timed out. The site is live over HTTP — issue HTTPS from the site page once it settles.'
      : `Could not issue the certificate yet — this usually means ${domain}'s DNS does not point here, or port 80 is blocked. The site is live over HTTP; enable HTTPS from the site page once DNS is ready.`);
  } else {
    skip('Issue the HTTPS certificate — you chose "No SSL"');
  }

  const s = await requireSpec(domain);
  if (s.type === 'wordpress') {
    step('Set the WordPress address');
    await syncWpAddress(helpers, s);
  }
  done(`Site ready — ${s.ssl ? 'https' : 'http'}://${domain}`);
}
