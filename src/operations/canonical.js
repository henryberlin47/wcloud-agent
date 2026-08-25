import { woSiteExists, setCanonical } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// ============================================================
//  canonical — change a live site's www / preferred-domain setting
// ============================================================
// The same work deploy does at creation time, exposed on its own so the choice
// can be changed later from the site page. setCanonical owns the details: the
// redirect snippet, the server_name edit (backed up, nginx -t, rolled back on
// failure), re-issuing the certificate when www starts being served, and
// re-pinning WordPress's address so nginx and WordPress cannot redirect at each
// other (see pinWpUrls).
// ============================================================

// params: { domain, canonical: "www"|"root"|"none", enableWww: boolean }
export async function runCanonical(job, helpers, p) {
  const { step, done } = logger(helpers);
  const domain = p.domain;
  if (!(await woSiteExists(helpers, domain))) {
    throw new Error(`${domain} is not a site on this server.`);
  }

  step('Apply the domain preference');
  await setCanonical(helpers, domain, p.canonical, p.enableWww);

  const shown = p.canonical === 'www' ? `www.${domain}`
    : p.canonical === 'root' ? domain
      : `${domain} and www.${domain}`;
  done(p.canonical === 'none'
    ? `Both addresses are served for ${domain}, with no redirect between them`
    : `${shown} is now the preferred address for this site`);
}
