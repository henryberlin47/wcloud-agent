import { certCovers, pathExists } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { requireSpec, applySite, syncWpAddress, fullchainPath } from '../lib/sites.js';
import { issueHttp } from '../lib/acme.js';
import { readSiteSsl } from '../lib/certinfo.js';

// ============================================================
//  canonical — change a live site's www / preferred-address setting
// ============================================================
// The spec change re-renders the vhost (server_name + the 301 to the preferred
// host) in one tested transaction. When www starts being served over HTTPS
// with a Let's Encrypt cert that lacks it, the cert is re-issued to cover it;
// WordPress's address is re-pinned so nginx and WordPress can't redirect at
// each other (see wp.pinWpUrls).
// ============================================================

// params: { domain, canonical: "www"|"root"|"none", enableWww: boolean }
export async function runCanonical(job, helpers, p) {
  const { step, ok, warn, done } = logger(helpers);
  const domain = p.domain;
  const s = { ...(await requireSpec(domain)), canonical: p.canonical, enableWww: p.enableWww };

  step('Apply the domain preference');
  await applySite(helpers, s);
  ok('Web server updated');

  const www = `www.${domain}`;
  if (s.enableWww && s.ssl && (await pathExists(fullchainPath(domain))) && !(await certCovers(fullchainPath(domain), www))) {
    if ((await readSiteSsl(helpers, domain)).source === 'letsencrypt') { // auto-renewing → ours to re-issue
      step(`Add ${www} to the certificate`);
      const r = await issueHttp(helpers, domain, { www: true });
      if (r.ok && r.www) ok(`Certificate now covers ${www}`);
      else warn(`Could not add ${www} to the certificate — is its DNS pointing here? ${www} shows a security warning over HTTPS until it's covered.`);
    } else {
      warn(`Your certificate doesn't cover ${www}, so that address shows a security warning over HTTPS. Install one that covers it.`);
    }
  }

  if (s.type === 'wordpress') {
    step('Update the WordPress address');
    await syncWpAddress(helpers, s);
  }

  const shown = p.canonical === 'www' ? www : p.canonical === 'root' ? domain : `${domain} and ${www}`;
  done(p.canonical === 'none'
    ? `${s.enableWww ? `Both ${domain} and ${www} are` : `${domain} is`} served, with no redirect`
    : `${shown} is now the preferred address for this site`);
}
