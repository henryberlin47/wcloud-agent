import { run } from '../lib/sys.js';

// Re-issue Let's Encrypt SSL for a site (wo site update <domain> --le --force).
export async function runSsl(job, helpers, p) {
  const domain = p.domain;
  helpers.log(`Issuing SSL for ${domain}...`);
  const r = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force']);
  if (r.code !== 0) {
    throw new Error(`SSL issuance failed for ${domain} — ensure its DNS points to this server and port 80 is reachable`);
  }
  helpers.log(`✓ SSL issued for ${domain}`);
}
