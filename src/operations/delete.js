import fs from 'node:fs/promises';
import { removePath, findPidsMatching, killPids, sleep, systemctl } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { siteDir, readSpec, deleteSite } from '../lib/sites.js';
import { clearChallenge } from '../lib/acme.js';

// ============================================================
//  delete — permanently remove a site
// ============================================================
// Custom cron schedule + its running processes and locks first (so nothing
// new spawns mid-teardown), then sites.deleteSite: vhost + PHP pool, the
// site user's processes, database, Redis user, files, certificates, spec.
// ============================================================

// params: { domain }   (confirm:true is enforced in validate())
export async function runDelete(job, helpers, p, opts = {}) {
  const { step, info, ok, warn, done } = logger(helpers, opts);
  const domain = p.domain;
  const spec = await readSpec(domain);
  if (!spec) warn(`${domain} isn't registered on this server — removing whatever is left of it`);

  step('Remove the site\'s scheduled tasks');
  await removePath(`/etc/cron.d/${domain.replace(/\./g, '_')}`);
  ok('Scheduled tasks removed');

  // Domain-scoped (lock path + site dir), so other sites' tasks keep running.
  step('Stop the site\'s background tasks');
  const patterns = [`/tmp/${domain}_cron-`, `${siteDir(domain)}/`];
  let pids = await findPidsMatching(patterns);
  if (pids.length > 0) {
    info(`Stopping ${pids.length} process(es)...`);
    killPids(pids, 'SIGTERM');
    await sleep(3000);
    pids = await findPidsMatching(patterns);
    if (pids.length > 0) {
      warn(`${pids.length} background task(s) did not stop on request — forcing them to close`);
      killPids(pids, 'SIGKILL');
    }
    ok('Background tasks stopped');
  } else {
    info('No running tasks found for this site');
  }
  await removeGlobLocks(domain);

  step('Remove the site, its database and certificates');
  await deleteSite(helpers, domain, spec);
  await clearChallenge(domain); // any pending manual DNS-01 challenge
  ok('Site removed');

  await systemctl(helpers, 'restart', 'cron');
  done(`${domain} has been deleted`);
}

// Remove /tmp/<domain>_cron-*.lock without a shell glob.
async function removeGlobLocks(domain) {
  const prefix = `${domain}_cron-`;
  let files;
  try { files = await fs.readdir('/tmp'); } catch { return; }
  await Promise.all(
    files
      .filter((f) => f.startsWith(prefix) && f.endsWith('.lock'))
      .map((f) => removePath(`/tmp/${f}`))
  );
}
