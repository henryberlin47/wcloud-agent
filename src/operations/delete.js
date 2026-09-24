import fs from 'node:fs/promises';
import config from '../config.js';
import {
  pathExists, removePath, findPidsMatching, killPids, sleep,
  nginxTest, nginxReload, systemctl, woSiteDelete, woSiteExists,
} from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { CRT, KEY, SSL_CONF } from '../lib/panelcert.js';
import { clearChallenge } from '../lib/acmedns.js';

// ============================================================
//  delete — permanently remove a WordPress site
// ============================================================
// Permanently removes a site: cron file, running cron procs, lock files,
// WordOps site, site dir, nginx config, LE certs; then validates + reloads
// nginx and restarts cron. Domain-scoped process kill leaves other sites alone.
// ============================================================

// params: { domain }   (confirm:true is enforced in validate())
export async function runDelete(job, helpers, p, opts = {}) {
  const { step, info, ok, warn, err, done } = logger(helpers, opts);
  const domain = p.domain;

  const SITE_DIR = `${config.wwwDir}/${domain}`;
  const CRON_FILE = `/etc/cron.d/${domain.replace(/\./g, '_')}`;
  const NGINX_AVAILABLE = `/etc/nginx/sites-available/${domain}`;
  const NGINX_ENABLED = `/etc/nginx/sites-enabled/${domain}`;

  // 1) Remove the cron schedule FIRST so nothing new spawns mid-teardown.
  step('Remove the site\'s scheduled tasks');
  await removePath(CRON_FILE);
  ok('Scheduled tasks removed');

  // 2) Stop this domain's running cron processes (TERM, wait, then KILL).
  //    Match on the domain lock path and the site dir so we catch the flock
  //    holder, the cd'd bash, and its php/wp children — domain-scoped.
  step('Stop the site\'s background tasks');
  const patterns = [`/tmp/${domain}_cron-`, `${SITE_DIR}/`];
  let pids = await findPidsMatching(patterns);
  if (pids.length > 0) {
    info(`Sending SIGTERM to ${pids.length} process(es)...`);
    killPids(pids, 'SIGTERM');
    await sleep(3000);
    pids = await findPidsMatching(patterns);
    if (pids.length > 0) {
      warn(`${pids.length} background task(s) did not stop on request — forcing them to close`);
      killPids(pids, 'SIGKILL');
    }
    ok('Background tasks stopped');
  } else {
    info('No running cron processes found for this domain');
  }

  // 3) Clear lock files.
  step('Clear leftover lock files');
  await removeGlobLocks(domain);
  ok('Lock files cleared');

  // 4) Delete the WordOps site. Check existence first so we can tell a real
  //    failure apart from "already gone", and verify it's actually removed.
  step('Remove the site from this server');
  const existedBefore = await woSiteExists(helpers, domain);
  if (existedBefore) {
    await woSiteDelete(helpers, domain);
    // Verify it's actually gone from WordOps' registry.
    const stillThere = await woSiteExists(helpers, domain);
    if (stillThere) {
      warn(`${domain} could not be fully removed from the server's site registry.`);
      warn(`Run manually: wo site delete ${domain} --no-prompt --force`);
    } else {
      ok('Site removed from the server');
    }
  } else {
    info('Not registered in WordOps (or already removed)');
  }

  // 5) Remove website files.
  step('Delete the site files and certificates');
  await removePath(SITE_DIR);
  ok('Site files deleted');

  // 6) Remove nginx config (enabled symlink + available file).
  await removePath(NGINX_ENABLED);
  await removePath(NGINX_AVAILABLE);
  ok('Web server configuration removed');

  // 7) Remove Let's Encrypt cert material, if present.
  await removePath(`/etc/letsencrypt/live/${domain}`);
  await removePath(`/etc/letsencrypt/archive/${domain}`);
  await removePath(`/etc/letsencrypt/renewal/${domain}.conf`);
  await removePath(`/etc/letsencrypt/renewal/${domain}_ecc`); // acme.sh v3 (ECC default)
  await clearChallenge(domain); // any pending manual DNS-01 challenge
  ok('HTTPS certificates removed');

  // 7b) If the WordOps admin panel (:22222) was pointed at THIS domain's cert
  //     (via `wo secure`), that reference is now dangling and would break
  //     `nginx -t` server-wide. Repoint it to the panel's self-signed cert.
  await repointAdminPanelCert(domain, { info, ok, warn });


  // 8) Validate + reload nginx, restart cron.
  step('Reload the web server');
  if (await nginxTest(helpers)) {
    ok('Web server configuration is valid');
    await nginxReload(helpers);
    ok('Web server reloaded');
  } else {
    // Don't throw — the site is already gone; surface it loudly instead.
    err('The web server configuration is invalid after removing this site. Other sites keep running on the old configuration until it is fixed.');
  }
  await systemctl(helpers, 'restart', 'cron');
  ok('Scheduled-task service restarted');

  done(`${domain} has been deleted`);
}

// If the :22222 admin panel's ssl.conf references the just-deleted domain's LE
// cert, rewrite it to use the panel's self-signed cert so nginx stays valid.
async function repointAdminPanelCert(domain, { warn, ok }) {
  if (!(await pathExists(SSL_CONF))) return; // panel not installed
  let conf;
  try { conf = await fs.readFile(SSL_CONF, 'utf8'); } catch { return; }
  if (!conf.includes(`/etc/letsencrypt/live/${domain}/`)) return; // panel isn't using this cert

  if (!(await pathExists(CRT)) || !(await pathExists(KEY))) {
    warn(`:22222 panel used the deleted ${domain} cert, but its self-signed cert is missing (${CRT}) — left as-is; fix manually`);
    return;
  }
  await fs.writeFile(SSL_CONF, `ssl_certificate     ${CRT};\nssl_certificate_key ${KEY};\n`);
  ok(`:22222 admin panel repointed to self-signed cert (was using deleted ${domain})`);
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
