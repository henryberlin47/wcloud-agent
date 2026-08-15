import fs from 'node:fs/promises';
import config from '../config.js';
import {
  run, pathExists, removePath, findPidsMatching, killPids, sleep,
  nginxTest, nginxReload, systemctl, woSiteDelete, woSiteExists,
} from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { CRT, KEY, SSL_CONF } from '../lib/panelcert.js';

// ============================================================
//  delete — permanently remove a WordPress site
// ============================================================
// Permanently removes a site: cron file, running cron procs, lock files,
// WordOps site, site dir, nginx config, LE certs; then validates + reloads
// nginx and restarts cron. Domain-scoped process kill leaves other sites alone.
// ============================================================

// params: { domain }   (confirm:true is enforced in validate())
export async function runDelete(job, helpers, p, opts = {}) {
  const { log, step, info, ok, warn, err } = logger(helpers, opts);
  const domain = p.domain;

  const SITE_DIR = `${config.wwwDir}/${domain}`;
  const CRON_FILE = `/etc/cron.d/${domain.replace(/\./g, '_')}`;
  const NGINX_AVAILABLE = `/etc/nginx/sites-available/${domain}`;
  const NGINX_ENABLED = `/etc/nginx/sites-enabled/${domain}`;

  // 1) Remove the cron schedule FIRST so nothing new spawns mid-teardown.
  step('Remove cron schedule');
  await removePath(CRON_FILE);
  ok(`Removed ${CRON_FILE}`);

  // 2) Stop this domain's running cron processes (TERM, wait, then KILL).
  //    Match on the domain lock path and the site dir so we catch the flock
  //    holder, the cd'd bash, and its php/wp children — domain-scoped.
  step('Stop running cron processes');
  const patterns = [`/tmp/${domain}_cron-`, `${SITE_DIR}/`];
  let pids = await findPidsMatching(patterns);
  if (pids.length > 0) {
    info(`Sending SIGTERM to ${pids.length} process(es)...`);
    killPids(pids, 'SIGTERM');
    await sleep(3000);
    pids = await findPidsMatching(patterns);
    if (pids.length > 0) {
      warn(`Force-killing ${pids.length} straggler(s) with SIGKILL`);
      killPids(pids, 'SIGKILL');
    }
    ok('Running cron processes stopped');
  } else {
    info('No running cron processes found for this domain');
  }

  // 3) Clear lock files.
  step('Clear lock files');
  await removeGlobLocks(domain);
  ok('Lock files cleared');

  // 4) Delete the WordOps site. Check existence first so we can tell a real
  //    failure apart from "already gone", and verify it's actually removed.
  step('Delete the WordOps site');
  const existedBefore = await woSiteExists(helpers, domain);
  if (existedBefore) {
    const res = await woSiteDelete(helpers, domain);
    // Verify it's actually gone from WordOps' registry.
    const stillThere = await woSiteExists(helpers, domain);
    if (stillThere) {
      warn(`wo site delete returned code ${res.code} but ${domain} is STILL in WordOps.`);
      warn(`Run manually: wo site delete ${domain} --no-prompt --force`);
    } else {
      ok('WordOps site deleted');
    }
  } else {
    info('Not registered in WordOps (or already removed)');
  }

  // 5) Remove website files.
  step('Remove site files, nginx config and certs');
  await removePath(SITE_DIR);
  ok(`Removed ${SITE_DIR}`);

  // 6) Remove nginx config (enabled symlink + available file).
  await removePath(NGINX_ENABLED);
  await removePath(NGINX_AVAILABLE);
  ok('Nginx config removed');

  // 7) Remove Let's Encrypt cert material, if present.
  await removePath(`/etc/letsencrypt/live/${domain}`);
  await removePath(`/etc/letsencrypt/archive/${domain}`);
  await removePath(`/etc/letsencrypt/renewal/${domain}.conf`);
  ok('Certificate files cleared');

  // 7b) If the WordOps admin panel (:22222) was pointed at THIS domain's cert
  //     (via `wo secure`), that reference is now dangling and would break
  //     `nginx -t` server-wide. Repoint it to the panel's self-signed cert.
  await repointAdminPanelCert(domain, { info, ok, warn });


  // 8) Validate + reload nginx, restart cron.
  step('Validate + reload nginx, restart cron');
  if (await nginxTest(helpers)) {
    ok('nginx -t passed');
    await nginxReload(helpers);
    ok('nginx reloaded');
  } else {
    // Don't throw — the site is already gone; surface it loudly instead.
    err('nginx -t FAILED after removal — review config before next reload');
  }
  await systemctl(helpers, 'restart', 'cron');
  ok('cron restarted');

  log(`Delete completed for ${domain}`);
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
