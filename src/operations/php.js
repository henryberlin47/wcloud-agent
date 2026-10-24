import { logger } from '../lib/log.js';
import { requireSpec, applySite } from '../lib/sites.js';
import { run } from '../lib/sys.js';
import { ensurePhp, installedPhp, fpmService, phpPackageVersions, phpPatch, upgradePhpPackages } from '../lib/stack.js';

// ============================================================
//  php — move a site to another PHP version
// ============================================================
// Installs the version if the server doesn't have it yet, then moves the
// site's pool from the old version's php-fpm to the new one in one tested
// transaction (the socket path doesn't change, so nginx isn't touched).
// A few seconds of 502s while the new pool starts is the whole downtime.
// ============================================================

// params: { domain, php }
export async function runPhp(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — it doesn't run PHP.`);
  if (s.php === p.php) { done(`${p.domain} already runs PHP ${p.php}`); return; }

  step(`Make PHP ${p.php} available`);
  await ensurePhp(helpers, p.php);
  ok(`PHP ${p.php} is ready`);

  step(`Move the site from PHP ${s.php} to PHP ${p.php}`);
  await applySite(helpers, { ...s, php: p.php }, { prevPhp: s.php });
  ok('PHP pool moved and reloaded');
  done(`${p.domain} now runs PHP ${p.php}`);
}

// ============================================================
//  phpupdate — security / patch releases of every installed PHP version
// ============================================================
// Upgrades every installed php* package (8.3.35 → 8.3.36; never 8.3 → 8.4 —
// sites keep their version), then reloads each PHP-FPM so it runs the new
// binary. A reload finishes requests in progress; sites don't go down.
// params: {}
export async function runPhpUpdate(job, helpers) {
  const { step, ok, info, done } = logger(helpers);
  const versions = await installedPhp();
  if (!versions.length) { done('No PHP installed on this server'); return; }
  const before = {};
  for (const v of versions) before[v] = phpPatch((await phpPackageVersions(helpers, v)).installed);

  step(`Upgrade the PHP packages (${versions.map((v) => `PHP ${before[v] || v}`).join(', ')})`);
  await upgradePhpPackages(helpers);
  ok('Packages up to date');

  step('Reload PHP-FPM');
  const changed = [];
  const h = { ...helpers, signal: undefined }; // the new binary must be loaded even if the job is cancelled now
  for (const v of versions) {
    const now = phpPatch((await phpPackageVersions(helpers, v)).installed);
    await run(h, 'systemctl', ['reload-or-restart', fpmService(v)], { timeout: 60_000 });
    let active = (await run(h, 'systemctl', ['is-active', fpmService(v)], { quiet: true, timeout: 10_000 })).stdout.trim() === 'active';
    if (!active) {
      await run(h, 'systemctl', ['restart', fpmService(v)], { timeout: 60_000 });
      active = (await run(h, 'systemctl', ['is-active', fpmService(v)], { quiet: true, timeout: 10_000 })).stdout.trim() === 'active';
    }
    if (!active) throw new Error(`PHP ${v} (PHP-FPM) didn't start after the upgrade — its sites are down. Check Server → Health.`);
    if (now && now !== before[v]) { changed.push(`${before[v] || v} → ${now}`); ok(`PHP ${before[v] || v} → ${now}`); }
    else info(`PHP ${now || v} was already the latest`);
  }
  done(changed.length ? `PHP updated: ${changed.join(', ')}` : 'PHP was already up to date');
}
