import { logger } from '../lib/log.js';
import { run, withLock, nginxTest } from '../lib/sys.js';
import { nginxPackageVersions, upgradeNginxPackages, nginxRunsCurrentBinary } from '../lib/stack.js';

// ============================================================
//  nginxupdate — the newest nginx build Ubuntu has (security fixes)
// ============================================================
// Upgrades every installed nginx package (binary + modules) and makes sure
// the RUNNING nginx is that build: a package upgrade replaces the binary on
// disk, but a master started earlier (also by unattended-upgrades) keeps
// running the old one until it is restarted — a reload doesn't swap it.
// The restart cuts open connections for about a second; visitors retry.
// params: {}
export async function runNginxUpdate(job, helpers) {
  const { step, ok, info, done } = logger(helpers);
  const before = (await nginxPackageVersions(helpers)).installed;
  step(`Upgrade the nginx packages (${before || 'version unknown'})`);
  await upgradeNginxPackages(helpers);
  const after = (await nginxPackageVersions(helpers)).installed;
  ok(after && after !== before ? `nginx ${before} → ${after}` : `nginx ${after} is already the newest build Ubuntu has`);

  step('Run the installed build');
  const h = { ...helpers, signal: undefined }; // once the binary is replaced, nginx must end up on it even if the job is cancelled
  let restarted = false;
  await withLock('config', async () => {
    if (!(await nginxTest(h))) throw new Error('The nginx configuration doesn\'t pass `nginx -t` with the new build (see the log above) — nginx keeps running as it was.');
    if ((await nginxRunsCurrentBinary()) !== true) {
      const r = await run(h, 'systemctl', ['restart', 'nginx'], { timeout: 60_000 });
      if (r.code !== 0) throw new Error('nginx didn\'t start on the new build — sites are down. Check Server → Health.');
      restarted = true;
    }
    if ((await nginxRunsCurrentBinary()) !== true) throw new Error('nginx isn\'t running the installed build after a restart — check Server → Health.');
  });
  ok(restarted ? 'nginx restarted on the installed build' : 'nginx already runs the installed build');
  const v = await run(h, 'nginx', ['-v'], { quiet: true, timeout: 10_000 });
  info((v.stderr || v.stdout).trim());
  done(after && after !== before ? `nginx updated: ${before} → ${after}` : restarted ? `nginx ${after} is now running (it was installed but not loaded)` : `nginx ${after} was already up to date`);
}
