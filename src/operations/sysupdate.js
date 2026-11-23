import { logger } from '../lib/log.js';
import { run, withLock, nginxTest, pathExists } from '../lib/sys.js';
import { installUpdates, setAutoSecurity, scheduleReboot, REBOOT_FILE } from '../lib/updates.js';
import { nginxRunsCurrentBinary } from '../lib/stack.js';
import { listJobs } from '../jobs.js';

// ============================================================
//  sysupdate — OS updates, automatic security updates, reboot (lib/updates.js)
// ============================================================
// params: { install?: 'security' | 'all', auto?: bool, reboot?: bool } — each part only when given.
// Afterwards whatever still runs a replaced binary or library is restarted:
// nginx by hand (after `nginx -t`, as nginxupdate does), the rest by
// needrestart. needrestart never restarts the unit it runs in (this agent), so
// running jobs survive.
export async function runSysUpdate(job, helpers, p) {
  const { step, ok, warn, done } = logger(helpers);
  const did = [];
  if (p.install) {
    step(p.install === 'security' ? 'Install the security updates' : 'Install all updates');
    const names = await installUpdates(helpers, p.install);
    ok(names.length ? `${names.length} package${names.length === 1 ? '' : 's'} updated: ${names.slice(0, 20).join(', ')}${names.length > 20 ? ', …' : ''}` : 'Nothing to install — everything is current');
    did.push(names.length ? `${names.length} package${names.length === 1 ? '' : 's'} updated` : 'nothing to install');
    step('Run the installed versions');
    await restartServices(helpers, { ok, warn });
    if (await pathExists(REBOOT_FILE)) warn('A reboot is still needed to finish (a new kernel or core library). Reboot when it suits the sites.');
  }
  if (typeof p.auto === 'boolean') {
    step(p.auto ? 'Turn on automatic security updates' : 'Turn off automatic security updates');
    await setAutoSecurity(helpers, p.auto);
    ok(p.auto ? 'Security updates install every day on their own' : 'Nothing installs by itself any more');
    did.push(p.auto ? 'automatic security updates on' : 'automatic security updates off');
  }
  if (p.reboot) {
    step('Reboot in one minute');
    // Like POST /api/reboot: never under another job (a restore or import cut off mid-way). This job itself is running.
    if (listJobs().some((j) => j.id !== job.id && (j.state === 'queued' || j.state === 'running'))) throw new Error('Another operation is running on this server — reboot once it finishes.');
    const r = await scheduleReboot(helpers);
    if (r.code !== 0) throw new Error('The reboot could not be scheduled (see the log above).');
    ok('Reboot scheduled — the sites are down for a minute or two');
    did.push('reboot scheduled');
  }
  done(did.length ? `Updates: ${did.join(', ')}` : 'Nothing to change');
}

// needrestart restarts a service that still runs a replaced library WITHOUT
// testing nginx's config. So it is run only when `nginx -t` passes, and nginx
// is restarted here first when its binary was replaced.
async function restartServices(helpers, { ok, warn }) {
  await withLock('config', async () => {
    const nginx = await nginxRunsCurrentBinary(); // null = not running
    if (nginx !== null && !(await nginxTest(helpers))) {
      warn('nginx keeps running what it had: its configuration doesn\'t pass `nginx -t`, so no service was restarted.');
      return;
    }
    if (nginx === false) {
      const r = await run(helpers, 'systemctl', ['restart', 'nginx'], { timeout: 60_000 });
      if (r.code !== 0) throw new Error('nginx didn\'t start on the new build — sites are down. Check Server → Health.');
      ok('nginx restarted on the new build');
    }
    if (!(await pathExists('/usr/sbin/needrestart'))) {
      warn('needrestart isn\'t installed, so services still on old libraries keep them until a restart or reboot.');
      return;
    }
    const r = await run(helpers, 'needrestart', ['-r', 'a', '-b'], { quiet: true, timeout: 900_000 });
    if (r.code === 0) ok('Services still on old libraries restarted (needrestart)');
    else warn('needrestart did not finish — services may still run old libraries.');
  });
}
