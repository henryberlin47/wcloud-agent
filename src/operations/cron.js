import fs from 'node:fs/promises';
import { logger } from '../lib/log.js';
import { run, userIds } from '../lib/sys.js';
import { requireSpec, applySite, webRoot, siteTmp } from '../lib/sites.js';
import { wpCli, setWpConstant } from '../lib/wp.js';
import { cleanJob, CRON_MAX, cronLogPath, ensureWrappers, jobEnv } from '../lib/cron.js';

// ============================================================
//  cron — a WordPress site's scheduled jobs (lib/cron.js)
// ============================================================
// params: { domain, action: 'save' | 'delete' | 'run' | 'wpcron', job?, id?, wpCron?, every? }
// save/delete/wpcron change the spec and re-render /etc/cron.d via applySite;
// run executes a job once, now, exactly as cron would (site user, htdocs, the
// site's php/wp) and shows its output.
// ============================================================

const RUN_TIMEOUT = 15 * 60_000;

export async function runCron(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — cron jobs are for WordPress sites.`);
  const jobs = Array.isArray(s.crons) ? s.crons : [];
  // The daemon that reads /etc/cron.d — enabled by init.sh; idempotent, so
  // servers set up before cron jobs existed are covered too.
  if (p.action !== 'run') await run(helpers, 'systemctl', ['enable', '--now', 'cron'], { quiet: true, timeout: 30_000 });

  if (p.action === 'save') {
    const existing = jobs.find((j) => j.id === p.job.id);
    const { job: j, error } = cleanJob(p.job, jobs.filter((x) => x !== existing).map((x) => x.id));
    if (error) throw new Error(error);
    if (!existing && jobs.length >= CRON_MAX) throw new Error(`A site can have ${CRON_MAX} cron jobs at most.`);
    step(`${existing ? 'Update' : 'Add'} the cron job "${j.name}" (${j.schedule})${j.enabled ? '' : ' — paused'}`);
    await applySite(helpers, { ...s, crons: existing ? jobs.map((x) => (x === existing ? j : x)) : [...jobs, j] });
    job.result = { id: j.id };
    ok('Scheduled');
    return done(`Cron job "${j.name}" saved`);
  }

  if (p.action === 'delete') {
    const j = jobs.find((x) => x.id === p.id);
    if (!j) throw new Error('That cron job no longer exists.');
    step(`Delete the cron job "${j.name}"`);
    await applySite(helpers, { ...s, crons: jobs.filter((x) => x !== j) });
    return done('Cron job deleted');
  }

  if (p.action === 'wpcron') {
    const server = p.wpCron === 'server';
    step(server ? `Run WordPress's scheduled tasks from the server every ${p.every} minute${p.every === 1 ? '' : 's'}` : 'Let visitors trigger WordPress\'s scheduled tasks (WordPress default)');
    if (server) {
      if (!(await setWpConstant(helpers, s, 'DISABLE_WP_CRON', 'true'))) throw new Error('Could not update wp-config.php — is WordPress working on this site?');
    } else {
      await (await wpCli(helpers, s))(['config', 'delete', 'DISABLE_WP_CRON', '--type=constant'], { quiet: true, timeout: 60_000 });
    }
    await applySite(helpers, { ...s, wpCron: server ? 'server' : 'wordpress', wpCronEvery: p.every });
    ok(server ? 'DISABLE_WP_CRON set; the server runs due events' : 'DISABLE_WP_CRON removed');
    return done('WordPress cron updated');
  }

  // run
  const j = jobs.find((x) => x.id === p.id);
  if (!j) throw new Error('That cron job no longer exists.');
  step(`Run "${j.name}" now`);
  await ensureWrappers(s.php);
  const { uid, gid } = await userIds(s.user);
  const r = await run(helpers, '/bin/sh', ['-c', j.command], {
    cwd: webRoot(s.domain), as: { uid, gid, home: siteTmp(s.domain) }, env: jobEnv(s), quiet: true, timeout: RUN_TIMEOUT,
  });
  const out = `${r.stdout}${r.stderr ? `\n${r.stderr}` : ''}`.trim();
  const lines = out ? out.split('\n') : [];
  for (const l of lines.slice(-200)) helpers.log(`   ${l}`);
  if (lines.length > 200) helpers.log(`   … ${lines.length - 200} earlier lines not shown`);
  // Same record as a scheduled run, so the Logs tab shows it too.
  await fs.appendFile(cronLogPath(s.domain), `=== ${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC — ${j.id} (run now)\n${out ? `${out}\n` : ''}`).catch(() => {});
  if (r.timedOut) throw new Error(`"${j.name}" was stopped after ${RUN_TIMEOUT / 60_000} minutes.`);
  if (r.code !== 0) throw new Error(`"${j.name}" exited with code ${r.code}.`);
  ok(`Finished (exit code 0)${out ? '' : ' — no output'}`);
  done(`"${j.name}" ran`);
}
