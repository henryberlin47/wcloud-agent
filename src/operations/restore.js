import { run, removePath } from '../lib/sys.js';
import { readSpec } from '../lib/sites.js';
import { logger } from '../lib/log.js';
import { runRestoreFromLocal, makeStagingDir, prepareArchive, RESTORING_RULE } from './import.js';
import { runDelete } from './delete.js';
import { downloadFile, explainSpacesError } from '../lib/spaces.js';
import { listRules, saveRule } from '../lib/nginxrules.js';

// ============================================================
//  restore — bring a site back from a Spaces backup
// ============================================================
// Downloads the backup from Spaces, then runs the SAME restore path the
// migration import uses (runRestoreFromLocal). In-place restore (site exists)
// tears it down with the full delete op — cron, procs, database, files,
// nginx, PHP pool, certs — so the rebuild starts clean. Everything that can fail
// for reasons unrelated to the site (download, wrong key, corrupt archive)
// happens BEFORE that delete, so those failures leave the live site untouched.
// The portal job also takes a safety backup before enqueueing this op — when
// it saw a site here. When it did not (replace: false) no snapshot exists, so a
// site that appeared since is never deleted: the op refuses.
// ============================================================

// params: { domain, sourceDomain, includeSsl, encryptKey, canonical, enableWww, replace,
//           space, key, endpoint, accessKeyId, secretAccessKey, cfToken?, cfZoneId? }
export async function runRestore(job, helpers, p) {
  const { step, ok, warn, err } = logger(helpers);
  const domain = p.domain;
  // The live site's custom nginx rules, put back after an in-place restore:
  // the delete takes them, and nginx config is never read from an archive.
  let rules = [];

  // Jobs on one domain never overlap (jobs.js), so this answer holds for the whole run.
  if (p.replace === false && await readSpec(domain)) {
    throw new Error(`${domain} already exists on this server — it was not replaced.`);
  }

  const tmpDir = await makeStagingDir(helpers, 'restore');
  try {
    step('Download the backup from your storage');
    try {
      await downloadFile(p, p.key, `${tmpDir}/export.tar.gz.enc`, { signal: helpers.signal });
    } catch (e) {
      if (helpers.signal?.aborted) throw e; // cancel/timeout, not a Spaces problem
      const why = explainSpacesError(e, p);
      err(`Download failed — ${why}`);
      throw new Error(`Spaces download failed — ${why}`);
    }
    ok('Backup downloaded');

    await prepareArchive(helpers, tmpDir, p.encryptKey, { step, ok });

    // In-place restore: destructive by design. Verify the whole gzip stream
    // first (CRC over every byte) so a truncated/corrupt backup can't take
    // the live site down with it. Reuse the delete op wholesale.
    if (p.replace !== false && await readSpec(domain)) {
      step('Verify the backup before replacing the current site');
      const t = await run(helpers, 'gzip', ['-t', `${tmpDir}/export.tar.gz`]);
      if (t.code !== 0) throw new Error('The backup archive is corrupted — the current site was left untouched.');
      ok('Backup verified');

      step('Remove the current site before restoring over it');
      // Not the "restore in progress" rule an interrupted restore left behind:
      // put back at the end, it would keep the restored site closed.
      rules = (await listRules(domain)).filter((r) => r.id !== RESTORING_RULE);
      await runDelete(job, helpers, { domain });
      ok(`${domain} removed — restoring from backup`);
    }
  } catch (e) {
    await removePath(tmpDir);
    throw e;
  }

  // Owns tmpDir cleanup from here on. The archive is already plaintext, so
  // prepareArchive inside it is a no-op.
  await runRestoreFromLocal(job, helpers, {
    tmpDir,
    domain,
    sourceDomain: p.sourceDomain,
    includeSsl: p.includeSsl,
    encryptKey: p.encryptKey,
    canonical: p.canonical,
    enableWww: p.enableWww,
    cfToken: p.cfToken, cfZoneId: p.cfZoneId,
    nested: true, // this op already numbered its own steps
  });

  if (rules.length) {
    step('Put the custom nginx rules back');
    // One that nginx refuses now must not cost the restored site: warn, keep going.
    for (const r of rules) {
      try { await saveRule(helpers, domain, r); ok(`Rule "${r.name}" restored`); }
      catch (e) { warn(`The custom rule "${r.name}" was not restored (${e.message}) — add it again on the Redirects & rules tab`); }
    }
  }
}
