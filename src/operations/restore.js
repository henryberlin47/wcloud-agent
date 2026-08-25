import fs from 'node:fs/promises';
import { run, woSiteExists, removePath } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { runRestoreFromLocal } from './import.js';
import { runDelete } from './delete.js';
import { downloadFile, explainSpacesError } from '../lib/spaces.js';

// ============================================================
//  restore — bring a site back from a Spaces backup
// ============================================================
// Downloads the backup from Spaces, then runs the SAME restore path the
// migration import uses (runRestoreFromLocal). In-place restore (site exists)
// first tears it down with the full delete op — cron, procs, wo site (DB
// included), files, nginx, certs — so the rebuild starts clean. The portal
// job takes a safety backup of the current state before enqueueing this op.
// ============================================================

// params: { domain, sourceDomain, includeSsl, encryptKey, canonical, enableWww,
//           space, key, endpoint, accessKeyId, secretAccessKey }
export async function runRestore(job, helpers, p) {
  const { log, step, ok, err } = logger(helpers);
  const domain = p.domain;

  // In-place restore: destructive by design (safety snapshot was taken by the
  // caller). Reuse the delete op wholesale — do not copy its teardown logic.
  if (await woSiteExists(helpers, domain)) {
    step('Remove existing site (in-place restore)');
    await runDelete(job, helpers, { domain });
    ok(`${domain} removed — restoring from backup`);
  }

  const tmpDir = `/tmp/wcloud_restore_${Date.now()}`;
  await fs.mkdir(tmpDir, { recursive: true, mode: 0o700 });
  await run(helpers, 'chown', ['www-data:www-data', tmpDir], { timeout: 30000 });

  step('Download backup from Spaces');
  try {
    try {
      await downloadFile(p, p.key, `${tmpDir}/export.tar.gz.enc`);
    } catch (e) {
      const why = explainSpacesError(e, p);
      err(`download failed: ${why}`);
      throw new Error(`Spaces download failed — ${why}`);
    }
    ok('Backup downloaded');
  } catch (e) {
    await removePath(tmpDir);
    throw e;
  }

  await runRestoreFromLocal(job, helpers, {
    tmpDir,
    domain,
    sourceDomain: p.sourceDomain,
    includeSsl: p.includeSsl,
    encryptKey: p.encryptKey,
    canonical: p.canonical,
    enableWww: p.enableWww,
  });
}
