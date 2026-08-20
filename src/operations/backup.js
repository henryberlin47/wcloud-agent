import fs from 'node:fs/promises';
import { run, woSiteExists, removePath } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { buildSiteArchive } from './export.js';
import { ensureRclone, spacesEnv, remotePath } from '../lib/spaces.js';

// ============================================================
//  backup — encrypted site archive uploaded straight to Spaces
// ============================================================
// Same archive as the export op (shared buildSiteArchive), but the transport
// is rclone instead of one-time HTTP serving. The portal's durable job passes
// the per-user Spaces creds per call; they live in this subprocess's env
// only and are never logged or persisted here.
// ============================================================

// params: { domain, includeSsl, encryptKey, space, key, endpoint, accessKeyId, secretAccessKey }
export async function runBackup(job, helpers, p) {
  const { log, step, ok, err } = logger(helpers);

  if (!(await woSiteExists(helpers, p.domain))) {
    throw new Error(`Site not found: ${p.domain}`);
  }

  step('Build encrypted archive');
  const { path: archivePath } = await buildSiteArchive(helpers, p.domain, {
    includeSsl: p.includeSsl,
    encryptKey: p.encryptKey,
  });
  ok('Archive built');

  try {
    step('Upload to Spaces');
    await ensureRclone(helpers);
    const up = await run(helpers, 'rclone', ['copyto', archivePath, remotePath(p.space, p.key)],
      { env: spacesEnv(p), quiet: true, timeout: 11 * 3600_000 });
    if (up.code !== 0) {
      err(`rclone upload failed: ${(up.stderr || up.stdout).trim().slice(-300)}`);
      throw new Error('Spaces upload failed');
    }
    const stat = await fs.stat(archivePath);
    ok(`Uploaded (${stat.size} bytes)`);

    // Result is read by the portal job (size for the backups row). Never logged.
    job.result = { key: p.key, size: stat.size };
    log(`Backup complete: ${p.domain}`);
  } finally {
    await removePath(archivePath);
  }
}
