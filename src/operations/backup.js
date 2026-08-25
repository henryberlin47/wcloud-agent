import fs from 'node:fs/promises';
import { run, woSiteExists, removePath } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { buildSiteArchive } from './export.js';
import { uploadFile, explainSpacesError } from '../lib/spaces.js';

// ============================================================
//  backup — encrypted site archive uploaded straight to Spaces
// ============================================================
// Same archive as the export op (shared buildSiteArchive), but the transport is
// a direct S3 upload instead of one-time HTTP serving. The portal's durable job
// passes the per-user Spaces creds per call; they live in the S3 client for that
// one transfer and are never logged or persisted here.
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
    nested: true, // step 1 above is the section; these are its details
  });
  ok('Archive built');

  try {
    step('Upload to Spaces');
    try {
      await uploadFile(p, p.key, archivePath);
    } catch (e) {
      const why = explainSpacesError(e, p);
      err(`upload failed: ${why}`);
      throw new Error(`Spaces upload failed — ${why}`);
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
