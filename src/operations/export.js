import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import { publicUrl } from '../config.js';
import { run, pathExists, removePath } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { requireSpec, publicSpec, siteDir, siteTmp } from '../lib/sites.js';
import { wpCli } from '../lib/wp.js';
import { makeStagingDir } from './import.js';

// Temporary export archives and their one-time tokens.
const exports = new Map();

// Archives hold a DB dump, wp-config and possibly TLS keys. Pre-create each one
// exclusively (O_EXCL: fails on an existing path or planted symlink) as 0600;
// tar/openssl then write into it and keep that mode. Root's default umask would
// otherwise leave it world-readable in /tmp until it's served or uploaded.
async function createPrivateFile(p) {
  await (await fs.open(p, 'wx', 0o600)).close();
}

// Build the site archive (DB dump + files + optional SSL), encrypting it when
// an encryptKey is given. Shared by the export op (served over HTTP) and the
// backup op (uploaded to Spaces) — one implementation, two transports.
//
// params: { domain, includeSsl?: boolean, encryptKey?: string, nested?: boolean }
// nested=true when the caller already numbered a step for this (backup does);
// its stages then render as indented detail instead of restarting at 1.
// returns: { path }  (encrypted `<path>.enc` when encryptKey is non-empty)
// The caller owns the returned path and must remove it when done.
export async function buildSiteArchive(helpers, domain, { includeSsl = false, encryptKey = '', nested = false } = {}) {
  const { step, ok } = logger(helpers, { nested });
  const s = await requireSpec(domain);
  const tmpDir = await makeStagingDir(helpers, 'export'); // root-only 0700
  const archivePath = `${tmpDir}.tar.gz`;
  // Type + PHP version travel with the archive, so a restore rebuilds the same site.
  await fs.writeFile(`${tmpDir}/wcloud-site.json`, JSON.stringify(publicSpec(s), null, 2));

  // 1) Dump the database. wp-cli runs as the site's user, so it writes into
  //    the site's own tmp dir; root then moves the dump into staging.
  if (s.type === 'wordpress') {
    step('Export the database');
    const dump = `${siteTmp(domain)}/wcloud-export-${crypto.randomBytes(6).toString('hex')}.sql`;
    const dbDump = await (await wpCli(helpers, s))(['db', 'export', dump]);
    if (dbDump.code !== 0 || (await run(helpers, 'mv', ['--', dump, `${tmpDir}/db.sql`])).code !== 0) {
      await removePath(dump);
      await removePath(tmpDir);
      throw new Error('Database export failed');
    }
    ok('Database exported');
  }

  // 2) Copy the site files (root, reading everything).
  step('Copy the site files');
  const destSite = `${tmpDir}/site`;
  const cpR = await run(helpers, 'cp', ['-a', siteDir(domain), destSite]);
  if (cpR.code !== 0) {
    // A partial copy would still archive and upload "successfully" — a
    // silently incomplete restore point.
    await removePath(tmpDir);
    throw new Error('Copying the site files failed — the disk may be full.');
  }
  // Sessions, uploads in flight and caches don't belong in a restore point.
  for (const dir of ['tmp', 'htdocs/wp-content/cache', 'htdocs/app/cache']) {
    await removePath(`${destSite}/${dir}`);
  }
  ok('Site files copied');

  // 3) Copy SSL certs + nginx config if requested.
  if (includeSsl) {
    // Cert material only: restore regenerates ssl.conf itself and never
    // trusts an archived renewal.conf, so neither is packed.
    step('Copy the HTTPS certificates');
    const sslLive = `/etc/letsencrypt/live/${domain}`;
    const sslArchive = `/etc/letsencrypt/archive/${domain}`;
    const sslDest = `${tmpDir}/ssl`;
    await fs.mkdir(sslDest, { recursive: true });

    if (await pathExists(sslLive)) {
      await run(helpers, 'cp', ['-a', sslLive, `${sslDest}/live`]);
    }
    if (await pathExists(sslArchive)) {
      await run(helpers, 'cp', ['-a', sslArchive, `${sslDest}/archive`]);
    }
    ok('Certificates copied');
  }

  // 4) Create tarball.
  step('Compress everything into one archive');
  await createPrivateFile(archivePath);
  const tarR = await run(helpers, 'tar', ['czf', archivePath, '-C', tmpDir, '.']);
  await removePath(tmpDir);
  if (tarR.code !== 0) {
    await removePath(archivePath);
    throw new Error('Archive creation failed');
  }

  // 5) Encrypt archive if key provided.
  if (encryptKey) {
    step('Encrypt the archive');
    const encryptedPath = `${archivePath}.enc`;
    await createPrivateFile(encryptedPath);
    const encR = await run(helpers, 'openssl', [
      'enc', '-aes-256-cbc', '-pbkdf2',
      '-pass', `env:ENC_KEY`,
      '-in', archivePath,
      '-out', encryptedPath,
    ], { env: { ENC_KEY: encryptKey } });
    if (encR.code !== 0) {
      await removePath(archivePath);
      await removePath(encryptedPath);
      throw new Error('Archive encryption failed');
    }
    await removePath(archivePath);
    ok('Archive encrypted');
  }

  return { path: encryptKey ? `${archivePath}.enc` : archivePath };
}

// params: { domain, includeSsl: boolean, encryptKey: string }
export async function runExport(job, helpers, p) {
  const { log, ok } = logger(helpers);
  const domain = p.domain;

  const { path: finalPath } = await buildSiteArchive(helpers, domain, {
    includeSsl: p.includeSsl,
    encryptKey: p.encryptKey,
  });

  // 6) Register for serving.
  const token = crypto.randomUUID();
  const expires = Date.now() + 3600_000;
  exports.set(token, { path: finalPath, expires });
  cleanupExports();
  // A never-downloaded archive (DB dump + keys) must not outlive its token just
  // because no later export runs cleanupExports.
  setTimeout(cleanupExports, 3600_000 + 1000).unref();

  const fetchUrl = `${publicUrl()}/api/export/${token}`;

  // Return URL as job result (not logged — token is secret).
  job.result = { url: fetchUrl, token, localArchive: finalPath };
  ok('Export ready');
  log(`Export completed: ${domain}`);
}

export async function serveExport(token, res) {
  const entry = exports.get(token);
  if (!entry) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
    return;
  }

  if (Date.now() > entry.expires) {
    exports.delete(token);
    await removePath(entry.path);
    res.writeHead(410, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'expired' }));
    return;
  }

  exports.delete(token);
  const stat = fsSync.statSync(entry.path);
  const readStream = fsSync.createReadStream(entry.path);

  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': stat.size,
    'Cache-Control': 'no-store',
  });

  readStream.pipe(res);
  readStream.on('close', async () => {
    await removePath(entry.path);
  });
}

function cleanupExports() {
  const now = Date.now();
  for (const [token, entry] of exports.entries()) {
    if (now > entry.expires) {
      exports.delete(token);
      removePath(entry.path).catch(() => {});
    }
  }
}
