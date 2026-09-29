import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { publicUrl } from '../config.js';
import { run, pathExists, removePath } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { requireSpec, publicSpec, siteDir, siteTmp } from '../lib/sites.js';
import { wpCli } from '../lib/wp.js';
import { objectCacheActive } from '../lib/cache.js';
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

// An archive's name is random on its own, never built from a name that is
// already in /tmp (the staging dir, the plain archive): /tmp is listable, and a
// site that creates `<that name>.tar.gz` first makes every export on the
// server fail.
const archiveName = (ext) => `/tmp/wcloud_export_${crypto.randomBytes(16).toString('hex')}${ext}`;

// Build the site archive (DB dump + files + optional SSL), encrypting it when
// an encryptKey is given. Shared by the export op (served over HTTP) and the
// backup op (uploaded to Spaces) — one implementation, two transports.
//
// params: { domain, includeSsl?: boolean, encryptKey?: string, nested?: boolean }
// nested=true when the caller already numbered a step for this (backup does);
// its stages then render as indented detail instead of restarting at 1.
// returns: { path }  (the encrypted archive when encryptKey is non-empty)
// The caller owns the returned path and must remove it when done.
export async function buildSiteArchive(helpers, domain, opts = {}) {
  const s = await requireSpec(domain);
  const tmpDir = await makeStagingDir(helpers, 'export'); // root-only 0700
  const dump = `${siteTmp(domain)}/wcloud-export-${crypto.randomBytes(6).toString('hex')}.sql`;
  const archivePath = archiveName('.tar.gz');
  const encryptedPath = archiveName('.tar.gz.enc');
  try {
    return await packSite(helpers, domain, s, { ...opts, tmpDir, dump, archivePath, encryptedPath });
  } catch (e) {
    // A cancel or a timeout throws out of whichever step was running, and
    // nothing else ever clears /tmp: remove the half-made copy of the site here.
    await fs.unlink(dump).catch(() => {}); // in the site's tmp/: never a recursive delete as root
    // Staging may hold what the site made of its dump: a directory it still has
    // a process in. rm walks by file descriptor; fs.rm (removePath) walks by
    // path, where a directory swapped for a link makes root delete the link's
    // target. Without the job's signal: after a cancel run() starts nothing.
    await run({ ...helpers, signal: undefined }, 'rm', ['-rf', '--', tmpDir]).catch(() => {});
    // Plain unlink for the same reason: a name removed earlier is free in /tmp.
    for (const p of [archivePath, encryptedPath]) await fs.unlink(p).catch(() => {});
    throw e;
  }
}

// The steps of buildSiteArchive, which cleans up after a throw from any of them.
async function packSite(helpers, domain, s, { tmpDir, dump, archivePath, encryptedPath, includeSsl = false, encryptKey = '', nested = false }) {
  const { step, ok } = logger(helpers, { nested });
  // Type + PHP version (+ whether the object cache was on) travel with the
  // archive, so a restore rebuilds the same site.
  const objectCache = s.type === 'wordpress' ? await objectCacheActive(s) : false;
  await fs.writeFile(`${tmpDir}/wcloud-site.json`, JSON.stringify({ ...publicSpec(s), objectCache }, null, 2));

  // 1) Dump the database. wp-cli runs as the site's user, so it writes into
  //    the site's own tmp dir; root then moves the dump into staging.
  if (s.type === 'wordpress') {
    step('Export the database');
    const dbDump = await (await wpCli(helpers, s))(['db', 'export', dump]);
    const staged = `${tmpDir}/db.sql`;
    // The site wrote the dump in its own tmp/, so it may be a link. Checked
    // (lstat) once it is in staging: restore only takes a regular file.
    const dumped = dbDump.code === 0
      && (await run(helpers, 'mv', ['--', dump, staged])).code === 0
      && (await fs.lstat(staged).then((st) => st.isFile(), () => false));
    if (!dumped) {
      await fs.unlink(dump).catch(() => {}); // in the site's tmp/: never a recursive delete as root
      // Staging, which may now hold a directory the site made, is removed by
      // buildSiteArchive (rm, not removePath).
      throw new Error('Database export failed');
    }
    ok('Database exported');
  }

  // 2) Copy the site files (root, reading everything).
  step('Copy the site files');
  const destSite = `${tmpDir}/site`;
  // quiet + LC_ALL=C: cp's own lines are read below, in English.
  const cpR = await run(helpers, 'cp', ['-a', siteDir(domain), destSite], { quiet: true, env: { LC_ALL: 'C' } });
  // The site is live: a file cp listed and found gone when it came to read it
  // (an upload's temp file, a session, a purged cache) is gone from the site
  // too — not a failed copy. Anything else cp complains about still is.
  // A directory gone after cp entered it (cache purge, wp-content/upgrade) adds
  // a line from the permissions step, which reads the source by path again:
  // the bare path (coreutils 8) or "preserving permissions for <copy>" (9).
  // Staging is root-only, so "No such file" on these is always the source.
  const cpErrs = cpR.stderr.split('\n').filter((l) => l.trim());
  const vanishedOnly = cpR.code === 1 && cpErrs.length > 0
    && cpErrs.every((l) => /^cp: (cannot (stat|access|open|read symbolic link) .*|preserving permissions for .*|'.*'): No such file or directory$/.test(l))
    && await pathExists(destSite); // the site folder itself gone = nothing was copied
  if (cpR.code !== 0 && !vanishedOnly) {
    // A partial copy would still archive and upload "successfully" — a
    // silently incomplete restore point.
    for (const l of cpErrs.slice(-15)) helpers.err?.(`    ${l}`);
    await removePath(tmpDir);
    throw new Error('Copying the site files failed — the disk may be full.');
  }
  // Sessions, uploads in flight and caches don't belong in a restore point.
  // Removing follows links in every part of a path but the last, and htdocs is
  // the site's: with `app` planted as a link to /var, root would delete
  // /var/cache. So only where the parent is a real directory inside staging.
  const stagedSite = await fs.realpath(destSite);
  for (const dir of ['tmp', 'htdocs/wp-content/cache', 'htdocs/app/cache']) {
    const parent = path.dirname(`${stagedSite}/${dir}`);
    if ((await fs.realpath(parent).catch(() => null)) === parent) await removePath(`${stagedSite}/${dir}`);
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

  return { path: encryptKey ? encryptedPath : archivePath };
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
    // Plain unlink, never removePath: a same-server import already removed the
    // archive, so the name may be something a site has put in /tmp since.
    await fs.unlink(entry.path).catch(() => {});
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

  // pipeline, not pipe: when the client goes away mid-download it closes the
  // file, and the archive is removed however the download ended. The token is
  // already spent, so nothing else would ever find it in /tmp.
  try {
    await pipeline(readStream, res);
  } catch { /* client went away mid-download */ }
  finally {
    await fs.unlink(entry.path).catch(() => {});
  }
}

function cleanupExports() {
  const now = Date.now();
  for (const [token, entry] of exports.entries()) {
    if (now > entry.expires) {
      exports.delete(token);
      fs.unlink(entry.path).catch(() => {}); // unlink: see serveExport
    }
  }
}
