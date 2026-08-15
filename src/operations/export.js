import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import config from '../config.js';
import { run, woSiteExists, pathExists, wpCli, removePath } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// Temporary export archives and their one-time tokens.
const exports = new Map();

// params: { domain, includeSsl: boolean, encryptKey: string }
export async function runExport(job, helpers, p) {
  const { log, step, ok, warn, err } = logger(helpers);
  const domain = p.domain;
  const includeSsl = p.includeSsl === true;
  const encryptKey = p.encryptKey || '';

  if (!(await woSiteExists(helpers, domain))) {
    throw new Error(`Site not found: ${domain}`);
  }

  const stamp = Date.now();
  const token = crypto.randomUUID();
  const tmpDir = `/tmp/wcloud_export_${stamp}`;
  const archivePath = `${tmpDir}.tar.gz`;
  const siteDir = `${config.wwwDir}/${domain}`;

  // Make staging dir accessible to www-data (wp-cli runs as www-data).
  // 0700 keeps it private (holds SSL keys), www-data can read/write for DB dump.
  await fs.mkdir(tmpDir, { recursive: true, mode: 0o700 });
  await run(helpers, 'chown', ['www-data:www-data', tmpDir]);

  // 1) Dump the database (runs as www-data, needs access to tmpDir).
  step('Dump database');
  const wpRoot = `${siteDir}/htdocs`;
  const wp = wpCli(helpers, wpRoot);
  const sqlPath = `${tmpDir}/db.sql`;
  const dbDump = await wp(['db', 'export', sqlPath]);
  if (dbDump.code !== 0) {
    await removePath(tmpDir);
    throw new Error('Database export failed');
  }
  ok('Database dumped');

  // 2) Copy site files (as root — root can write to www-data-owned dir).
  step('Copy site files');
  const destSite = `${tmpDir}/site`;
  await run(helpers, 'cp', ['-a', siteDir, destSite]);
  // Remove cache dirs to shrink archive.
  for (const cacheDir of ['app/cache', 'wp-content/cache', 'wp-content/uploads/wp-rocket-minify']) {
    await removePath(`${destSite}/${cacheDir}`);
  }
  ok('Site files copied');

  // 3) Copy SSL certs + nginx config if requested.
  if (includeSsl) {
    step('Copy SSL certificates and nginx config');
    const sslLive = `/etc/letsencrypt/live/${domain}`;
    const sslArchive = `/etc/letsencrypt/archive/${domain}`;
    const sslRenewal = `/etc/letsencrypt/renewal/${domain}.conf`;
    const sslDest = `${tmpDir}/ssl`;
    await fs.mkdir(sslDest, { recursive: true });

    if (await pathExists(sslLive)) {
      await run(helpers, 'cp', ['-a', sslLive, `${sslDest}/live`]);
    }
    if (await pathExists(sslArchive)) {
      await run(helpers, 'cp', ['-a', sslArchive, `${sslDest}/archive`]);
    }
    if (await pathExists(sslRenewal)) {
      await run(helpers, 'cp', ['-a', sslRenewal, `${sslDest}/renewal.conf`]);
    }
    // Copy the per-site SSL nginx config (portable across servers for same domain).
    const sslNginxConf = `${siteDir}/conf/nginx/ssl.conf`;
    if (await pathExists(sslNginxConf)) {
      await run(helpers, 'cp', ['-a', sslNginxConf, `${sslDest}/ssl.conf`]);
    }
    ok('SSL certificates and config copied');
  }

  // 4) Create tarball.
  step('Create archive');
  const tarR = await run(helpers, 'tar', ['czf', archivePath, '-C', tmpDir, '.']);
  if (tarR.code !== 0) {
    await removePath(tmpDir);
    throw new Error('Archive creation failed');
  }
  await removePath(tmpDir);

  // 5) Encrypt archive if key provided.
  if (encryptKey) {
    step('Encrypt archive');
    const encryptedPath = `${archivePath}.enc`;
    const encR = await run(helpers, 'openssl', [
      'enc', '-aes-256-cbc', '-pbkdf2',
      '-pass', `env:ENC_KEY`,
      '-in', archivePath,
      '-out', encryptedPath,
    ], { env: { ENC_KEY: encryptKey } });
    if (encR.code !== 0) {
      await removePath(archivePath);
      throw new Error('Archive encryption failed');
    }
    await removePath(archivePath);
    ok('Archive encrypted');
  }

  const finalPath = encryptKey ? `${archivePath}.enc` : archivePath;

  // 6) Register for serving.
  const expires = Date.now() + 3600_000;
  exports.set(token, { path: finalPath, expires });
  cleanupExports();

  const baseUrl = config.advertiseUrl || `http://${config.host}:${config.port}`;
  const fetchUrl = `${baseUrl.replace(/\/+$/, '')}/api/export/${token}`;

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
