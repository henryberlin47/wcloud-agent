import fs from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { run, pathExists, removePath, userIds } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import {
  SITE_TYPES, CACHE_MODES, readSpec, createSite, deleteSite, applySslConf, syncWpAddress, webRoot, siteTmp,
} from '../lib/sites.js';
import { wpCli, clearWpCaches, safePrefix } from '../lib/wp.js';
import { PHP_VERSIONS, DEFAULT_PHP } from '../lib/stack.js';
import { issueHttp } from '../lib/acme.js';
import { installCachePlugin } from '../lib/cache.js';

// Unpredictable, atomically-created staging dir (mkdtemp: 0700 root, never
// reuses an existing path). Only root touches it; the one file a site's wp-cli
// needs (the SQL dump) is handed over through the site's own tmp dir.
export async function makeStagingDir(helpers, prefix) {
  return fs.mkdtemp(`/tmp/wcloud_${prefix}_`);
}

// A crafted archive can make a top-level entry (site, site/htdocs, ssl/live) a
// symlink, and `cp -a src/. dest` DEREFERENCES the source root — copying an
// arbitrary host dir (e.g. /root) into the web root, then chowning it to the
// site. Only ever copy out of real directories. (Symlinks *inside* a tree are
// copied as links, not followed.)
async function isRealDir(p) {
  try { return (await fs.lstat(p)).isDirectory(); } catch { return false; }
}

async function mustRun(helpers, cmd, args, what) {
  const r = await run(helpers, cmd, args);
  if (r.code !== 0) throw new Error(`${what} failed — the disk may be full or the archive incomplete.`);
  return r;
}

// Turn `${tmpDir}/export.tar.gz.enc` into a plaintext `${tmpDir}/export.tar.gz`
// (decrypting when a key is given). Idempotent, so restore can do it up front —
// proving the key works BEFORE it deletes the live site — and the shared restore
// path then skips it.
export async function prepareArchive(helpers, tmpDir, encryptKey, { step, ok }) {
  const enc = `${tmpDir}/export.tar.gz.enc`;
  const plain = `${tmpDir}/export.tar.gz`;
  if (!(await pathExists(enc))) return;
  if (encryptKey) {
    step('Decrypt the archive');
    const decR = await run(helpers, 'openssl', [
      'enc', '-d', '-aes-256-cbc', '-pbkdf2',
      '-pass', `env:ENC_KEY`,
      '-in', enc,
      '-out', plain,
    ], { env: { ENC_KEY: encryptKey } });
    if (decR.code !== 0) {
      throw new Error('The archive could not be decrypted. This usually means the encryption key for this account has changed since the backup was made.');
    }
    await removePath(enc);
    ok('Archive decrypted');
  } else {
    await mustRun(helpers, 'mv', [enc, plain], 'Preparing the archive');
  }
}

// params: { sourceUrl, domain, sourceDomain?, includeSsl?, issueSsl?, sameServer?, localArchive?, encryptKey?, canonical?, enableWww? }
export async function runImport(job, helpers, p) {
  const { step, ok, err } = logger(helpers);
  const domain = p.domain;
  const sourceDomain = p.sourceDomain || domain;

  if (await readSpec(domain)) {
    throw new Error(`${domain} already exists on this server. Delete it first, or choose a different domain.`);
  }

  const tmpDir = await makeStagingDir(helpers, 'import');
  try {
    // 1) Fetch archive to `${tmpDir}/export.tar.gz.enc` (or copy a local one).
    step('Fetch the site archive');
    if (p.sameServer && p.localArchive) {
      await mustRun(helpers, 'cp', ['--', p.localArchive, `${tmpDir}/export.tar.gz.enc`], 'Copying the archive');
      // Clean up the source archive after copying (same-server migration).
      await removePath(p.localArchive);
      ok('Archive copied');
    } else {
      const fetchR = await run(helpers, 'curl', [
        // Pin the protocol on the initial request AND on redirects: -L would
        // otherwise happily follow an http(s) URL into file:// or a link-local
        // metadata address.
        '--proto', '=http,https', '--proto-redir', '=http,https',
        // Another agent's self-signed certificate: trusted by its pinned public
        // key (curl still checks the pin with -k), never by "accept anything".
        ...(p.sourcePin ? ['-k', '--pinnedpubkey', `sha256//${p.sourcePin}`] : []),
        '-sL', '--fail', '--create-dirs',
        '-o', `${tmpDir}/export.tar.gz.enc`,
        p.sourceUrl,
      ], { timeout: 300_000 });
      if (fetchR.code !== 0) {
        err(`Failed to fetch archive: ${fetchR.stderr.slice(-200)}`);
        throw new Error('Could not download the site archive from the source server.');
      }
      ok('Archive downloaded');
    }
  } catch (e) {
    await removePath(tmpDir);
    throw e;
  }

  await runRestoreFromLocal(job, helpers, {
    tmpDir, domain, sourceDomain,
    includeSsl: p.includeSsl, issueSsl: p.issueSsl, encryptKey: p.encryptKey,
    canonical: p.canonical, enableWww: p.enableWww,
    nested: true, // runImport already numbered its own steps
  });
}

// The restore proper, shared by import (HTTP / same-server archive) and the
// backup restore op (archive downloaded from Spaces). Expects the archive at
// `${tmpDir}/export.tar.gz.enc` (plaintext `.tar.gz` renamed is fine too).
// Owns tmpDir cleanup and rollback of a half-created site on failure.
//
// params: { tmpDir, domain, sourceDomain, includeSsl?, issueSsl?, encryptKey?, canonical?, enableWww? }
// includeSsl → copy the source's certs; issueSsl → issue Let's Encrypt; both
// false → no SSL (explicit "No SSL" choice from the portal).
export async function runRestoreFromLocal(job, helpers, {
  tmpDir, domain, sourceDomain,
  includeSsl = false, issueSsl = true, encryptKey = '', canonical = 'none', enableWww = true,
  nested = false,
}) {
  const { log, step, ok, warn, err, skip } = logger(helpers, { nested });
  const domainChanged = sourceDomain !== domain;
  let siteCreated = false;

  try {
    await prepareArchive(helpers, tmpDir, encryptKey, { step, ok });

    // --no-same-owner: entries land root-owned regardless of the uids recorded
    // in a (possibly foreign) archive.
    step('Unpack the archive');
    const extractR = await run(helpers, 'tar', ['xzf', `${tmpDir}/export.tar.gz`, '--no-same-owner', '-C', tmpDir]);
    if (extractR.code !== 0) {
      throw new Error('The archive could not be unpacked — the file may be incomplete or corrupted.');
    }
    await removePath(`${tmpDir}/export.tar.gz`);
    ok('Archive unpacked');

    // What kind of site this was. Archives made before site types existed are
    // WordPress; values are checked, never trusted.
    let src = {};
    try { src = JSON.parse(await fs.readFile(`${tmpDir}/wcloud-site.json`, 'utf8')); } catch { /* older archive */ }
    const type = SITE_TYPES.includes(src.type) ? src.type : 'wordpress';
    const php = PHP_VERSIONS.includes(src.php) ? src.php : DEFAULT_PHP;
    const cache = CACHE_MODES.includes(src.cache) ? src.cache : 'fastcgi';

    // Source table prefix, from the archived wp-config.php.
    let tablePrefix = 'wp_';
    if (type === 'wordpress') {
      for (const cfgPath of [`${tmpDir}/site/wp-config.php`, `${tmpDir}/site/htdocs/wp-config.php`]) {
        if (!(await pathExists(cfgPath))) continue;
        const m = (await fs.readFile(cfgPath, 'utf8')).match(/\$table_prefix\s*=\s*['"]([^'"]+)['"]/);
        if (m) {
          if (safePrefix(m[1])) tablePrefix = m[1];
          else warn('The archived table prefix is not a plain name — using wp_');
          break;
        }
      }
    }

    step(type === 'wordpress' ? `Create the WordPress site (PHP ${php})` : 'Create the static site');
    const s = await createSite(helpers, {
      domain, type, php, cache, enableWww, canonical,
      wp: { install: false, tablePrefix }, // the archive brings WordPress itself
    });
    siteCreated = true;
    ok(`Site created — ${domain}`);

    step('Restore the site files');
    const srcSite = `${tmpDir}/site`;
    if (await isRealDir(srcSite)) {
      const srcHtdocs = `${srcSite}/htdocs`;
      const dest = webRoot(domain);
      const from = (await isRealDir(srcHtdocs)) ? srcHtdocs : srcSite;
      await mustRun(helpers, 'cp', ['-a', `${from}/.`, dest], 'Copying the site files');
      // The site keeps its own wp-config.php (non-standard sources leak one in).
      if (type === 'wordpress') await removePath(`${dest}/wp-config.php`);
      // The source's uids mean nothing here. (-R does not follow symlinks, so a
      // link in the tree can't redirect the chown.)
      await mustRun(helpers, 'chown', ['-R', `${s.user}:www-data`, dest], 'Setting file ownership');
      ok('Site files restored');
    } else {
      warn('No site files found in archive');
    }

    if (type === 'wordpress') {
      step('Restore the database');
      const sqlFile = `${tmpDir}/db.sql`;
      if (await pathExists(sqlFile)) {
        // Hand the dump to the site through its own tmp dir: wp-cli runs as the
        // site's user and can't (and mustn't) read the root-only staging dir.
        const handed = `${siteTmp(domain)}/wcloud-import-${randomBytes(6).toString('hex')}.sql`;
        await mustRun(helpers, 'mv', ['--', sqlFile, handed], 'Preparing the database dump');
        const { uid, gid } = await userIds(s.user);
        await fs.chown(handed, uid, gid);
        await fs.chmod(handed, 0o600);

        const wp = await wpCli(helpers, s);
        const importR = await wp(['db', 'import', handed]);
        await removePath(handed);
        if (importR.code !== 0) throw new Error('Database import failed');
        ok('Database imported');

        if (domainChanged) {
          step('Update site URLs');
          // --precise does exact string match, avoiding partial hits in emails.
          // --all-tables covers options, usermeta, postmeta, custom tables.
          const replaceR = await wp(['search-replace', sourceDomain, domain, '--all-tables', '--precise', '--report-changed-only']);
          if (replaceR.code !== 0) warn('URL search-replace had issues — may need manual review');
          else ok(`URLs updated: ${sourceDomain} → ${domain}`);
        }

        await clearWpCaches(helpers, s);
        ok('Caches cleared');
      } else {
        warn('No database dump found in archive');
      }
    }

    if (includeSsl) {
      step('Restore SSL certificates');
      const destLive = `/etc/letsencrypt/live/${domain}`;
      const destArchive = `/etc/letsencrypt/archive/${domain}`;
      // Only cert material comes from the archive — never a renewal.conf
      // (can carry root-run hook commands) or nginx config.
      for (const [from, to] of [[`${tmpDir}/ssl/live`, destLive], [`${tmpDir}/ssl/archive`, destArchive]]) {
        if (!(await isRealDir(from))) continue;
        await fs.mkdir(to, { recursive: true });
        await mustRun(helpers, 'cp', ['-a', `${from}/.`, to], 'Copying the certificates');
        await run(helpers, 'chown', ['-R', 'root:root', to]);
        await run(helpers, 'find', [to, '-type', 'd', '-exec', 'chmod', '700', '{}', ';']);
        await run(helpers, 'find', [to, '-type', 'f', '-exec', 'chmod', '600', '{}', ';']);
      }
      // A bad or missing cert must not cost the restored site: warn, serve HTTP.
      try {
        await applySslConf(helpers, domain);
        ok('SSL certificates restored');
        warn('The copied certificate will not renew automatically. Once this domain\'s DNS points here, re-issue HTTPS from the site page to get an auto-renewing certificate.');
      } catch {
        warn('The archived certificate could not be enabled — the site is restored on HTTP. Issue HTTPS from the site page.');
      }
    } else if (issueSsl) {
      step('Issue SSL certificate');
      const r = await issueHttp(helpers, domain, { www: enableWww });
      if (r.ok) ok(`SSL issued for ${domain}`);
      else warn('SSL failed (DNS/propagation?) — issue it from the site page later');
    } else {
      skip('SSL — "No SSL" selected');
    }

    // After the DB import, so the imported home/siteurl don't win.
    if (type === 'wordpress') {
      step('Set the WordPress address');
      await syncWpAddress(helpers, await readSpec(domain));
    }
    // The archive may predate the page cache (or come from another host).
    if (type === 'wordpress' && cache === 'fastcgi') {
      await installCachePlugin(helpers, await readSpec(domain)).catch((e) => warn(`Page cache helper not installed: ${e.message}`));
    }

    log(`Restore completed: ${domain}`);
  } catch (e) {
    if (siteCreated) {
      warn('Restore failed — removing the half-created site');
      try {
        await deleteSite(helpers, domain);
        ok('Half-created site removed');
      } catch {
        err(`Failed to clean up ${domain} — delete it from the site page.`);
      }
    }
    throw e;
  } finally {
    await removePath(tmpDir);
  }
}
