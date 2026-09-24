import fs from 'node:fs/promises';
import config from '../config.js';
import {
  run, woSiteExists, nginxTest, nginxReload, getPhpVersion,
  wpCli, clearWpCaches, pathExists, removePath, setCanonical,
  WO_SITE_TIMEOUT_MS,
} from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { applySslConf } from '../lib/certinstall.js';

// Unpredictable, atomically-created 0700 staging dir (mkdtemp never reuses an
// existing path). www-data gets it because wp-cli's db import/export runs as
// www-data. ponytail: www-data (any site's PHP) could still tamper with the tree
// mid-run; a root-only dir + a single www-data-owned SQL file closes that.
export async function makeStagingDir(helpers, prefix) {
  const dir = await fs.mkdtemp(`/tmp/wcloud_${prefix}_`);
  await run(helpers, 'chown', ['www-data:www-data', dir], { timeout: 30000 });
  return dir;
}

// A crafted archive can make a top-level entry (site, site/htdocs, ssl/live) a
// symlink, and `cp -a src/. dest` DEREFERENCES the source root — copying an
// arbitrary host dir (e.g. /root) into the web root, then chowning it to
// www-data. Only ever copy out of real directories. (Symlinks *inside* a tree
// are copied as links, not followed — WordOps' own logs/*.log links are fine.)
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

  if (await woSiteExists(helpers, domain)) {
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
  const siteDir = `${config.wwwDir}/${domain}`;
  let siteCreated = false;

  try {
    await prepareArchive(helpers, tmpDir, encryptKey, { step, ok });

    // 2) Extract archive. --no-same-owner: entries land root-owned regardless of
    // the uids recorded in a (possibly foreign) archive.
    step('Unpack the archive');
    const extractR = await run(helpers, 'tar', ['xzf', `${tmpDir}/export.tar.gz`, '--no-same-owner', '-C', tmpDir]);
    if (extractR.code !== 0) {
      throw new Error('The archive could not be unpacked — the file may be incomplete or corrupted.');
    }
    await removePath(`${tmpDir}/export.tar.gz`);
    ok('Archive unpacked');

    // 3) Read source table prefix from archived wp-config.php.
    let sourcePrefix = '';
    const srcConfigPaths = [
      `${tmpDir}/site/wp-config.php`,
      `${tmpDir}/site/htdocs/wp-config.php`,
    ];
    for (const cfgPath of srcConfigPaths) {
      if (await pathExists(cfgPath)) {
        const cfgContent = await fs.readFile(cfgPath, 'utf8');
        const prefixMatch = cfgContent.match(/\$table_prefix\s*=\s*['"]([^'"]+)['"]/);
        if (prefixMatch) {
          sourcePrefix = prefixMatch[1];
          break;
        }
      }
    }

    // 4) Create WordPress site via WordOps.
    step('Create the WordPress site');
    const php = getPhpVersion();
    const woArgs = ['site', 'create', domain, '--wp', `--php${php.flag}`];
    const deployR = await run(helpers, 'wo', woArgs, { timeout: WO_SITE_TIMEOUT_MS });
    if (deployR.code !== 0) {
      const detail = deployR.timedOut
        ? `timed out after ${WO_SITE_TIMEOUT_MS}ms`
        : `code ${deployR.code}`;
      throw new Error(`wo site create failed (${detail})`);
    }
    siteCreated = true;
    ok(`Site created — ${domain}`);

    // 5) Fix table prefix BEFORE importing DB.
    if (sourcePrefix) {
      step('Match the database table prefix');
      const wpRoot = `${siteDir}/htdocs`;
      const wp = wpCli(helpers, wpRoot);
      const setPrefix = await wp(['config', 'set', 'table_prefix', sourcePrefix, '--type=variable']);
      if (setPrefix.code === 0) {
        ok(`Table prefix set to '${sourcePrefix}'`);
      } else {
        warn('Failed to set table prefix — DB import may have mismatched prefix');
      }
    }

    // 6) Restore site files (exclude wp-config.php from htdocs copy).
    step('Restore the site files');
    const srcSite = `${tmpDir}/site`;
    if (await isRealDir(srcSite)) {
      const srcHtdocs = `${srcSite}/htdocs`;
      const destHtdocs = `${siteDir}/htdocs`;

      // One overlay copy of the whole tree (wp-content included). A per-subdir
      // `cp -a src/plugins dest/plugins` used to run first: dest already exists
      // on a fresh WordOps site, so it nested (plugins/plugins/…) and copied
      // uploads twice.
      const from = (await isRealDir(srcHtdocs)) ? srcHtdocs : srcSite;
      await mustRun(helpers, 'cp', ['-a', `${from}/.`, destHtdocs], 'Copying the site files');
      // The target keeps its own wp-config.php (non-standard sources leak one in).
      await removePath(`${destHtdocs}/wp-config.php`);

      // Fix file ownership — source UID may differ from target. (-R does not
      // follow symlinks, so a link in the tree can't redirect the chown.)
      await mustRun(helpers, 'chown', ['-R', 'www-data:www-data', destHtdocs], 'Setting file ownership');
      ok('Site files restored');
    } else {
      warn('No site files found in archive');
    }

    // 7) Restore database.
    step('Restore the database');
    const sqlFile = `${tmpDir}/db.sql`;
    if (await pathExists(sqlFile)) {
      // Ensure www-data can read the SQL file.
      await run(helpers, 'chown', ['www-data:www-data', sqlFile]);
      await run(helpers, 'chmod', ['640', sqlFile]);

      const wpRoot = `${siteDir}/htdocs`;
      const wp = wpCli(helpers, wpRoot);

      const importR = await wp(['db', 'import', sqlFile]);
      if (importR.code !== 0) {
        err(`Database import failed (code ${importR.code})`);
        throw new Error('Database import failed');
      }
      ok('Database imported');

      // 8) Update site URLs if domain changed.
      if (domainChanged) {
        step('Update site URLs');
        // --precise does exact string match, avoiding partial hits in emails.
        // --all-tables covers options, usermeta, postmeta, custom tables.
        const replaceR = await wp([
          'search-replace', sourceDomain, domain,
          '--all-tables', '--precise', '--report-changed',
        ]);
        if (replaceR.code !== 0) {
          warn('URL search-replace had issues — may need manual review');
        } else {
          ok(`URLs updated: ${sourceDomain} → ${domain}`);
        }

        // Update WP_HOME / WP_SITEURL constants if they reference old domain.
        const homeR = await wp(['config', 'get', 'WP_HOME']);
        if (homeR.code === 0 && homeR.stdout.includes(sourceDomain)) {
          await wp(['config', 'set', 'WP_HOME', `https://${domain}`, '--type=constant']);
        }
        const siteUrlR = await wp(['config', 'get', 'WP_SITEURL']);
        if (siteUrlR.code === 0 && siteUrlR.stdout.includes(sourceDomain)) {
          await wp(['config', 'set', 'WP_SITEURL', `https://${domain}`, '--type=constant']);
        }
      }

      await clearWpCaches(helpers, wpRoot, siteDir);
      ok('Caches cleared');
    } else {
      warn('No database dump found in archive');
    }

    // 9) Handle SSL.
    if (includeSsl) {
      step('Restore SSL certificates');
      const sslLive = `${tmpDir}/ssl/live`;
      const sslArchiveDir = `${tmpDir}/ssl/archive`;

      const destLive = `/etc/letsencrypt/live/${domain}`;
      const destArchive = `/etc/letsencrypt/archive/${domain}`;

      // Only cert material comes from the archive. The archive's renewal.conf
      // (certbot-format, can carry root-run hook commands) and ssl.conf (raw
      // nginx directives included into the server block) are NOT restored —
      // ssl.conf is regenerated below by the transactional applySslConf.
      if (await isRealDir(sslLive)) {
        await fs.mkdir(destLive, { recursive: true });
        await mustRun(helpers, 'cp', ['-a', `${sslLive}/.`, destLive], 'Copying the certificates');
      }
      if (await isRealDir(sslArchiveDir)) {
        await fs.mkdir(destArchive, { recursive: true });
        await mustRun(helpers, 'cp', ['-a', `${sslArchiveDir}/.`, destArchive], 'Copying the certificates');
      }

      // Set correct permissions: dirs 700 (traversable), files 600.
      if (await pathExists(destLive)) {
        await run(helpers, 'chown', ['-R', 'root:root', destLive]);
        await run(helpers, 'find', [destLive, '-type', 'd', '-exec', 'chmod', '700', '{}', ';']);
        await run(helpers, 'find', [destLive, '-type', 'f', '-exec', 'chmod', '600', '{}', ';']);
      }
      if (await pathExists(destArchive)) {
        await run(helpers, 'chown', ['-R', 'root:root', destArchive]);
        await run(helpers, 'find', [destArchive, '-type', 'd', '-exec', 'chmod', '700', '{}', ';']);
        await run(helpers, 'find', [destArchive, '-type', 'f', '-exec', 'chmod', '600', '{}', ';']);
      }

      // Wire HTTPS to the copied cert (backup → nginx -t → rollback). A bad or
      // missing cert must not cost the restored site: warn and serve HTTP.
      try {
        await applySslConf(helpers, domain);
        ok('SSL certificates restored');
        warn('The copied certificate will not renew automatically. Once this domain\'s DNS points here, re-issue HTTPS from the site page to get an auto-renewing certificate.');
      } catch {
        warn('The archived certificate could not be enabled — the site is restored on HTTP. Issue HTTPS from the site page.');
      }
    } else if (issueSsl) {
      step('Issue SSL certificate');
      const sslR = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force'], { timeout: 300000 });
      if (sslR.code === 0) {
        ok(`SSL issued for ${domain}`);
      } else {
        warn(`SSL failed (DNS/propagation?) — run the SSL op from the site page later`);
      }
    } else {
      skip('SSL — "No SSL" selected');
    }

    // Apply domain preferences (after DB import so WP options aren't
    // overwritten by imported values). Handles none/enable-www itself.
    step('Apply domain preferences');
    await setCanonical(helpers, domain, canonical, enableWww);

    // 10) Validate + reload nginx.
    step('Validate + reload nginx');
    if (await nginxTest(helpers)) {
      await nginxReload(helpers);
      ok('nginx reloaded');
    } else {
      err('The web server configuration is invalid, so it was not reloaded. The site may not serve until this is fixed.');
    }

    log(`Restore completed: ${domain}`);
  } catch (e) {
    // Rollback: if we created the site but the restore failed, clean up the
    // half-site.
    if (siteCreated) {
      warn('Restore failed — rolling back half-created site');
      try {
        await run(helpers, 'wo', ['site', 'delete', domain, '--no-prompt', '--force'], { stdin: '', timeout: 120000 });
        ok('Half-created site removed');
      } catch {
        warn(`Failed to clean up ${domain} — delete manually: wo site delete ${domain} --no-prompt --force`);
      }
    }
    throw e;
  } finally {
    await removePath(tmpDir);
  }
}
