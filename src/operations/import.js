import fs from 'node:fs/promises';
import config from '../config.js';
import {
  run, woSiteExists, nginxTest, nginxReload, getPhpVersion,
  wpCli, clearWpCaches, pathExists, removePath, setCanonical,
} from '../lib/sys.js';
import { logger } from '../lib/log.js';

// params: { sourceUrl, domain, sourceDomain?, includeSsl?, sameServer?, localArchive?, encryptKey? }
export async function runImport(job, helpers, p) {
  const { log, step, ok, warn, err } = logger(helpers);
  const sourceUrl = p.sourceUrl;
  const domain = p.domain;
  const sourceDomain = p.sourceDomain || domain;
  const sameServer = p.sameServer === true;
  const domainChanged = sourceDomain !== domain;
  const encryptKey = p.encryptKey || '';

  if (await woSiteExists(helpers, domain)) {
    throw new Error(`Site already exists: ${domain}`);
  }

  const tmpDir = `/tmp/wcloud_import_${Date.now()}`;
  const siteDir = `${config.wwwDir}/${domain}`;
  let siteCreated = false;

  try {
    // 1) Fetch and extract archive.
    step('Fetch export archive');
    await fs.mkdir(tmpDir, { recursive: true, mode: 0o700 });
    await run(helpers, 'chown', ['www-data:www-data', tmpDir]);

    if (sameServer && p.localArchive) {
      await run(helpers, 'cp', [p.localArchive, `${tmpDir}/export.tar.gz.enc`]);
      // Clean up the source archive after copying (same-server migration).
      await removePath(p.localArchive);
      ok('Local archive copied');
    } else {
      const fetchR = await run(helpers, 'curl', [
        '-sL', '--fail', '--create-dirs',
        '-o', `${tmpDir}/export.tar.gz.enc`,
        sourceUrl,
      ], { timeout: 300_000 });
      if (fetchR.code !== 0) {
        err(`Failed to fetch archive: ${fetchR.stderr.slice(-200)}`);
        throw new Error('Failed to fetch export archive');
      }
      ok('Archive downloaded');
    }

    // Decrypt if encrypted.
    if (encryptKey) {
      step('Decrypt archive');
      const decR = await run(helpers, 'openssl', [
        'enc', '-d', '-aes-256-cbc', '-pbkdf2',
        '-pass', `env:ENC_KEY`,
        '-in', `${tmpDir}/export.tar.gz.enc`,
        '-out', `${tmpDir}/export.tar.gz`,
      ], { env: { ENC_KEY: encryptKey } });
      if (decR.code !== 0) {
        throw new Error('Archive decryption failed');
      }
      await removePath(`${tmpDir}/export.tar.gz.enc`);
      ok('Archive decrypted');
    } else {
      await run(helpers, 'mv', [`${tmpDir}/export.tar.gz.enc`, `${tmpDir}/export.tar.gz`]);
    }

    // 2) Extract archive.
    step('Extract archive');
    const extractR = await run(helpers, 'tar', ['xzf', `${tmpDir}/export.tar.gz`, '-C', tmpDir]);
    if (extractR.code !== 0) {
      throw new Error('Archive extraction failed');
    }
    await removePath(`${tmpDir}/export.tar.gz`);
    ok('Archive extracted');

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
    step('Create WordPress site');
    const php = getPhpVersion();
    const woArgs = ['site', 'create', domain, '--wp', `--php${php.flag}`];
    const deployR = await run(helpers, 'wo', woArgs);
    if (deployR.code !== 0) {
      throw new Error(`wo site create failed (code ${deployR.code})`);
    }
    siteCreated = true;
    ok(`Site created: ${domain}`);

    // 5) Fix table prefix BEFORE importing DB.
    if (sourcePrefix) {
      step('Fix table prefix');
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
    step('Restore site files');
    const srcSite = `${tmpDir}/site`;
    if (await pathExists(srcSite)) {
      const srcHtdocs = `${srcSite}/htdocs`;
      const destHtdocs = `${siteDir}/htdocs`;

      if (await pathExists(srcHtdocs)) {
        // Copy wp-content subdirs (plugins, themes, uploads).
        for (const sub of ['wp-content/uploads', 'wp-content/plugins', 'wp-content/themes', 'wp-content/mu-plugins']) {
          const srcSub = `${srcHtdocs}/${sub}`;
          const destSub = `${destHtdocs}/${sub}`;
          if (await pathExists(srcSub)) {
            await run(helpers, 'cp', ['-a', srcSub, destSub]);
          }
        }
        // Copy other WP files, excluding wp-config.php (target keeps its own).
        await run(helpers, 'cp', ['-a', `${srcHtdocs}/.` , destHtdocs]);
        // Remove any wp-config.php that leaked into htdocs (non-standard source layout).
        await removePath(`${destHtdocs}/wp-config.php`);
      } else {
        await run(helpers, 'cp', ['-a', `${srcSite}/.`, destHtdocs]);
        await removePath(`${destHtdocs}/wp-config.php`);
      }

      // Fix file ownership — source UID may differ from target.
      await run(helpers, 'chown', ['-R', 'www-data:www-data', destHtdocs]);
      ok('Site files restored');
    } else {
      warn('No site files found in archive');
    }

    // 7) Restore database.
    step('Restore database');
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
    if (p.includeSsl === true) {
      step('Restore SSL certificates');
      const sslLive = `${tmpDir}/ssl/live`;
      const sslArchiveDir = `${tmpDir}/ssl/archive`;
      const sslRenewal = `${tmpDir}/ssl/renewal.conf`;
      const sslConf = `${tmpDir}/ssl/ssl.conf`;

      const destLive = `/etc/letsencrypt/live/${domain}`;
      const destArchive = `/etc/letsencrypt/archive/${domain}`;
      const destRenewal = `/etc/letsencrypt/renewal/${domain}.conf`;

      if (await pathExists(sslLive)) {
        await fs.mkdir(destLive, { recursive: true });
        await run(helpers, 'cp', ['-a', `${sslLive}/.`, destLive]);
      }
      if (await pathExists(sslArchiveDir)) {
        await fs.mkdir(destArchive, { recursive: true });
        await run(helpers, 'cp', ['-a', `${sslArchiveDir}/.`, destArchive]);
      }
      if (await pathExists(sslRenewal)) {
        await fs.mkdir(`/etc/letsencrypt/renewal`, { recursive: true });
        await run(helpers, 'cp', ['--', sslRenewal, destRenewal]);
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

      // Wire the SSL nginx config (pointing at copied cert paths).
      if (await pathExists(sslConf)) {
        const destConf = `${siteDir}/conf/nginx/ssl.conf`;
        await fs.mkdir(`${siteDir}/conf/nginx`, { recursive: true });
        await run(helpers, 'cp', ['--', sslConf, destConf]);
        ok('SSL nginx config restored');
      }

      ok('SSL certificates restored');
      warn('Copied certs will not auto-renew. After DNS points here, run the SSL op to get acme.sh-managed certs with renewal.');
    } else if (!domainChanged) {
      step('Issue SSL certificate');
      const sslR = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force']);
      if (sslR.code === 0) {
        ok(`SSL issued for ${domain}`);
      } else {
        warn(`SSL failed (DNS/propagation?) — run "wo site update ${domain} --le --force" later`);
      }
    } else {
      step('Issue SSL certificate');
      const sslR = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force']);
      if (sslR.code === 0) {
        ok(`SSL issued for ${domain}`);
      } else {
        warn(`SSL failed (DNS/propagation?) — run "wo site update ${domain} --le --force" later`);
      }
    }

    // Set canonical domain redirect (after DB import so WP options aren't overwritten).
    if (p.canonical) {
      step('Set canonical domain');
      await setCanonical(helpers, domain, p.canonical);
    }

    // 10) Validate + reload nginx.
    step('Validate + reload nginx');
    if (await nginxTest(helpers)) {
      await nginxReload(helpers);
      ok('nginx reloaded');
    } else {
      err('nginx -t FAILED — review config');
    }

    log(`Import completed: ${domain}`);
  } catch (e) {
    // Rollback: if we created the site but import failed, clean up the half-site.
    if (siteCreated) {
      warn('Import failed — rolling back half-created site');
      try {
        await run(helpers, 'wo', ['site', 'delete', domain, '--no-prompt', '--force'], { stdin: '' });
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
