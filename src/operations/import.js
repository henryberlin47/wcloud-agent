import fs from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { run, pathExists, removePath, userIds } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import {
  SITE_TYPES, CACHE_MODES, readSpec, createSite, deleteSite, applySite, applySslConf, syncWpAddress, webRoot, siteTmp,
  REDIRECT_MAX, cleanRedirects, cleanDomainRedirect,
} from '../lib/sites.js';
import { wpCli, clearWpCaches, safePrefix, setWpConstant } from '../lib/wp.js';
import { PHP_VERSIONS, DEFAULT_PHP } from '../lib/stack.js';
import { issueHttp, issueDnsCloudflare } from '../lib/acme.js';
import { syncCachePlugin, retireLiteSpeedCache, syncLiteSpeedGuard, setObjectCache } from '../lib/cache.js';
import { cleanJob, fitsCron, CRON_MAX, WP_CRON_EVERY } from '../lib/cron.js';
import { cleanPhpSettings, cleanFpm } from '../lib/phpsettings.js';
import { saveRule, deleteRule } from '../lib/nginxrules.js';
import { checkCustomCert } from '../lib/certcheck.js';

// The custom nginx rule that keeps a WordPress site closed while its database
// is being restored. Never one of the site's own rules (restore.js skips it).
export const RESTORING_RULE = 'wcloud-restoring';

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

// The same for a file root is about to read: a link in the archive would make
// it read whatever the link points at.
async function isRealFile(p) {
  try { return (await fs.lstat(p)).isFile(); } catch { return false; }
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
      // Plain unlink: the name is in world-writable /tmp, never a recursive delete.
      await fs.unlink(p.localArchive).catch(() => {});
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
        // No time limit on the download itself: a big archive takes as long as
        // it takes, and the job's signal (cancel, the 12h op timeout) stops
        // curl. Only a dead link gives up: no connection in 30s, or under
        // 1 KB/s for 2 minutes.
        '--connect-timeout', '30', '--speed-limit', '1024', '--speed-time', '120',
        '-sSL', '--fail', '--create-dirs',
        '-o', `${tmpDir}/export.tar.gz.enc`,
        p.sourceUrl,
        // quiet: the URL carries the one-time export token, and run() prints the
        // command line into the job log on failure. curl's own reason (-S) is
        // logged below.
      ], { quiet: true });
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
// params: { tmpDir, domain, sourceDomain, includeSsl?, issueSsl?, encryptKey?, canonical?, enableWww?, cfToken?, cfZoneId? }
// cfToken + cfZoneId → Let's Encrypt over Cloudflare DNS first (auto-renewing,
// works before DNS points here — e.g. a site moving in from another host);
// includeSsl → copy the source's certs; issueSsl → issue Let's Encrypt; all
// off → no SSL (explicit "No SSL" choice from the portal).
export async function runRestoreFromLocal(job, helpers, {
  tmpDir, domain, sourceDomain,
  includeSsl = false, issueSsl = true, encryptKey = '', canonical = 'none', enableWww = true,
  cfToken = null, cfZoneId = null,
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
    // canonical "keep" (a restore): the address the site had — www or not.
    if (canonical === 'keep') {
      canonical = ['www', 'root', 'none'].includes(src.canonical) ? src.canonical : 'none';
      enableWww = src.enableWww !== false;
      if (canonical === 'www' && !enableWww) canonical = 'root';
    }
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
      realIp: src.realIp !== false, // as the site had it; archives that don't say → on, like a new site
      wp: { install: false, tablePrefix }, // the archive brings WordPress itself
    });
    siteCreated = true;
    ok(`Site created — ${domain}`);
    // Closed until the database is in: WordPress on an empty database serves
    // its installer to anyone who asks.
    if (type === 'wordpress') await saveRule(helpers, domain, { id: RESTORING_RULE, name: 'Restore in progress', content: 'return 503;', enabled: true });

    step('Restore the site files');
    const srcSite = `${tmpDir}/site`;
    if (await isRealDir(srcSite)) {
      const srcHtdocs = `${srcSite}/htdocs`;
      const dest = webRoot(domain);
      const from = (await isRealDir(srcHtdocs)) ? srcHtdocs : srcSite;
      // createSite's placeholder must not outlive a restore (it would win over index.htm).
      if (type === 'static') await removePath(`${dest}/index.html`);
      await mustRun(helpers, 'cp', ['-a', `${from}/.`, dest], 'Copying the site files');
      // The site keeps its own wp-config.php (non-standard sources leak one in).
      if (type === 'wordpress') await removePath(`${dest}/wp-config.php`);
      // The source's uids mean nothing here. (-R does not follow symlinks, so a
      // link in the tree can't redirect the chown.)
      await mustRun(helpers, 'chown', ['-R', `${s.user}:www-data`, dest], 'Setting file ownership');
      // cp -a put the archive's mode on htdocs itself: back to what createSite
      // set, so nginx reads through the group and other sites can't enter.
      await fs.chmod(dest, 0o2750);
      ok('Site files restored');
    } else {
      warn('No site files found in archive');
    }

    if (type === 'wordpress') {
      step('Restore the database');
      const sqlFile = `${tmpDir}/db.sql`;
      // lstat, not pathExists: chown/chmod follow links, so a symlinked db.sql
      // would hand the link's TARGET (any root file) to the site's user.
      const sqlStat = await fs.lstat(sqlFile).catch(() => null);
      if (sqlStat && !sqlStat.isFile()) throw new Error('The archive\'s database dump is not a regular file — it was not imported.');
      if (sqlStat) {
        // Hand the dump to the site through its own tmp dir: wp-cli runs as the
        // site's user and can't (and mustn't) read the root-only staging dir.
        // Ownership is set while the file is still in staging: once it is in
        // the site's tmp/ the site could swap what the name points at.
        const handed = `${siteTmp(domain)}/wcloud-import-${randomBytes(6).toString('hex')}.sql`;
        const { uid, gid } = await userIds(s.user);
        await fs.chown(sqlFile, uid, gid);
        await fs.chmod(sqlFile, 0o600);
        await mustRun(helpers, 'mv', ['--', sqlFile, handed], 'Preparing the database dump');

        const wp = await wpCli(helpers, s);
        const importR = await wp(['db', 'import', handed]);
        await fs.unlink(handed).catch(() => {}); // in the site's tmp/: never a recursive delete as root
        if (importR.code !== 0) throw new Error('Database import failed');
        ok('Database imported');

        // Coming from RunCloud (wcloud-site.json source): its LiteSpeed stack's
        // cache plugin does nothing on nginx — first, before any other wp-cli
        // run loads its object-cache drop-in.
        if (src.source === 'runcloud') {
          try {
            const ls = await retireLiteSpeedCache(helpers, s);
            if (ls.active || ls.removed.length) {
              step('Turn off LiteSpeed Cache');
              ok(`${ls.active ? 'Deactivated LiteSpeed Cache' : 'LiteSpeed Cache was already inactive'}${ls.removed.length ? ` and removed its ${ls.removed.map((f) => f.split('/').pop()).join(' + ')}` : ''} — it only works on a LiteSpeed server; wcloud's server page cache takes over`);
            }
          } catch (e) {
            warn(`LiteSpeed Cache is still active (${e.message}) — deactivate it from the Plugins tab`);
          }
        }

        if (domainChanged) {
          step('Update site URLs');
          // The domain only where a host name starts: not inside another name
          // (walmart.com for art.com) and not as the domain of an e-mail
          // address (admin@source) — accounts and form recipients keep their
          // mailbox. %2F may come before it, so URL-encoded links are rewritten
          // too. --regex runs in PHP, so serialized data is handled as before.
          // --all-tables covers options, usermeta, postmeta, custom tables.
          const from = `(?:(?<![A-Za-z0-9@-])|(?<=%2[Ff]))${sourceDomain.replace(/\./g, '\\.')}(?![A-Za-z0-9-])`;
          const replaceR = await wp(['search-replace', from, domain, '--regex', '--all-tables', '--report-changed-only']);
          if (replaceR.code !== 0) warn('URL search-replace had issues — may need manual review');
          else ok(`URLs updated: ${sourceDomain} → ${domain}`);
        }

        await clearWpCaches(helpers, s);
        ok('Caches cleared');
      } else {
        warn('No database dump found in archive');
      }
      // Open again — before the certificate step: the rule would also answer
      // Let's Encrypt's check with a 503.
      await deleteRule(helpers, domain, RESTORING_RULE);
    }

    let cfIssued = false;
    if (cfToken && cfZoneId) {
      step('Issue the HTTPS certificate (Let\'s Encrypt via Cloudflare DNS)');
      const r = await issueDnsCloudflare(helpers, domain, { www: enableWww, token: cfToken, zoneId: cfZoneId });
      if (r.ok) { cfIssued = true; ok(`SSL issued for ${domain} — renews automatically`); }
      else warn(`Cloudflare DNS validation failed${includeSsl ? ' — trying the archived certificate' : ''}`);
    }
    // An archived certificate is only installed when it works here: it names
    // THIS domain (a restore to another domain would serve the source's
    // certificate, which every browser refuses), its key is its own and it has
    // not expired — nginx accepts all of those. Never when the archived site
    // had HTTPS off: that keeps the certificate on disk, so it is in the backup
    // (RunCloud and older archives don't say → as before). Refused or not in
    // the archive: a new one is issued below, when that was asked for.
    const archivedCert = `${tmpDir}/ssl/live/fullchain.pem`;
    const archivedKey = `${tmpDir}/ssl/live/key.pem`;
    const httpsWasOff = includeSsl && src.ssl === false;
    let copySsl = includeSsl && !cfIssued && !httpsWasOff && (await isRealFile(archivedCert));
    if (copySsl) {
      try {
        checkCustomCert(domain, await fs.readFile(archivedCert, 'utf8'),
          (await isRealFile(archivedKey)) ? await fs.readFile(archivedKey, 'utf8') : '', { www: enableWww });
      } catch (e) {
        copySsl = false;
        // The reason only: the rest is advice for someone pasting a certificate.
        warn(`The archived certificate was not installed: ${e.message.split('. ')[0]}`);
      }
    }
    if (cfIssued) {
      // done
    } else if (copySsl) {
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
    } else if (httpsWasOff) {
      skip('SSL — HTTPS was off on the archived site; it stays off');
    } else if (issueSsl) {
      step('Issue SSL certificate');
      const r = await issueHttp(helpers, domain, { www: enableWww });
      if (r.ok) ok(`SSL issued for ${domain}`);
      else warn('SSL failed (DNS/propagation?) — issue it from the site page later');
    } else {
      // includeSsl here = the archived certificate was refused above, not a choice.
      skip(includeSsl ? 'SSL — the site is restored on HTTP; issue HTTPS from the site page' : 'SSL — "No SSL" selected');
    }

    // After the DB import, so the imported home/siteurl don't win.
    if (type === 'wordpress') {
      step('Set the WordPress address');
      await syncWpAddress(helpers, await readSpec(domain));
    }
    // Cron jobs travel with the site (validated like new ones); Cloudflare
    // cache doesn't — it belongs to the destination's zone and is set up there.
    if (type === 'wordpress') {
      const cur = await readSpec(domain);
      const crons = [];
      for (const j of (Array.isArray(src.crons) ? src.crons : []).slice(0, CRON_MAX)) {
        const { job: c, error } = cleanJob(j, crons.map((x) => x.id));
        if (error) warn(`The cron job "${String(j?.name || '').slice(0, 60)}" was left out: ${error}`);
        else if (c && !fitsCron(cur, c)) warn(`The cron job "${c.name}" was left out: its command is too long for cron — put it in a script file and schedule the script`);
        else if (c) crons.push(c);
      }
      const wpCron = src.wpCron === 'server' ? 'server' : 'wordpress';
      if (crons.length || wpCron === 'server') {
        step('Restore the cron jobs');
        if (wpCron === 'server' && !(await setWpConstant(helpers, cur, 'DISABLE_WP_CRON', 'true'))) warn('Could not set DISABLE_WP_CRON — WordPress will also run its cron on visits');
        await applySite(helpers, { ...cur, crons, wpCron, wpCronEvery: WP_CRON_EVERY.includes(src.wpCronEvery) ? src.wpCronEvery : 5 });
        ok(`${crons.length} cron job${crons.length === 1 ? '' : 's'}${wpCron === 'server' ? ' + WordPress cron run by the server' : ''}`);
      }
      // PHP settings and FPM sizing travel too (dropped if they don't validate here).
      const phpSettings = cleanPhpSettings(src.phpSettings || {}).value || {};
      const fpm = cleanFpm(src.fpm || {}).value || {};
      if (Object.keys(phpSettings).length || Object.keys(fpm).length) {
        step('Restore the PHP settings');
        await applySite(helpers, { ...(await readSpec(domain)), phpSettings, fpm });
        ok('PHP and PHP-FPM settings restored');
      }
      // The archive's helper plugin may come from another setup — rewrite or drop it.
      await syncCachePlugin(helpers, await readSpec(domain)).catch((e) => warn(`Cache helper not installed: ${e.message}`));
      await syncLiteSpeedGuard(helpers, await readSpec(domain)).catch((e) => warn(`LiteSpeed Cache guard not installed: ${e.message}`));
      // Object cache on by default, like a new site — unless the archive says
      // the source had it off (RunCloud and older archives don't say → on).
      if (src.objectCache !== false) {
        step('Turn on the object cache (Redis)');
        await setObjectCache(helpers, await readSpec(domain), true)
          .catch((e) => warn(`The object cache couldn't be turned on (${e.message}) — turn it on from the site page.`));
      }
    }

    // Redirects travel with the site (both site types), checked entry by entry
    // like new ones. Last, so a whole-domain redirect can't get in the way of
    // the steps above — and that one belongs to the domain: a copy under
    // another domain doesn't take it.
    const redirects = (Array.isArray(src.redirects) ? src.redirects : []).slice(0, REDIRECT_MAX)
      .flatMap((r) => { const c = cleanRedirects([r]); return Array.isArray(c) ? c : []; });
    const domainRedirect = (!domainChanged && src.domainRedirect && cleanDomainRedirect(src.domainRedirect, domain).value) || null;
    if (redirects.length || domainRedirect) {
      step('Restore the redirects');
      // A refusal must not cost the restored site: warn, keep going.
      try {
        await applySite(helpers, { ...(await readSpec(domain)), redirects, ...(domainRedirect ? { domainRedirect } : {}) });
        ok(`${redirects.length} redirect${redirects.length === 1 ? '' : 's'}${domainRedirect ? ` + the whole domain → ${domainRedirect.to}` : ''}`);
      } catch (e) {
        warn(`The redirects could not be restored (${e.message}) — add them again on the Redirects & rules tab`);
      }
    }

    log(`Restore completed: ${domain}`);
  } catch (e) {
    if (siteCreated) {
      warn('Restore failed — removing the half-created site');
      try {
        // Without the job's signal: after a cancel or a timeout nothing would run.
        await deleteSite({ ...helpers, signal: undefined }, domain);
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
