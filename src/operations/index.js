import { runDelete } from './delete.js';
import { runUpdate } from './update.js';
import { runDeploy } from './deploy.js';
import { runSsl, runSslDnsVerify } from './ssl.js';
import { runCanonical } from './canonical.js';
import { runPurge } from './purge.js';
import { runResetPassword } from './resetPassword.js';
import { runExport } from './export.js';
import { runImport } from './import.js';
import { runBackup } from './backup.js';
import { runRestore } from './restore.js';
import { runPhp } from './php.js';
import { runPlugin } from './plugin.js';
import { runCache } from './cache.js';
import { runIndexing } from './indexing.js';
import { runSiteconfig, runNginxrule } from './siteconfig.js';
import { runCron } from './cron.js';
import { runCfCache } from './cfcache.js';
import { cleanJob, WP_CRON_EVERY } from '../lib/cron.js';
import { cleanRedirects } from '../lib/sites.js';
import { RULE_MAX } from '../lib/nginxrules.js';
import { CACHE_MODES } from '../lib/sites.js';
import { PLUGIN_NAME, UPLOAD_NAME } from '../lib/plugins.js';
import { SITE_TYPES } from '../lib/sites.js';
import { PHP_VERSIONS, DEFAULT_PHP } from '../lib/stack.js';

// ============================================================
//  Operation registry
// ============================================================
// Each operation defines:
//   - validate(params) -> { ok, errors[], clean }   (never trust the network)
//   - run(job, helpers, params)                       (the actual work)
//
// SECURITY: validation is the injection boundary. Domains are checked
// against strict patterns so nothing dangerous reaches a shell.
// ============================================================

// --- validation primitives -------------------------------------------------

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

// Hostnames are case-insensitive and are routinely pasted with a scheme and/or
// a trailing path ("https://Example.COM/"). Normalise instead of rejecting.
export function normDomain(v) {
  return String(v ?? '')
    .trim()
    .replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, '') // strip scheme
    .replace(/\/.*$/, '')                          // drop path / trailing slash
    .replace(/^www\./i, '')                       // strip leading www. (any case — runs before toLowerCase)
    .toLowerCase();
}

// Domain parameters normalized the same way across all operations.
const DOMAIN_FIELDS = ['domain'];

function sanitize(p) {
  const out = { ...p };
  for (const k of DOMAIN_FIELDS) if (typeof out[k] === 'string') out[k] = normDomain(out[k]);
  return out;
}

export function isDomain(v) {
  return typeof v === 'string' && DOMAIN_RE.test(v);
}
function reqDomain(errors, name, v) {
  if (!isDomain(v)) errors.push(`${name} must be a valid domain`);
}

// S3/Spaces fields shared by the backup + restore ops. Validated here (the
// injection boundary); the agent passes them straight to the S3 client and never
// stores or logs them.
function reqSpaces(p, errors) {
  for (const f of ['space', 'key', 'endpoint', 'accessKeyId', 'secretAccessKey']) {
    if (typeof p[f] !== 'string' || !p[f]) errors.push(`${f} is required`);
  }
  if (typeof p.space === 'string' && p.space && !/^[a-z0-9][a-z0-9-]*$/.test(p.space)) {
    errors.push('space must be a valid Space name');
  }
  if (typeof p.key === 'string' && p.key && (!p.key.startsWith('backups/') || p.key.includes('..'))) {
    errors.push('key must be a backups/ object key');
  }
}

// ============================================================
//  deploy
// ============================================================
const deploy = {
  name: 'deploy',
  // params: { domain, type?: "wordpress"|"static", php?, wp_user?, wp_password?, canonical?: "www"|"root"|"none", enableWww?, issueSsl?, cert?, key? }
  // cert + key (PEM) = install the user's own certificate instead of Let's Encrypt.
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const type = p.type == null ? 'wordpress' : p.type;
    if (!SITE_TYPES.includes(type)) errors.push(`type must be one of: ${SITE_TYPES.join(', ')}`);
    const php = p.php == null || p.php === '' ? DEFAULT_PHP : p.php;
    const cache = p.cache == null ? 'fastcgi' : p.cache;
    if (!CACHE_MODES.includes(cache)) errors.push(`cache must be one of: ${CACHE_MODES.join(', ')}`);
    if (!PHP_VERSIONS.includes(php)) errors.push(`php must be one of: ${PHP_VERSIONS.join(', ')}`);

    const cert = typeof p.cert === 'string' ? p.cert.trim() : '';
    const key = typeof p.key === 'string' ? p.key : '';
    if (!!cert !== !!key) errors.push('a custom certificate needs both cert and key');
    if (cert.length > 60_000) errors.push('cert is too large (60KB max)');
    if (key.length > 60_000) errors.push('key is too large (60KB max)');

    let wpUser = typeof p.wp_user === 'string' ? p.wp_user.trim() : '';
    let wpPassword = typeof p.wp_password === 'string' ? p.wp_password : '';
    if (wpUser.length > 60) errors.push('wp_user must be 60 characters or fewer');
    if (wpPassword.length > 200) errors.push('wp_password must be 200 characters or fewer');
    // Optional pair: a lone value without its partner is dropped rather than
    // erroring — a username without its password (or vice versa) means nothing.
    if (!wpUser || !wpPassword) { wpUser = ''; wpPassword = ''; }

    let canonical = (p.canonical === 'www' || p.canonical === 'root' || p.canonical === 'none') ? p.canonical : 'none';
    const enableWww = p.enableWww !== false;
    if (canonical === 'www' && !enableWww) canonical = 'root'; // can't redirect to a host we don't serve
    // Explicit SSL choice from the portal (default: issue, as before). A custom
    // certificate replaces Let's Encrypt.
    const issueSsl = !cert && p.issueSsl !== false;

    // Cloudflare-managed DNS: the portal passes the zone token so the
    // certificate is issued over DNS-01 (redacted in job views: "token").
    let cf = {};
    if (issueSsl && p.cfToken != null) {
      if (typeof p.cfToken !== 'string' || !/^[A-Za-z0-9_-]{30,200}$/.test(p.cfToken)) errors.push('cfToken is invalid');
      if (typeof p.cfZoneId !== 'string' || !/^[a-f0-9]{32}$/.test(p.cfZoneId)) errors.push('cfZoneId is invalid');
      cf = { cfToken: p.cfToken, cfZoneId: p.cfZoneId };
    }
    return { ok: errors.length === 0, errors, clean: { domain: p.domain, type, php, cache, wp_user: wpUser, wp_password: wpPassword, canonical, enableWww, issueSsl, ...(cert ? { cert, key } : {}), ...cf } };
  },
  async run(job, helpers, p) {
    await runDeploy(job, helpers, p);
  },
};

// ============================================================
//  php — switch a site to another PHP version
// ============================================================
const phpOp = {
  name: 'php',
  // params: { domain, php }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    if (!PHP_VERSIONS.includes(p.php)) errors.push(`php must be one of: ${PHP_VERSIONS.join(', ')}`);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain, php: p.php } };
  },
  async run(job, helpers, p) {
    await runPhp(job, helpers, p);
  },
};

// ============================================================
//  plugin — manage a WordPress site's plugins (see plugin.js)
// ============================================================
const PLUGIN_ACTIONS = ['install', 'activate', 'deactivate', 'update', 'delete', 'auto-update-on', 'auto-update-off'];
const pluginOp = {
  name: 'plugin',
  // params: { domain, action, plugins?: [name], all?, slug?, upload?, activate?, replace? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const action = PLUGIN_ACTIONS.includes(p.action) ? p.action : null;
    if (!action) errors.push(`action must be one of: ${PLUGIN_ACTIONS.join(', ')}`);
    const clean = { domain: p.domain, action };
    if (action === 'install') {
      // Exactly one source: a WordPress.org slug or an uploaded zip.
      if (typeof p.upload === 'string' && p.upload) {
        if (!UPLOAD_NAME.test(p.upload)) errors.push('upload must be a file from the upload endpoint');
        clean.upload = p.upload;
      } else if (typeof p.slug === 'string' && /^[a-z0-9-]{1,100}$/.test(p.slug)) {
        clean.slug = p.slug;
      } else errors.push('slug (a WordPress.org plugin slug) or upload is required');
      clean.activate = p.activate === true;
      clean.replace = p.replace === true;
    } else if (action) {
      // update/activate/… accept all:true where wp-cli supports --all
      if (p.all === true && action !== 'delete') clean.all = true;
      else {
        const plugins = Array.isArray(p.plugins) ? p.plugins : [];
        if (!plugins.length || plugins.length > 200 || !plugins.every((n) => typeof n === 'string' && PLUGIN_NAME.test(n))) {
          errors.push('plugins must be a list of plugin names');
        }
        clean.plugins = plugins;
      }
    }
    return { ok: errors.length === 0, errors, clean };
  },
  async run(job, helpers, p) {
    await runPlugin(job, helpers, p);
  },
};

// ============================================================
//  cache — page cache mode + Redis object cache (see cache.js)
// ============================================================
const cacheOp = {
  name: 'cache',
  // params: { domain, mode?: "fastcgi"|"wprocket"|"off", objectCache?: boolean }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const clean = { domain: p.domain };
    if (p.mode != null) {
      if (!CACHE_MODES.includes(p.mode)) errors.push(`mode must be one of: ${CACHE_MODES.join(', ')}`);
      clean.mode = p.mode;
    }
    if (p.objectCache != null) {
      if (typeof p.objectCache !== 'boolean') errors.push('objectCache must be true or false');
      clean.objectCache = p.objectCache;
    }
    if (clean.mode == null && clean.objectCache == null) errors.push('nothing to change (mode or objectCache)');
    return { ok: errors.length === 0, errors, clean };
  },
  async run(job, helpers, p) {
    await runCache(job, helpers, p);
  },
};

// ============================================================
//  indexing — search engine visibility (see indexing.js)
// ============================================================
const indexingOp = {
  name: 'indexing',
  // params: { domain, enabled: boolean }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    if (typeof p.enabled !== 'boolean') errors.push('enabled must be true or false');
    return { ok: errors.length === 0, errors, clean: { domain: p.domain, enabled: p.enabled } };
  },
  async run(job, helpers, p) {
    await runIndexing(job, helpers, p);
  },
};

// ============================================================
//  siteconfig — real visitor IPs (Cloudflare) + redirects
// ============================================================
const siteconfigOp = {
  name: 'siteconfig',
  // params: { domain, realIp?: boolean, redirects?: [{ from, to, code, regex, keepQuery }] }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const clean = { domain: p.domain };
    if (p.realIp != null) {
      if (typeof p.realIp !== 'boolean') errors.push('realIp must be true or false');
      clean.realIp = p.realIp;
    }
    if (p.redirects != null) {
      const r = cleanRedirects(p.redirects);
      if (typeof r === 'string') errors.push(r); else clean.redirects = r;
    }
    if (clean.realIp == null && clean.redirects == null) errors.push('nothing to change');
    return { ok: errors.length === 0, errors, clean };
  },
  async run(job, helpers, p) {
    await runSiteconfig(job, helpers, p);
  },
};

// ============================================================
//  nginxrule — a site's named custom nginx rules (lib/nginxrules.js)
// ============================================================
const nginxruleOp = {
  name: 'nginxrule',
  // params: { domain, action: "save"|"delete", id?, name?, content?, enabled? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const action = p.action === 'save' || p.action === 'delete' ? p.action : null;
    if (!action) errors.push('action must be save or delete');
    const id = p.id == null || p.id === '' ? undefined : String(p.id);
    if (id !== undefined && !/^[a-z0-9][a-z0-9-]{0,39}$/.test(id)) errors.push('invalid rule id');
    if (action === 'delete' && !id) errors.push('id is required');
    const clean = { domain: p.domain, action, id };
    if (action === 'save') {
      const name = typeof p.name === 'string' ? p.name.trim() : '';
      const content = typeof p.content === 'string' ? p.content : '';
      if (!name || name.length > 60 || /[\r\n]/.test(name)) errors.push('name is required (60 characters max, one line)');
      if (content.length > RULE_MAX || content.includes('\0')) errors.push('content is too large');
      Object.assign(clean, { name, content, enabled: p.enabled !== false });
    }
    return { ok: errors.length === 0, errors, clean };
  },
  async run(job, helpers, p) {
    await runNginxrule(job, helpers, p);
  },
};

// ============================================================
//  cron — a WordPress site's scheduled jobs (operations/cron.js)
// ============================================================
const cronOp = {
  name: 'cron',
  // params: { domain, action: save|delete|run|wpcron, job?, id?, wpCron?, every? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const clean = { domain: p.domain, action: p.action };
    if (p.action === 'save') {
      const { job, error } = cleanJob(p.job || {}, []); // id collisions are resolved at run time
      if (error) errors.push(error);
      else clean.job = { ...job, id: typeof p.job?.id === 'string' && /^[a-z0-9][a-z0-9-]{0,39}$/.test(p.job.id) ? p.job.id : undefined };
    } else if (p.action === 'delete' || p.action === 'run') {
      if (typeof p.id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,39}$/.test(p.id)) errors.push('invalid job id');
      clean.id = p.id;
    } else if (p.action === 'wpcron') {
      if (p.wpCron !== 'server' && p.wpCron !== 'wordpress') errors.push('wpCron must be server or wordpress');
      clean.wpCron = p.wpCron;
      clean.every = WP_CRON_EVERY.includes(Number(p.every)) ? Number(p.every) : 5;
    } else {
      errors.push('action must be save, delete, run or wpcron');
    }
    return { ok: errors.length === 0, errors, clean };
  },
  async run(job, helpers, p) {
    await runCron(job, helpers, p);
  },
};

// ============================================================
//  cfcache — Cloudflare cache purging for a site (operations/cfcache.js)
// ============================================================
const cfcacheOp = {
  name: 'cfcache',
  // params: { domain, enabled, cfToken?, cfZoneId?, hosts? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    if (typeof p.enabled !== 'boolean') errors.push('enabled must be true or false');
    const clean = { domain: p.domain, enabled: p.enabled };
    if (p.enabled) {
      if (typeof p.cfToken !== 'string' || !/^[A-Za-z0-9_-]{30,200}$/.test(p.cfToken)) errors.push('cfToken is required');
      if (typeof p.cfZoneId !== 'string' || !/^[a-f0-9]{32}$/.test(p.cfZoneId)) errors.push('cfZoneId is required');
      // Exactly as given (lowercased) — normDomain would strip the www. we need here.
      const hosts = Array.isArray(p.hosts) ? p.hosts.map((h) => String(h).trim().toLowerCase()) : [];
      if (!hosts.length || hosts.length > 2 || !hosts.every(isDomain)) errors.push('hosts must be the site\'s domain (and its www)');
      Object.assign(clean, { cfToken: p.cfToken, cfZoneId: p.cfZoneId, hosts });
    }
    return { ok: errors.length === 0, errors, clean };
  },
  async run(job, helpers, p) {
    await runCfCache(job, helpers, p);
  },
};

// ============================================================
//  update
// ============================================================
const update = {
  name: 'update',
  // params: { domain }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
  },
  async run(job, helpers, p) {
    await runUpdate(job, helpers, p);
  },
};

// ============================================================
//  delete
// ============================================================
const del = {
  name: 'delete',
  // params: { domain, confirm: true }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    if (p.confirm !== true) errors.push('confirm:true is required to delete a site');
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
  },
  async run(job, helpers, p) {
    await runDelete(job, helpers, p);
  },
};

// ============================================================
//  ssl — mode-driven SSL: off | le-http | le-dns-manual | custom
// ============================================================
// cert/key ride the authenticated body only. redactParams (jobs.js) masks
// them in every job view; the ops never log them. le-dns-manual starts the
// two-step manual DNS-01 flow (verified by the sslDnsVerify op).
const SSL_MODES = ['off', 'le-http', 'le-dns-manual', 'le-dns-cf', 'custom'];
const ssl = {
  name: 'ssl',
  // params: { domain, mode: "off"|"le-http"|"le-dns-cf"|"custom", cert?, key?, cfToken?, cfZoneId? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const mode = SSL_MODES.includes(p.mode) ? p.mode : null;
    if (!mode) errors.push(`mode is required (one of: ${SSL_MODES.join(', ')})`);

    let cert = '';
    let key = '';
    if (mode === 'custom') {
      cert = typeof p.cert === 'string' ? p.cert.trim() : '';
      key = typeof p.key === 'string' ? p.key : '';
      if (!cert) errors.push('cert is required (PEM fullchain)');
      if (!key) errors.push('key is required (PEM private key)');
      if (cert.length > 60_000) errors.push('cert is too large (60KB max)');
      if (key.length > 60_000) errors.push('key is too large (60KB max)');
    }

    // le-dns-cf: the Cloudflare token + zone come from the portal (the owner's
    // stored token for this domain); the key is redacted in job views.
    let cf = {};
    if (mode === 'le-dns-cf') {
      if (typeof p.cfToken !== 'string' || !/^[A-Za-z0-9_-]{30,200}$/.test(p.cfToken)) errors.push('cfToken is required');
      if (typeof p.cfZoneId !== 'string' || !/^[a-f0-9]{32}$/.test(p.cfZoneId)) errors.push('cfZoneId is required');
      cf = { cfToken: p.cfToken, cfZoneId: p.cfZoneId };
    }

    return {
      ok: errors.length === 0,
      errors,
      clean: { domain: p.domain, mode, ...(mode === 'custom' ? { cert, key } : {}), ...cf },
    };
  },
  async run(job, helpers, p) {
    await runSsl(job, helpers, p);
  },
};

// ============================================================
//  sslDnsVerify — step 2 of manual DNS-01 (verify the TXT records)
// ============================================================
const sslDnsVerify = {
  name: 'sslDnsVerify',
  // params: { domain }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
  },
  async run(job, helpers, p) {
    await runSslDnsVerify(job, helpers, p);
  },
};

// ============================================================
//  canonical — www / preferred-domain preference for a live site
// ============================================================
// Same shape deploy validates, so the two can never drift: a "www" preference
// requires www to be served, otherwise it would redirect to a host this server
// does not answer for.
const canonicalOp = {
  name: 'canonical',
  // params: { domain, canonical: "www"|"root"|"none", enableWww? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const canonical = (p.canonical === 'www' || p.canonical === 'root' || p.canonical === 'none') ? p.canonical : null;
    if (!canonical) errors.push('canonical is required (one of: www, root, none)');
    let enableWww = p.enableWww !== false;
    if (canonical === 'www' && !enableWww) {
      errors.push('www cannot be the preferred address while the www version is turned off');
    }
    return { ok: errors.length === 0, errors, clean: { domain: p.domain, canonical, enableWww } };
  },
  async run(job, helpers, p) {
    await runCanonical(job, helpers, p);
  },
};

// ============================================================
//  purge — clear a site's WP Rocket + object caches
// ============================================================
const purge = {
  name: 'purge',
  // params: { domain, only?: 'cloudflare' }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    if (p.only != null && p.only !== 'cloudflare') errors.push('only must be cloudflare');
    return { ok: errors.length === 0, errors, clean: { domain: p.domain, ...(p.only ? { only: p.only } : {}) } };
  },
  async run(job, helpers, p) {
    await runPurge(job, helpers, p);
  },
};

// ============================================================
//  resetPassword — set a new, known WordPress admin password
// ============================================================
const resetPassword = {
  name: 'resetPassword',
  // params: { domain, wp_password }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    const wpPassword = typeof p.wp_password === 'string' ? p.wp_password : '';
    if (!wpPassword) errors.push('wp_password is required');
    if (wpPassword.length > 200) errors.push('wp_password must be 200 characters or fewer');
    return { ok: errors.length === 0, errors, clean: { domain: p.domain, wp_password: wpPassword } };
  },
  async run(job, helpers, p) {
    await runResetPassword(job, helpers, p);
  },
};

// Archive work (export/import for migrations, backup/restore) can take hours on
// big sites, so these ops run past the default job timeout. Export/import used
// to get the 20-minute default, so migrating any large site was killed mid-way.
const BACKUP_TIMEOUT_MS = parseInt(process.env.AGENT_BACKUP_TIMEOUT_MS || String(12 * 3600 * 1000), 10);

// ============================================================
//  export — create a portable archive of a site (files + DB + optional SSL)
// ============================================================
const exportOp = {
  name: 'export',
  timeout: BACKUP_TIMEOUT_MS,
  // params: { domain, includeSsl?: boolean, encryptKey?: string }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    return {
      ok: errors.length === 0,
      errors,
      clean: { domain: p.domain, includeSsl: p.includeSsl === true, encryptKey: p.encryptKey || '' },
    };
  },
  async run(job, helpers, p) {
    await runExport(job, helpers, p);
  },
};

// ============================================================
//  import — restore a site from an export archive
// ============================================================
const importOp = {
  name: 'import',
  timeout: BACKUP_TIMEOUT_MS,
  // params: { sourceUrl, domain, sourceDomain?, includeSsl?, issueSsl?, sameServer?, localArchive?, encryptKey?, canonical?: "www"|"root"|"none", enableWww? }
  validate(p = {}) {
    const out = { ...p };
    if (typeof out.domain === 'string') out.domain = normDomain(out.domain);
    if (typeof out.sourceDomain === 'string') out.sourceDomain = normDomain(out.sourceDomain);
    const errors = [];
    // sourceUrl reaches `curl`. Anything but http(s) turns this into a local-file
    // read or an internal-network probe, so the scheme is checked here and curl
    // is additionally pinned to http/https (including across redirects) in
    // import.js — validate() is the boundary, the flag is the belt.
    if (!out.sourceUrl || typeof out.sourceUrl !== 'string') {
      errors.push('sourceUrl is required');
    } else if (!/^https?:\/\//i.test(out.sourceUrl)) {
      errors.push('sourceUrl must be an http(s) URL');
    }

    // localArchive is copied from and then REMOVED — recursively, as root. It is
    // only ever the agent's own export staging file handed back to us, so pin it
    // to that shape; an unchecked value here is an arbitrary `rm -rf`.
    const LOCAL_ARCHIVE_RE = /^\/tmp\/wcloud_export_[A-Za-z0-9]{6}\.tar\.gz(\.enc)?$/; // mkdtemp's 6-char suffix
    if (out.localArchive != null && out.localArchive !== '' && !LOCAL_ARCHIVE_RE.test(String(out.localArchive))) {
      errors.push('localArchive must be an export archive produced by this agent');
    }
    reqDomain(errors, 'domain', out.domain);
    if (out.sourceDomain && !isDomain(out.sourceDomain)) errors.push('sourceDomain must be a valid domain');
    // The source agent's public-key pin (base64 SHA-256 of its SPKI): its
    // certificate is self-signed, so this is what makes the download trusted.
    if (out.sourcePin != null && out.sourcePin !== '' && !/^[A-Za-z0-9+/]{43}=$/.test(String(out.sourcePin))) {
      errors.push('sourcePin must be a base64 SHA-256 public-key pin');
    }
    let canonical = (out.canonical === 'www' || out.canonical === 'root' || out.canonical === 'none') ? out.canonical : 'none';
    const enableWww = out.enableWww !== false;
    if (canonical === 'www' && !enableWww) canonical = 'root'; // can't redirect to a host we don't serve
    return {
      ok: errors.length === 0,
      errors,
      clean: {
        sourceUrl: out.sourceUrl,
        sourcePin: out.sourcePin || null,
        domain: out.domain,
        sourceDomain: out.sourceDomain || out.domain,
        includeSsl: out.includeSsl === true,
        issueSsl: out.issueSsl !== false,
        sameServer: out.sameServer === true,
        localArchive: out.localArchive || null,
        encryptKey: out.encryptKey || '',
        canonical,
        enableWww,
      },
    };
  },
  async run(job, helpers, p) {
    await runImport(job, helpers, p);
  },
};

// ============================================================
//  backup — encrypted site archive uploaded to the user's Spaces
// ============================================================
const backup = {
  name: 'backup',
  timeout: BACKUP_TIMEOUT_MS,
  // params: { domain, includeSsl?, encryptKey?, space, key, endpoint, accessKeyId, secretAccessKey }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    reqSpaces(p, errors);
    return {
      ok: errors.length === 0,
      errors,
      clean: {
        domain: p.domain,
        includeSsl: p.includeSsl === true,
        encryptKey: typeof p.encryptKey === 'string' ? p.encryptKey : '',
        space: p.space, key: p.key, endpoint: p.endpoint,
        accessKeyId: p.accessKeyId, secretAccessKey: p.secretAccessKey,
      },
    };
  },
  async run(job, helpers, p) {
    await runBackup(job, helpers, p);
  },
};

// ============================================================
//  restore — bring a site back from a Spaces backup (see restore.js)
// ============================================================
const restoreOp = {
  name: 'restore',
  timeout: BACKUP_TIMEOUT_MS,
  // params: { domain, sourceDomain?, includeSsl?, encryptKey?, canonical?, enableWww?, space, key, endpoint, accessKeyId, secretAccessKey }
  validate(p = {}) {
    const out = { ...p };
    if (typeof out.domain === 'string') out.domain = normDomain(out.domain);
    if (typeof out.sourceDomain === 'string') out.sourceDomain = normDomain(out.sourceDomain);
    const errors = [];
    reqDomain(errors, 'domain', out.domain);
    if (out.sourceDomain && !isDomain(out.sourceDomain)) errors.push('sourceDomain must be a valid domain');
    reqSpaces(out, errors);
    let canonical = (out.canonical === 'www' || out.canonical === 'root' || out.canonical === 'none') ? out.canonical : 'none';
    const enableWww = out.enableWww !== false;
    if (canonical === 'www' && !enableWww) canonical = 'root';
    return {
      ok: errors.length === 0,
      errors,
      clean: {
        domain: out.domain,
        sourceDomain: out.sourceDomain || out.domain,
        includeSsl: out.includeSsl === true,
        encryptKey: typeof out.encryptKey === 'string' ? out.encryptKey : '',
        canonical,
        enableWww,
        space: out.space, key: out.key, endpoint: out.endpoint,
        accessKeyId: out.accessKeyId, secretAccessKey: out.secretAccessKey,
      },
    };
  },
  async run(job, helpers, p) {
    await runRestore(job, helpers, p);
  },
};

// ---------------------------------------------------------------------------

export const operations = { deploy, php: phpOp, plugin: pluginOp, cache: cacheOp, indexing: indexingOp, siteconfig: siteconfigOp, nginxrule: nginxruleOp, cron: cronOp, cfcache: cfcacheOp, update, delete: del, ssl, sslDnsVerify, canonical: canonicalOp, purge, resetPassword, export: exportOp, import: importOp, backup, restore: restoreOp };

export function getOperation(type) {
  return operations[type] || null;
}
