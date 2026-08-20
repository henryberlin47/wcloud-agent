import { runDelete } from './delete.js';
import { runUpdate } from './update.js';
import { runDeploy } from './deploy.js';
import { runSsl } from './ssl.js';
import { runPurge } from './purge.js';
import { runResetPassword } from './resetPassword.js';
import { runExport } from './export.js';
import { runImport } from './import.js';
import { runBackup } from './backup.js';
import { runRestore } from './restore.js';

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
    .replace(/^www\./, '')                         // strip leading www.
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
// injection boundary); the agent passes them through to rclone's env and never
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
  // params: { domain, wp_user?, wp_password?, canonical?: "www"|"root"|"none", enableWww?, issueSsl? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);

    let wpUser = typeof p.wp_user === 'string' ? p.wp_user.trim() : '';
    let wpPassword = typeof p.wp_password === 'string' ? p.wp_password : '';
    if (wpUser.length > 60) errors.push('wp_user must be 60 characters or fewer');
    if (wpPassword.length > 200) errors.push('wp_password must be 200 characters or fewer');
    // Optional pair: a lone value without its partner is dropped rather than
    // erroring — wo needs both --user and --pass together to be meaningful.
    if (!wpUser || !wpPassword) { wpUser = ''; wpPassword = ''; }

    let canonical = (p.canonical === 'www' || p.canonical === 'root' || p.canonical === 'none') ? p.canonical : 'none';
    const enableWww = p.enableWww !== false;
    if (canonical === 'www' && !enableWww) canonical = 'root'; // can't redirect to a host we don't serve
    // Explicit SSL choice from the portal (default: issue, as before).
    const issueSsl = p.issueSsl !== false;

    return { ok: errors.length === 0, errors, clean: { domain: p.domain, wp_user: wpUser, wp_password: wpPassword, canonical, enableWww, issueSsl } };
  },
  async run(job, helpers, p) {
    await runDeploy(job, helpers, p);
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
//  ssl — mode-driven SSL: off | le-http | custom
// ============================================================
// cert/key ride the authenticated body only. redactParams (jobs.js) masks
// them in every job view; the ops never log them.
const SSL_MODES = ['off', 'le-http', 'custom'];
const ssl = {
  name: 'ssl',
  // params: { domain, mode: "off"|"le-http"|"custom", cert?, key? }
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

    return {
      ok: errors.length === 0,
      errors,
      clean: { domain: p.domain, mode, ...(mode === 'custom' ? { cert, key } : {}) },
    };
  },
  async run(job, helpers, p) {
    await runSsl(job, helpers, p);
  },
};

// ============================================================
//  purge — clear a site's WP Rocket + object caches
// ============================================================
const purge = {
  name: 'purge',
  // params: { domain }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
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

// ============================================================
//  export — create a portable archive of a site (files + DB + optional SSL)
// ============================================================
const exportOp = {
  name: 'export',
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
  // params: { sourceUrl, domain, sourceDomain?, includeSsl?, issueSsl?, sameServer?, localArchive?, encryptKey?, canonical?: "www"|"root"|"none", enableWww? }
  validate(p = {}) {
    const out = { ...p };
    if (typeof out.domain === 'string') out.domain = normDomain(out.domain);
    if (typeof out.sourceDomain === 'string') out.sourceDomain = normDomain(out.sourceDomain);
    const errors = [];
    if (!out.sourceUrl || typeof out.sourceUrl !== 'string') errors.push('sourceUrl is required');
    reqDomain(errors, 'domain', out.domain);
    if (out.sourceDomain && !isDomain(out.sourceDomain)) errors.push('sourceDomain must be a valid domain');
    let canonical = (out.canonical === 'www' || out.canonical === 'root' || out.canonical === 'none') ? out.canonical : 'none';
    const enableWww = out.enableWww !== false;
    if (canonical === 'www' && !enableWww) canonical = 'root'; // can't redirect to a host we don't serve
    return {
      ok: errors.length === 0,
      errors,
      clean: {
        sourceUrl: out.sourceUrl,
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
// Backups can take hours on big sites, so this op runs past the default job
// timeout (AGENT_BACKUP_TIMEOUT_MS).
const BACKUP_TIMEOUT_MS = parseInt(process.env.AGENT_BACKUP_TIMEOUT_MS || String(12 * 3600 * 1000), 10);

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

export const operations = { deploy, update, delete: del, ssl, purge, resetPassword, export: exportOp, import: importOp, backup, restore: restoreOp };

export function getOperation(type) {
  return operations[type] || null;
}
