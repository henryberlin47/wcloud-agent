import { runDelete } from './delete.js';
import { runUpdate } from './update.js';
import { runDeploy } from './deploy.js';
import { runSsl } from './ssl.js';
import { runPurge } from './purge.js';
import { runResetPassword } from './resetPassword.js';
import { runExport } from './export.js';
import { runImport } from './import.js';

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
    .toLowerCase();
}

// Domain parameters normalized the same way across all operations.
const DOMAIN_FIELDS = ['domain'];

function sanitize(p) {
  const out = { ...p };
  for (const k of DOMAIN_FIELDS) if (typeof out[k] === 'string') out[k] = normDomain(out[k]);
  return out;
}

function isDomain(v) {
  return typeof v === 'string' && DOMAIN_RE.test(v);
}
function reqDomain(errors, name, v) {
  if (!isDomain(v)) errors.push(`${name} must be a valid domain`);
}

// ============================================================
//  deploy
// ============================================================
const deploy = {
  name: 'deploy',
  // params: { domain, wp_user?, wp_password? }
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

    return { ok: errors.length === 0, errors, clean: { domain: p.domain, wp_user: wpUser, wp_password: wpPassword } };
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
//  ssl — re-issue Let's Encrypt cert (retry for a failed SSL step)
// ============================================================
const ssl = {
  name: 'ssl',
  // params: { domain }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
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
  // params: { sourceUrl, domain, sourceDomain?, includeSsl?, sameServer?, localArchive?, encryptKey? }
  validate(p = {}) {
    const out = { ...p };
    if (typeof out.domain === 'string') out.domain = normDomain(out.domain);
    if (typeof out.sourceDomain === 'string') out.sourceDomain = normDomain(out.sourceDomain);
    const errors = [];
    if (!out.sourceUrl || typeof out.sourceUrl !== 'string') errors.push('sourceUrl is required');
    reqDomain(errors, 'domain', out.domain);
    if (out.sourceDomain && !isDomain(out.sourceDomain)) errors.push('sourceDomain must be a valid domain');
    return {
      ok: errors.length === 0,
      errors,
      clean: {
        sourceUrl: out.sourceUrl,
        domain: out.domain,
        sourceDomain: out.sourceDomain || out.domain,
        includeSsl: out.includeSsl === true,
        sameServer: out.sameServer === true,
        localArchive: out.localArchive || null,
        encryptKey: out.encryptKey || '',
      },
    };
  },
  async run(job, helpers, p) {
    await runImport(job, helpers, p);
  },
};

// ---------------------------------------------------------------------------

export const operations = { deploy, update, delete: del, ssl, purge, resetPassword, export: exportOp, import: importOp };

export function getOperation(type) {
  return operations[type] || null;
}
