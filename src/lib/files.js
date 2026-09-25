import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { userIds } from './sys.js';
import { webRoot, siteTmp } from './sites.js';

// ============================================================
//  files.js — the site file manager (see ../fm-worker.js)
// ============================================================
// Every operation is a short-lived worker process running as the SITE's user
// with a clean env, confined to the site's web root. Never do file-manager I/O
// in the agent itself: it is root, and a site-controlled symlink would turn
// "read this file" into "read any file on the server".

const WORKER = fileURLToPath(new URL('../fm-worker.js', import.meta.url));
export const UPLOAD_MAX = 512 * 1024 * 1024; // matches the PHP upload limit

// HTTP status for a worker error code.
const STATUS = { ENOENT: 404, EEXIST: 409, EACCES: 403, EPERM: 403, ETOOBIG: 413 };
export const statusFor = (code) => STATUS[code] || 400;

// root: the folder the worker is confined to — the web root, or the site's
// private tmp/ for plugin uploads that must never be web-reachable.
export async function spawnWorker(site, op, args = {}, { root = webRoot(site.domain) } = {}) {
  const { uid, gid } = await userIds(site.user);
  return spawn(process.execPath, [WORKER, op, root, JSON.stringify(args)], {
    uid, gid, cwd: root,
    env: { PATH: '/usr/bin:/bin', HOME: siteTmp(site.domain), LANG: 'C.UTF-8' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

// Collect a worker's output. Resolves { ok, data | code, message }.
export function settle(child, { timeout = 60_000 } = {}) {
  return new Promise((resolve) => {
    let out = '';
    let err = '';
    const t = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => {
      clearTimeout(t);
      if (code === 0) {
        try { return resolve({ ok: true, data: out ? JSON.parse(out) : null }); } catch { return resolve({ ok: true, data: null }); }
      }
      let e = {};
      try { e = JSON.parse(err); } catch { /* killed or crashed */ }
      resolve({ ok: false, code: e.code || 'EIO', message: friendly(e) });
    });
  });
}

function friendly(e) {
  switch (e.code) {
    case 'ENOENT': return 'That file or folder no longer exists.';
    case 'EACCES': case 'EPERM': return 'The site doesn\'t have permission for that (permission denied).';
    case 'ENOTEMPTY': return 'That folder isn\'t empty.';
    case 'EISDIR': case 'ENOTDIR': case 'EEXIST': case 'EOUTSIDE': case 'EINVAL': case 'ETOOBIG': return e.message;
    default: return e.message ? `The operation failed: ${e.message}` : 'The operation failed.';
  }
}
