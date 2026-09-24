// ============================================================
//  fm-worker.js — one file-manager operation, run AS THE SITE'S USER
// ============================================================
// Spawned by lib/files.js with the site's uid/gid and a clean env, so every
// operation has exactly the permissions the site's own PHP has: a symlink to
// /etc/shadow is as unreadable here as it is to WordPress. Paths are also
// confined lexically to the web root. Standalone (builtins only) because it
// runs outside the agent process.
//
//   node fm-worker.js <op> <root> <json args>
//   list {path} · stat {path} · read {path} → stdout · write {path, max} ← stdin
//   mkdir {path} · rename {from, to} · move/copy {paths[], to} · delete {paths[]}
// Result: JSON on stdout (read: the raw file). Failure: {code, message} on
// stderr, exit 1.
// ============================================================
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { pipeline } from 'node:stream/promises';

process.umask(0o022); // nginx (group www-data via htdocs' setgid) must read new files

const [, , op, root, rawArgs] = process.argv;
const a = JSON.parse(rawArgs || '{}');

const fail = (code, message) => Object.assign(new Error(message), { code });

// '../../etc' normalizes against '/' first, so it can only land inside root.
// resolve (not join): no trailing slash, so '/' and '' are exactly root and the
// notRoot guard can't be sidestepped.
function P(rel) {
  const p = path.resolve(root, `.${path.posix.normalize(`/${String(rel ?? '')}`)}`);
  if (p !== root && !p.startsWith(`${root}/`)) throw fail('EOUTSIDE', 'That path is outside the site.');
  return p;
}
const notRoot = (p) => { if (p === root) throw fail('EINVAL', 'The site folder itself can\'t be changed.'); return p; };
const exists = async (p) => { try { await fsp.lstat(p); return true; } catch { return false; } };
const refuseExisting = async (p) => { if (await exists(p)) throw fail('EEXIST', `${path.basename(p)} already exists there.`); };

const ops = {
  async list() {
    const dir = P(a.path);
    const out = [];
    for (const d of await fsp.readdir(dir, { withFileTypes: true })) {
      const full = path.join(dir, d.name);
      try {
        const st = await fsp.lstat(full);
        out.push({
          name: d.name,
          type: st.isSymbolicLink() ? 'link' : st.isDirectory() ? 'dir' : 'file',
          size: st.size,
          mtime: st.mtime.toISOString(),
          mode: (st.mode & 0o777).toString(8),
          ...(st.isSymbolicLink() ? { target: await fsp.readlink(full).catch(() => '') } : {}),
        });
      } catch { /* vanished between readdir and lstat */ }
    }
    return out;
  },

  // Readable check first: stat alone works on files the site can't read
  // (e.g. a symlink to /etc/shadow), which would leak their size and turn
  // into an empty 200 download instead of a clear refusal.
  async stat() {
    const p = P(a.path);
    await fsp.access(p, fs.constants.R_OK);
    const st = await fsp.stat(p);
    return { type: st.isDirectory() ? 'dir' : 'file', size: st.size, mtime: st.mtime.toISOString() };
  },

  async read() {
    const p = P(a.path);
    const st = await fsp.stat(p);
    if (!st.isFile()) throw fail('EISDIR', 'That is a folder, not a file.');
    await pipeline(fs.createReadStream(p), process.stdout);
    return undefined; // the file itself is the output
  },

  // Save/upload: stdin → temp file beside the target → rename, so a reader
  // never sees half a file and a failed upload leaves the old one intact.
  async write() {
    const p = notRoot(P(a.path));
    await fsp.mkdir(path.dirname(p), { recursive: true });
    const old = await fsp.stat(p).catch(() => null);
    if (old && !old.isFile()) throw fail('EISDIR', 'A folder with that name already exists.');
    const tmp = path.join(path.dirname(p), `.${path.basename(p)}.wcloud-${randomBytes(4).toString('hex')}`);
    let n = 0;
    const max = Number(a.max) || Infinity;
    try {
      await pipeline(process.stdin, async function* (src) {
        for await (const chunk of src) {
          n += chunk.length;
          if (n > max) throw fail('ETOOBIG', 'The file is larger than the upload limit.');
          yield chunk;
        }
      }, fs.createWriteStream(tmp, { flags: 'wx', mode: old ? old.mode & 0o777 : 0o644 }));
      await fsp.rename(tmp, p);
    } catch (e) {
      await fsp.rm(tmp, { force: true });
      throw e;
    }
    return { path: a.path, size: n };
  },

  async mkdir() {
    const p = notRoot(P(a.path));
    await refuseExisting(p);
    await fsp.mkdir(p, { recursive: true });
    return { path: a.path };
  },

  async rename() {
    const from = notRoot(P(a.from));
    const to = notRoot(P(a.to));
    await refuseExisting(to);
    await fsp.rename(from, to);
    return { from: a.from, to: a.to };
  },

  // Into a folder, keeping names. Refuses to overwrite anything.
  async move() { return intoDir((src, dst) => fsp.rename(src, dst)); },
  async copy() {
    return intoDir((src, dst) => fsp.cp(src, dst, { recursive: true, errorOnExist: true, force: false, verbatimSymlinks: true }));
  },

  async delete() {
    const paths = (a.paths || []).map((x) => notRoot(P(x)));
    for (const p of paths) await fsp.rm(p, { recursive: true });
    return { deleted: paths.length };
  },
};

async function intoDir(fn) {
  const dest = P(a.to);
  if (!(await fsp.stat(dest)).isDirectory()) throw fail('ENOTDIR', 'The destination must be a folder.');
  const done = [];
  for (const rel of a.paths || []) {
    const src = notRoot(P(rel));
    const dst = path.join(dest, path.basename(src));
    if (dst === src) throw fail('EINVAL', `${path.basename(src)} is already in that folder.`);
    if (dst.startsWith(`${src}/`)) throw fail('EINVAL', `${path.basename(src)} can't go inside itself.`);
    await refuseExisting(dst);
    await fn(src, dst);
    done.push(rel);
  }
  return { done };
}

try {
  if (!ops[op] || !root || !path.isAbsolute(root)) throw fail('EINVAL', `unknown operation ${op}`);
  const out = await ops[op]();
  if (out !== undefined) process.stdout.write(JSON.stringify(out));
} catch (e) {
  process.stderr.write(JSON.stringify({ code: e.code || 'EIO', message: e.message }));
  process.exitCode = 1;
}
