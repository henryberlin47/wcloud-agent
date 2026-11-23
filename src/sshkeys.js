// ============================================================
//  sshkeys.js — read / remove authorized_keys entries, OUTSIDE the sandbox
// ============================================================
// wcloud.service hides /root and /home from the agent (ProtectHome), so
// lib/ssh.js runs this through `systemd-run --pipe` as its own transient
// service. Standalone (builtins only). Request JSON on stdin:
//   { op: 'list', akf }            → { keys: [{ user, file, type, fingerprint, comment, options, modifiedAt }] }
//   { op: 'remove', akf, list }    → { removed }   list: [{ user, fingerprint }]
//   { op: 'add', akf, list }       → { results: [{ user, added, file, fingerprint, comment }] }   list: [{ user, key }]
// akf = sshd's AuthorizedKeysFile (from `sshd -T`). Failure: { error } on stdout, exit 1.
// Only users with a login shell; only regular files.
// Each user's files are read and changed AS that user (asUser: a child process
// with its uid/gid), so a symlink or a race a user plants in ~/.ssh can only
// reach what that user could reach anyway — never root's files.
// ============================================================
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SELF = fileURLToPath(import.meta.url);
const KEY_TYPE = /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$/;

/** One authorized_keys line → { type, fingerprint, comment, options } (OpenSSH's SHA256 fingerprint), or null. */
export function parseKeyLine(line) {
  const t = line.trim();
  if (!t || t.startsWith('#')) return null;
  // Options may hold quoted spaces (command="a b"): split on spaces outside quotes.
  const parts = t.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
  const i = parts.findIndex((p) => KEY_TYPE.test(p));
  if (i < 0 || !parts[i + 1]) return null;
  const blob = Buffer.from(parts[i + 1], 'base64');
  if (!blob.length) return null;
  return {
    type: parts[i], fingerprint: `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`,
    comment: parts.slice(i + 2).join(' '), options: i > 0 ? parts.slice(0, i).join(' ') : '',
  };
}

/** A key to add: `<type> <base64> [comment]`, one line, no options → { type, fingerprint, comment, line }, or { error }. */
export function parseNewKey(input) {
  const line = String(input ?? '').trim();
  if (line.length > 16 * 1024) return { error: 'The key is over 16 KB.' };
  if (/PRIVATE KEY/.test(line)) return { error: 'That is a private key. Paste the public key line (the .pub file).' };
  const m = line.match(/^(\S+) (\S+)(?: (.*))?$/);
  if (!m || !KEY_TYPE.test(m[1])) return { error: 'Paste one public key line: its type (ssh-ed25519, ssh-rsa, ecdsa-sha2-…), the key, then an optional comment. Options are not allowed.' };
  const [, type, b64, comment = ''] = m;
  // The blob starts with its own type name (uint32 length + name): it must be the declared type.
  const blob = Buffer.from(b64, 'base64');
  const n = blob.length >= 4 ? blob.readUInt32BE(0) : -1;
  if (blob.toString('base64').replace(/=+$/, '') !== b64.replace(/=+$/, '') || n < 0 || 4 + n > blob.length || blob.toString('latin1', 4, 4 + n) !== type) {
    return { error: `The key data isn't a valid ${type} public key.` };
  }
  if (comment.length > 100 || !/^[\x20-\x7e]*$/.test(comment)) return { error: 'The comment is printable ASCII, 100 characters at most.' };
  return { type, fingerprint: parseKeyLine(line).fingerprint, comment, line };
}

async function loginUsers() {
  const out = [];
  for (const l of (await fs.readFile('/etc/passwd', 'utf8')).split('\n')) {
    const [name, , uid, gid, , home, shell] = l.split(':');
    if (!name || !home || /(nologin|false|sync|shutdown|halt)$/.test(shell || '')) continue;
    out.push({ name, home, uid: Number(uid), gid: Number(gid) });
  }
  return out;
}
const keyFiles = (u, akf) => (akf || '.ssh/authorized_keys .ssh/authorized_keys2').split(/\s+/).filter((f) => f && f !== 'none')
  .map((f) => f.replace(/%h/g, u.home).replace(/%u/g, u.name).replace(/%%/g, '%'))
  .map((f) => (path.isAbsolute(f) ? f : path.join(u.home, f)));

// Not a regular file, or not readable by this process (an admin-owned AuthorizedKeysFile): null.
async function readRegular(f) {
  try {
    const st = await fs.lstat(f);
    return st.isFile() ? { text: await fs.readFile(f, 'utf8'), st } : null;
  } catch {
    return null;
  }
}

// ── Child: one user's files (runs as that user) ─────────────────────────────

async function userKeys(u, akf) {
  const keys = [];
  for (const file of keyFiles(u, akf)) {
    const r = await readRegular(file);
    if (!r) continue;
    for (const line of r.text.split('\n')) {
      const k = parseKeyLine(line);
      if (k) keys.push({ user: u.name, file, ...k, modifiedAt: r.st.mtime.toISOString() });
    }
  }
  return keys;
}

async function userRemove(u, akf, fingerprints) {
  const fps = new Set(fingerprints);
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  let removed = 0;
  for (const file of keyFiles(u, akf)) {
    const r = await readRegular(file);
    if (!r) continue;
    const lines = r.text.split('\n');
    const keep = lines.filter((l) => !fps.has(parseKeyLine(l)?.fingerprint));
    if (keep.length === lines.length) continue;
    await fs.copyFile(file, `${file}.wcloud-${stamp}.bak`);
    const tmp = `${file}.wcloud-tmp`;
    await fs.rm(tmp, { force: true });
    await fs.writeFile(tmp, keep.join('\n'), { mode: r.st.mode & 0o777, flag: 'wx' });
    await fs.chown(tmp, r.st.uid, r.st.gid);
    await fs.rename(tmp, file);
    removed += lines.length - keep.length;
  }
  return removed;
}

// Appends to the user's first key file. Runs as the user: the folder and file must be theirs,
// and a link is refused (O_NOFOLLOW), so nothing outside their own files can be written.
async function userAdd(u, akf, key) {
  const k = parseNewKey(key);
  if (k.error) throw new Error(k.error);
  const files = keyFiles(u, akf);
  if (!files.length) throw new Error('sshd reads no key file for this user (AuthorizedKeysFile none).');
  const result = (added) => ({ added, file: files[0], fingerprint: k.fingerprint, comment: k.comment });
  const uid = process.getuid();
  const dir = path.dirname(files[0]); // ~/.ssh by default
  await fs.mkdir(dir, { mode: 0o700 }).catch((e) => { if (e.code !== 'EEXIST') throw e; });
  const d = await fs.lstat(dir);
  if (!d.isDirectory() || d.uid !== uid) throw new Error(`${dir} must be a folder of this user, not a link.`);
  const st = await fs.lstat(files[0]).catch(() => null);
  if (st && (!st.isFile() || st.uid !== uid)) throw new Error(`${files[0]} must be a file of this user, not a link.`);
  for (const f of files) {
    const r = await readRegular(f);
    if (r?.text.split('\n').some((l) => parseKeyLine(l)?.fingerprint === k.fingerprint)) return result(false);
  }
  const fh = await fs.open(files[0], fs.constants.O_RDWR | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW, 0o600);
  try {
    const fst = await fh.stat();
    if (!fst.isFile() || fst.uid !== uid) throw new Error(`${files[0]} must be a file of this user, not a link.`);
    let sep = '';
    if (fst.size) { const last = Buffer.alloc(1); await fh.read(last, 0, 1, fst.size - 1); if (last[0] !== 10) sep = '\n'; }
    await fh.appendFile(`${sep}${k.line}\n`);
  } finally {
    await fh.close();
  }
  return result(true);
}

// ── Root: one child per login user ──────────────────────────────────────────

// Runs this script as the user (uid/gid), in / so no root cwd leaks in, env cleared.
function asUser(u, req) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [SELF], { uid: u.uid, gid: u.gid, cwd: '/', env: {}, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.stdin.on('error', () => {}); // the child may exit before it reads its input
    p.on('error', reject);
    p.on('close', (code) => {
      let j = null;
      try { j = JSON.parse(out); } catch { /* below */ }
      if (code === 0 && j && !j.error) resolve(j);
      else reject(new Error(j?.error || err.trim().slice(0, 300) || `exit ${code}`));
    });
    p.stdin.end(JSON.stringify({ ...req, name: u.name, home: u.home }));
  });
}

async function list(akf) {
  const keys = [];
  for (const u of await loginUsers()) keys.push(...(await asUser(u, { op: 'list', akf })).keys);
  return { keys };
}

async function remove(akf, items) {
  let removed = 0;
  for (const u of await loginUsers()) {
    const fingerprints = items.filter((x) => x.user === u.name).map((x) => x.fingerprint);
    if (fingerprints.length) removed += (await asUser(u, { op: 'remove', akf, fingerprints })).removed;
  }
  return { removed };
}

// Every user and key is checked before the first write. Users must already exist with a login shell.
async function add(akf, list) {
  const users = await loginUsers();
  const todo = list.map((x) => {
    const u = users.find((v) => v.name === x.user);
    if (!u) throw new Error(`${x.user} isn't a user with a login shell on this server. Keys are only added to existing users.`);
    const k = parseNewKey(x.key);
    if (k.error) throw new Error(k.error);
    return { u, user: x.user, key: k.line };
  });
  const results = [];
  for (const t of todo) results.push({ user: t.user, ...(await asUser(t.u, { op: 'add', akf, key: t.key })) });
  return { results };
}

if (process.argv[1] === SELF) {
  let input = '';
  for await (const c of process.stdin) input += c;
  try {
    const req = JSON.parse(input);
    let out;
    const u = { name: req.name, home: req.home };
    if (req.home) out = req.op === 'remove' ? { removed: await userRemove(u, req.akf, req.fingerprints) }
      : req.op === 'add' ? await userAdd(u, req.akf, req.key) : { keys: await userKeys(u, req.akf) };
    else if (req.op === 'remove') out = await remove(req.akf, req.list || []);
    else out = req.op === 'add' ? await add(req.akf, req.list || []) : await list(req.akf);
    process.stdout.write(JSON.stringify(out));
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: e.message }));
    process.exitCode = 1;
  }
}
