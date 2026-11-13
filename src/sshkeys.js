// ============================================================
//  sshkeys.js — read / remove authorized_keys entries, OUTSIDE the sandbox
// ============================================================
// wcloud.service hides /root and /home from the agent (ProtectHome), so
// lib/ssh.js runs this through `systemd-run --pipe` as its own transient
// service. Standalone (builtins only). Request JSON on stdin:
//   { op: 'list', akf }            → { keys: [{ user, file, type, fingerprint, comment, options, modifiedAt }] }
//   { op: 'remove', akf, list }    → { removed }   list: [{ user, fingerprint }]
// akf = sshd's AuthorizedKeysFile (from `sshd -T`). Failure: { error } on stdout, exit 1.
// Only users with a login shell; only regular files (a symlink a user planted
// must not make root read or write elsewhere).
// ============================================================
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

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

async function loginUsers() {
  const out = [];
  for (const l of (await fs.readFile('/etc/passwd', 'utf8')).split('\n')) {
    const [name, , , , , home, shell] = l.split(':');
    if (!name || !home || /(nologin|false|sync|shutdown|halt)$/.test(shell || '')) continue;
    out.push({ name, home });
  }
  return out;
}
const keyFiles = (u, akf) => (akf || '.ssh/authorized_keys .ssh/authorized_keys2').split(/\s+/).filter((f) => f && f !== 'none')
  .map((f) => f.replace(/%h/g, u.home).replace(/%u/g, u.name).replace(/%%/g, '%'))
  .map((f) => (path.isAbsolute(f) ? f : path.join(u.home, f)));

async function readRegular(f) {
  const st = await fs.lstat(f).catch(() => null);
  return st?.isFile() ? { text: await fs.readFile(f, 'utf8'), st } : null;
}

async function list(akf) {
  const keys = [];
  for (const u of await loginUsers()) {
    for (const file of keyFiles(u, akf)) {
      const r = await readRegular(file);
      if (!r) continue;
      for (const line of r.text.split('\n')) {
        const k = parseKeyLine(line);
        if (k) keys.push({ user: u.name, file, ...k, modifiedAt: r.st.mtime.toISOString() });
      }
    }
  }
  return { keys };
}

async function remove(akf, items) {
  let removed = 0;
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  for (const u of await loginUsers()) {
    const fps = new Set(items.filter((x) => x.user === u.name).map((x) => x.fingerprint));
    if (!fps.size) continue;
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
  }
  return { removed };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  let input = '';
  for await (const c of process.stdin) input += c;
  try {
    const req = JSON.parse(input);
    const out = req.op === 'remove' ? await remove(req.akf, req.list || []) : await list(req.akf);
    process.stdout.write(JSON.stringify(out));
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: e.message }));
    process.exitCode = 1;
  }
}
