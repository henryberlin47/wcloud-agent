import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';

// ============================================================
//  terminal.js — a root shell for the portal's server Terminal tab
// ============================================================
// util-linux `script` gives the shell a real pseudo-terminal (prompt, colours,
// Ctrl+C, full-screen programs) without a native module. Output is read in
// raw bytes and streamed (base64, SSE) to whoever follows the session; input
// is written to script's stdin, which it copies to the terminal. The size is
// set on the shell's own tty with stty (the kernel then signals the program).
// A session ends when its shell exits, after IDLE_MS without input, or when
// nobody has followed it for ORPHAN_MS (the browser tab was closed).
// ============================================================

const MAX_SESSIONS = 10;
const IDLE_MS = 30 * 60_000;
const ORPHAN_MS = 2 * 60_000;
const KEEP_OUTPUT = 64 * 1024; // replayed to a stream that attaches late
const sessions = new Map();

const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, Math.floor(Number(n) || lo)));

export function openTerminal({ cols, rows } = {}) {
  for (const s of sessions.values()) if (s.closed) sessions.delete(s.id);
  if (sessions.size >= MAX_SESSIONS) throw Object.assign(new Error(`${MAX_SESSIONS} terminals are open on this server already — close one first.`), { status: 429 });
  const proc = spawn('script', ['-qfc', '/bin/bash --login', '/dev/null'], {
    cwd: '/root', detached: true, stdio: ['pipe', 'pipe', 'pipe'],
    env: { HOME: '/root', USER: 'root', LOGNAME: 'root', SHELL: '/bin/bash', TERM: 'xterm-256color', LANG: 'C.UTF-8', PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' },
  });
  const s = { id: randomUUID(), proc, out: [], outBytes: 0, listeners: new Set(), lastInput: Date.now(), lastFollowed: Date.now(), closed: false, code: null };
  sessions.set(s.id, s);
  const emit = (chunk) => {
    s.out.push(chunk); s.outBytes += chunk.length;
    while (s.outBytes > KEEP_OUTPUT && s.out.length > 1) s.outBytes -= s.out.shift().length;
    for (const l of s.listeners) l.data(chunk);
  };
  proc.stdout.on('data', emit);
  proc.stderr.on('data', emit);
  proc.stdin.on('error', () => {});
  proc.on('error', () => {});
  proc.on('close', (code) => { s.closed = true; s.code = code; clearInterval(s.timer); for (const l of s.listeners) l.exit(code); s.listeners.clear(); });
  s.timer = setInterval(() => {
    const now = Date.now();
    if (now - s.lastInput > IDLE_MS || (!s.listeners.size && now - s.lastFollowed > ORPHAN_MS)) closeTerminal(s.id);
  }, 15_000);
  s.timer.unref?.();
  if (cols && rows) setTimeout(() => resizeTerminal(s.id, { cols, rows }).catch(() => {}), 300); // once bash has its tty
  return s.id;
}

export const getTerminal = (id) => sessions.get(id) || null;

/** Follow a session: replays recent output, then live. → unsubscribe. */
export function followTerminal(id, { data, exit }) {
  const s = sessions.get(id);
  if (!s) return null;
  for (const c of s.out) data(c);
  if (s.closed) { exit(s.code); return () => {}; }
  const l = { data, exit };
  s.listeners.add(l);
  return () => { s.listeners.delete(l); s.lastFollowed = Date.now(); };
}

export function writeTerminal(id, text) {
  const s = sessions.get(id);
  if (!s || s.closed) return false;
  s.lastInput = Date.now();
  s.proc.stdin.write(text);
  return true;
}

// The shell's tty: script's child is the shell; its stdin is the terminal.
async function ttyOf(s) {
  if (s.tty) return s.tty;
  for (const p of await fs.readdir('/proc').catch(() => [])) {
    if (!/^\d+$/.test(p)) continue;
    const stat = await fs.readFile(`/proc/${p}/stat`, 'utf8').catch(() => '');
    if (Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]) !== s.proc.pid) continue; // field 4: parent pid
    const t = await fs.readlink(`/proc/${p}/fd/0`).catch(() => '');
    if (/^\/dev\/pts\/\d+$/.test(t)) return (s.tty = t);
  }
  return null;
}

export async function resizeTerminal(id, { cols, rows }) {
  const s = sessions.get(id);
  if (!s || s.closed) return false;
  const tty = await ttyOf(s);
  if (!tty) return false;
  await new Promise((done) => {
    const p = spawn('stty', ['-F', tty, 'cols', String(clamp(cols, 20, 500)), 'rows', String(clamp(rows, 5, 200))], { stdio: 'ignore' });
    p.on('close', done); p.on('error', done);
  });
  return true;
}

export function closeTerminal(id) {
  const s = sessions.get(id);
  if (!s) return false;
  sessions.delete(id);
  if (!s.closed) {
    try { process.kill(-s.proc.pid, 'SIGHUP'); } catch {}
    setTimeout(() => { try { process.kill(-s.proc.pid, 'SIGKILL'); } catch {} }, 3000).unref?.();
  }
  return true;
}
