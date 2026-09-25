import fs from 'node:fs/promises';
import { constants as FS } from 'node:fs';
import { phpLogPath } from './sites.js';
import { cronLogPath } from './cron.js';

// ============================================================
//  sitelogs.js — the tail of a site's access / error / PHP log
// ============================================================
// nginx's logs are root-owned in /var/log/nginx; the PHP log is written by the
// site's own user in the root-owned /var/log/wcloud. Read without following
// symlinks, capped at the last 4 MB, filtered, last `lines` returned.

export const LOG_TYPES = {
  access: (d) => `/var/log/nginx/${d}.access.log`,
  error: (d) => `/var/log/nginx/${d}.error.log`,
  php: (d) => phpLogPath(d),
  cron: (d) => cronLogPath(d),
};
const WINDOW = 4 * 1024 * 1024;

export async function readSiteLog(domain, type, { lines = 200, q = '' } = {}) {
  const path = LOG_TYPES[type](domain);
  let fh;
  try {
    fh = await fs.open(path, FS.O_RDONLY | FS.O_NOFOLLOW);
  } catch (e) {
    if (e.code === 'ENOENT') return { lines: [], size: 0, truncated: false };
    throw e;
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) return { lines: [], size: 0, truncated: false };
    const start = Math.max(0, st.size - WINDOW);
    const { buffer, bytesRead } = await fh.read(Buffer.alloc(st.size - start), 0, st.size - start, start);
    let all = buffer.subarray(0, bytesRead).toString('utf8').split('\n');
    if (start > 0) all = all.slice(1); // first line is cut
    all = all.filter(Boolean);
    const needle = q.toLowerCase();
    const hits = needle ? all.filter((l) => l.toLowerCase().includes(needle)) : all;
    return { lines: hits.slice(-lines), size: st.size, truncated: start > 0, matched: hits.length };
  } finally {
    await fh.close();
  }
}
