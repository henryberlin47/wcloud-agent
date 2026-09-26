import { spawn } from 'node:child_process';

// ============================================================
//  agentlog.js — the agent's own log (systemd journal of wcloud.service)
// ============================================================
// Startup, enrollment, job start/finish, background errors (renewals, purges,
// refreshes). Read with journalctl's JSON output → { time, level, message }.
// Filtered over the last WINDOW entries, newest `lines` returned.

const UNIT = 'wcloud';
const WINDOW = 5000;
// journald priorities → the portal's tones (stderr lines are "error" by the
// message itself when the unit doesn't tag them).
const LEVEL = (prio, msg) => (prio <= 3 || /\b(error|fail(ed|ure)?|timeout|refus|reject|unhandled)\b/i.test(msg) ? 'error'
  : prio === 4 || /\bwarn(ing)?\b/i.test(msg) ? 'warn' : 'info');

export function readAgentLog({ lines = 200, q = '' } = {}) {
  return new Promise((resolve) => {
    const child = spawn('journalctl', ['-u', UNIT, '-n', String(WINDOW), '-o', 'json', '--no-pager', '--output-fields=MESSAGE,PRIORITY'], { stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    child.stdout.setEncoding('utf8').on('data', (d) => { out += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 20_000);
    const done = (error) => {
      clearTimeout(timer);
      const all = [];
      for (const l of out.split('\n')) {
        if (!l) continue;
        let e; try { e = JSON.parse(l); } catch { continue; }
        // MESSAGE is an array of bytes when it isn't valid UTF-8.
        const message = Array.isArray(e.MESSAGE) ? Buffer.from(e.MESSAGE).toString('utf8') : String(e.MESSAGE ?? '');
        if (!message.trim()) continue;
        all.push({ time: new Date(Number(e.__REALTIME_TIMESTAMP) / 1000).toISOString(), level: LEVEL(Number(e.PRIORITY ?? 6), message), message });
      }
      const needle = q.toLowerCase();
      const hits = needle ? all.filter((x) => x.message.toLowerCase().includes(needle)) : all;
      resolve({ entries: hits.slice(-lines), matched: hits.length, ...(error && !all.length ? { error } : {}) });
    };
    child.on('error', (e) => done(`journalctl unavailable: ${e.message}`));
    child.on('close', () => done(null));
  });
}
