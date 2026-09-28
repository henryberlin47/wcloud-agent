import net from 'node:net';
import fs from 'node:fs/promises';
import { run, withLock, lockBusy } from './sys.js';
import { installedPhp, fpmService, redisPing } from './stack.js';
import { listSites } from './sites.js';

// ============================================================
//  watchdog.js — keep the server's stack healthy
// ============================================================
// Every AGENT_WATCHDOG_MS (default 60s; 0 = off) each service is checked by
// what it DOES, not just "is the unit active": nginx answers on :80, every
// site's PHP-FPM socket accepts a connection, MariaDB answers a ping, Redis
// answers PING; cron runs; the disk has room. A failed check → restart that
// service, then re-check. Safeguards:
//  - nginx is never restarted with a config that fails `nginx -t` (it would
//    stay down) — that's reported instead;
//  - nginx / PHP-FPM heal under the 'config' lock, and a round is skipped while
//    a config change or package install is in progress;
//  - a service restarted GIVE_UP times within WINDOW_MS is left alone
//    ("needs a look") rather than restarted in a loop.
// Heals are logged to the agent's journal (portal: server → Agent log).
// GET /api/health returns the last result; GET /api/stack the summary the
// portal's health sweep stores per server.
// ============================================================

export const WATCHDOG_MS = parseInt(process.env.AGENT_WATCHDOG_MS ?? '60000', 10) || 0;
const GIVE_UP = 3;
const WINDOW_MS = 30 * 60_000;
const H = { log: () => {}, err: () => {} };

const state = { checkedAt: null, checks: [], heals: [] };
const restarts = new Map(); // key → [timestamps]

const unitActive = async (unit) => (await run(H, 'systemctl', ['is-active', unit], { quiet: true, timeout: 10_000 })).stdout.trim() === 'active';
const connects = (opts, ms = 3000) => new Promise((resolve) => {
  const s = net.connect(opts);
  const done = (ok) => { s.destroy(); resolve(ok); };
  s.setTimeout(ms, () => done(false));
  s.once('connect', () => done(true));
  s.once('error', () => done(false));
});

// Each check: { key, label, unit?, heal: bool, probe: () => null | problem }
async function checksFor() {
  const sites = await listSites();
  const list = [
    { key: 'nginx', label: 'Web server (nginx)', unit: 'nginx', lock: 'config',
      probe: async () => (!(await unitActive('nginx')) ? 'not running' : !(await connects({ host: '127.0.0.1', port: 80 })) ? 'not answering on port 80' : null) },
  ];
  for (const v of await installedPhp()) {
    // Only sites whose pool is in place: one being deleted or moved between
    // versions has a spec but (for a moment) no pool — not a failure.
    const socks = [];
    for (const s of sites.filter((x) => x.type === 'wordpress' && x.php === v)) {
      if (await fs.access(`/etc/php/${v}/fpm/pool.d/${s.domain}.conf`).then(() => true, () => false)) socks.push({ domain: s.domain, path: `/run/php/wcloud-${s.domain}.sock` });
    }
    list.push({ key: `php${v}`, label: `PHP ${v} (FPM)`, unit: fpmService(v), lock: 'config',
      probe: async () => {
        if (!(await unitActive(fpmService(v)))) return 'not running';
        const dead = [];
        for (const k of socks) if (!(await connects({ path: k.path }, 2000))) dead.push(k.domain);
        return dead.length ? `not answering for ${dead.slice(0, 3).join(', ')}${dead.length > 3 ? ` and ${dead.length - 3} more` : ''}` : null;
      } });
  }
  list.push(
    { key: 'mariadb', label: 'Database (MariaDB)', unit: 'mariadb',
      probe: async () => (!(await unitActive('mariadb')) ? 'not running' : (await run(H, 'mysqladmin', ['ping'], { quiet: true, timeout: 10_000 })).code !== 0 ? 'not answering' : null) },
    { key: 'redis', label: 'Object cache (Redis)', unit: 'redis-server',
      probe: async () => (!(await unitActive('redis-server')) ? 'not running' : !(await redisPing(H)) ? 'not answering' : null) },
    { key: 'cron', label: 'Scheduler (cron)', unit: 'cron', probe: async () => (!(await unitActive('cron')) ? 'not running' : null) },
    { key: 'disk', label: 'Disk space', noHeal: true,
      probe: async () => {
        const st = await fs.statfs('/');
        const free = st.bavail / st.blocks;
        const gb = (st.bavail * st.bsize) / 1024 ** 3;
        return free < 0.05 ? `only ${gb.toFixed(1)} GB (${Math.round(free * 100)}%) free — sites and databases will start failing` : null;
      },
      warn: async () => {
        const st = await fs.statfs('/');
        return st.bavail / st.blocks < 0.1 ? `${Math.round((st.bavail / st.blocks) * 100)}% free` : null;
      } },
  );
  return list;
}

async function heal(c, problem) {
  const now = Date.now();
  const recent = (restarts.get(c.key) || []).filter((t) => now - t < WINDOW_MS);
  if (recent.length >= GIVE_UP) return { status: 'error', detail: `${problem} — restarted ${recent.length}× in 30 min without lasting; needs a look` };
  if (c.key === 'nginx') {
    const t = await run(H, 'nginx', ['-t'], { quiet: true, timeout: 30_000 });
    if (t.code !== 0) {
      const why = `${t.stderr}\n${t.stdout}`.split('\n').find((l) => /\[emerg\]/.test(l))?.replace(/^.*\[emerg\]\s*\d+#\d+:\s*/, '') || 'config test fails';
      return { status: 'error', detail: `${problem}, and its config doesn't pass nginx -t (${why.slice(0, 160)}) — not restarted` };
    }
  }
  recent.push(now);
  restarts.set(c.key, recent);
  const restart = () => run(H, 'systemctl', ['restart', c.unit], { quiet: true, timeout: 90_000 });
  const r = c.lock ? await withLock(c.lock, restart) : await restart();
  await new Promise((res) => setTimeout(res, 2000));
  const after = r.code === 0 ? await c.probe() : 'restart failed';
  const ok = !after;
  state.heals.unshift({ at: new Date().toISOString(), key: c.key, label: c.label, problem, ok, detail: ok ? 'restarted — healthy again' : `restarted, still ${after}` });
  state.heals.length = Math.min(state.heals.length, 50);
  (ok ? console.log : console.error)(`[watchdog] ${c.label}: ${problem} → restarted ${c.unit}${ok ? ', healthy again' : `, still ${after}`}`);
  return ok ? { status: 'ok', detail: `was ${problem} — restarted, healthy again`, healed: true } : { status: 'error', detail: `${problem}; restarted, still ${after}` };
}

let running = null;
/** One round: check everything, heal what failed. Concurrent callers share a round. */
export function checkNow() {
  running ||= (async () => {
    // Mid config change / package install: services may be down on purpose.
    const busy = lockBusy('config') || lockBusy('apt');
    const out = [];
    for (const c of await checksFor()) {
      let problem = null;
      try { problem = await c.probe(); } catch (e) { problem = `check failed (${e.message})`; }
      if (!problem) {
        const w = c.warn ? await c.warn().catch(() => null) : null;
        out.push({ key: c.key, label: c.label, status: w ? 'warn' : 'ok', detail: w });
      } else if (c.noHeal) out.push({ key: c.key, label: c.label, status: 'error', detail: problem });
      else if (busy) out.push({ key: c.key, label: c.label, status: 'warn', detail: `${problem} — a change is in progress, checking again next round` });
      else out.push({ key: c.key, label: c.label, ...(await heal(c, problem)) });
    }
    state.checks = out;
    state.checkedAt = new Date().toISOString();
    return snapshot();
  })().finally(() => { running = null; });
  return running;
}

export const snapshot = () => ({ enabled: WATCHDOG_MS > 0, intervalMs: WATCHDOG_MS, checkedAt: state.checkedAt, checks: state.checks, heals: state.heals.slice(0, 20) });

/** { status: ok|warn|error|unknown, problems: [label: detail] } — for the portal's health sweep. */
export function summary() {
  if (!state.checkedAt) return { status: 'unknown', problems: [] };
  const bad = state.checks.filter((c) => c.status === 'error');
  const warn = state.checks.filter((c) => c.status === 'warn');
  return {
    status: bad.length ? 'error' : warn.length ? 'warn' : 'ok',
    problems: [...bad, ...warn].map((c) => `${c.label}: ${c.detail}`),
    checkedAt: state.checkedAt,
  };
}

export function startWatchdog() {
  if (!WATCHDOG_MS) return;
  const tick = () => checkNow().catch((e) => console.error('[watchdog]', e.message));
  setTimeout(tick, 20_000).unref(); // after startup's reconcile has begun
  setInterval(tick, Math.max(WATCHDOG_MS, 15_000)).unref();
}
