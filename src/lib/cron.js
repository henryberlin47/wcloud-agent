import fs from 'node:fs/promises';
import config from '../config.js';

// ============================================================
//  cron.js — a WordPress site's scheduled jobs (/etc/cron.d)
// ============================================================
// The spec holds `crons` [{ id, name, schedule, command, enabled }] and
// `wpCron` ('server' = WordPress's own cron is run by the system every
// `wpCronEvery` minutes and DISABLE_WP_CRON is set; anything else = visitors
// trigger it, WordPress's default). applySite renders one root-owned file,
// /etc/cron.d/wcloud-<domain>, in the same tested transaction as the vhost —
// so a PHP switch or a spec change re-renders it.
//
// Every line runs AS THE SITE'S USER (the user field is ours, never input),
// in its htdocs, with `php`/`wp` resolving to the site's PHP version (wrapper
// dir first on PATH), and appends to /var/log/wcloud/<d>.cron.log (Logs tab).
// The one thing a command could do to the file is break its format: newlines
// are refused (a new line could name another user — root) and `%` is escaped
// (cron turns it into a newline + stdin).
// ============================================================

export const CRON_MAX = 30;
export const COMMAND_MAX = 2000;
export const WP_CRON_EVERY = [1, 5, 15];
export const cronLogPath = (d) => `/var/log/wcloud/${d}.cron.log`;
// cron ignores /etc/cron.d names with dots — domain dots become underscores.
export const cronFilePath = (d) => `/etc/cron.d/wcloud-${d.replace(/[^A-Za-z0-9-]/g, '_')}`;
const wrapperDir = (php) => `/usr/local/lib/wcloud/php${php}`;
const siteRoot = (d) => `${config.wwwDir}/${d}`;

const PRESETS = new Set(['@hourly', '@daily', '@weekly', '@monthly']);
const FIELDS = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 7]]; // min hour dom month dow

function fieldOk(f, [lo, hi]) {
  return f.split(',').every((part) => {
    const m = part.match(/^(\*|(\d{1,2})(?:-(\d{1,2}))?)(?:\/(\d{1,2}))?$/);
    if (!m) return false;
    const [, , a, b, step] = m;
    if (step !== undefined && (+step < 1 || +step > hi)) return false;
    if (a === undefined) return true; // *
    if (+a < lo || +a > hi) return false;
    return b === undefined || (+b >= +a && +b <= hi);
  });
}

/** A cron schedule we accept: @hourly|@daily|@weekly|@monthly or 5 numeric fields. */
export function scheduleOk(s) {
  if (typeof s !== 'string') return false;
  const v = s.trim().replace(/\s+/g, ' ');
  if (PRESETS.has(v)) return true;
  const f = v.split(' ');
  return f.length === 5 && f.every((x, i) => fieldOk(x, FIELDS[i]));
}

/** Validate a job from a request → { job } or { error }. `taken` = ids in use. */
export function cleanJob(j, taken = []) {
  const name = typeof j?.name === 'string' ? j.name.trim() : '';
  const command = typeof j?.command === 'string' ? j.command.trim() : '';
  const schedule = typeof j?.schedule === 'string' ? j.schedule.trim().replace(/\s+/g, ' ') : '';
  if (!name || name.length > 60 || /[\r\n\0]/.test(name)) return { error: 'Give the job a name (60 characters max, one line)' };
  if (!command || command.length > COMMAND_MAX) return { error: `The command is required (${COMMAND_MAX} characters max)` };
  if (/[\r\n\0]/.test(command)) return { error: 'The command must be one line — chain steps with && or ;' };
  if (!scheduleOk(schedule)) return { error: `"${schedule}" isn't a valid schedule (5 fields like */5 * * * *, or @hourly / @daily / @weekly / @monthly)` };
  let id = typeof j?.id === 'string' && /^[a-z0-9][a-z0-9-]{0,39}$/.test(j.id) ? j.id : '';
  if (!id) {
    const base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32) || 'job';
    id = base;
    for (let i = 2; taken.includes(id); i++) id = `${base}-${i}`;
  }
  return { job: { id, name, schedule, command, enabled: j?.enabled !== false } };
}

// One cron line: run as the site user, in htdocs, logged with a header.
const q = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
function line(s, schedule, label, command) {
  const d = s.domain;
  const body = `{ echo "=== $(date -u '+%F %T') UTC — ${label}"; ${command}; } >> ${q(cronLogPath(d))} 2>&1`;
  return `${schedule} ${s.user} cd ${q(`${siteRoot(d)}/htdocs`)} && ${body}`.replace(/%/g, '\\%');
}

/** The cron.d file for a site, or null when it has nothing scheduled. */
export function renderCron(s) {
  if (s.type !== 'wordpress' || !s.php || !s.user) return null;
  const jobs = (Array.isArray(s.crons) ? s.crons : []).filter((j) => j.enabled !== false);
  const every = WP_CRON_EVERY.includes(s.wpCronEvery) ? s.wpCronEvery : 5;
  const lines = [];
  if (s.wpCron === 'server') lines.push(line(s, every === 1 ? '* * * * *' : `*/${every} * * * *`, 'WordPress cron', 'wp cron event run --due-now --quiet'));
  // Job ids are [a-z0-9-] — safe inside the echo; names aren't, so they stay out.
  for (const j of jobs) lines.push(line(s, j.schedule, j.id, j.command));
  if (!lines.length) return null;
  return [
    `# wcloud: scheduled jobs for ${s.domain} — generated from the site's settings; edits here are overwritten.`,
    'SHELL=/bin/sh',
    `PATH=${wrapperDir(s.php)}:/usr/local/bin:/usr/bin:/bin`,
    `HOME=${siteRoot(s.domain)}/tmp`,
    `WP_CLI_CACHE_DIR=${siteRoot(s.domain)}/tmp/.wp-cli-cache`,
    'MAILTO=""',
    ...lines,
    '',
  ].join('\n');
}

/** `php` and `wp` for one PHP version (what a site's cron PATH puts first). */
export async function ensureWrappers(php) {
  const dir = wrapperDir(php);
  await fs.mkdir(dir, { recursive: true, mode: 0o755 });
  const put = async (name, body) => {
    const p = `${dir}/${name}`;
    const want = `#!/bin/sh\n${body}\n`;
    if ((await fs.readFile(p, 'utf8').catch(() => null)) !== want) await fs.writeFile(p, want, { mode: 0o755 });
  };
  await put('php', `exec /usr/bin/php${php} "$@"`);
  await put('wp', `exec /usr/bin/php${php} /usr/local/bin/wp "$@"`);
}

/** The environment a job runs with ("Run now" uses the same one as cron). */
export const jobEnv = (s) => ({
  PATH: `${wrapperDir(s.php)}:/usr/local/bin:/usr/bin:/bin`,
  HOME: `${siteRoot(s.domain)}/tmp`,
  WP_CLI_CACHE_DIR: `${siteRoot(s.domain)}/tmp/.wp-cli-cache`,
});
