// ============================================================
//  phpsettings.js — a WordPress site's PHP settings and PHP-FPM pool sizing
// ============================================================
// spec.phpSettings / spec.fpm hold ONLY the values that differ from the
// defaults below, so a better default later reaches every site that never
// changed it. Each key is whitelisted and each value checked here, because
// both are rendered into the site's pool file (lib/sites.js renderPool) —
// php_value only, so nothing can loosen the php_admin_value isolation.
// ============================================================

const SIZE = /^[1-9]\d{0,4}[MG]$/;
export const toMB = (v) => Number(v.slice(0, -1)) * (v.endsWith('G') ? 1024 : 1);
const size = (minMB, maxMB, range) => (v) => {
  const s = String(v ?? '').trim().toUpperCase();
  return SIZE.test(s) && toMB(s) >= minMB && toMB(s) <= maxMB ? { v: s } : { error: `a size like 256M or 1G (${range})` };
};
const int = (min, max) => (v) => {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  return Number.isInteger(n) && n >= min && n <= max ? { v: n } : { error: `a whole number from ${min} to ${max}` };
};
const bool = (v) => (typeof v === 'boolean' ? { v } : { error: 'on or off' });
const oneOf = (list) => (v) => (list.includes(v) ? { v } : { error: list.join(', ') });
let zones;
const timezone = (v) => {
  zones ||= new Set(['UTC', ...Intl.supportedValuesOf('timeZone')]);
  return zones.has(v) ? { v } : { error: 'a time zone like UTC or Asia/Jakarta' };
};

export const PHP_SETTINGS = {
  memory_limit: { def: '512M', check: size(32, 8192, '32M–8G') },
  max_execution_time: { def: 600, check: int(0, 3600) },
  max_input_time: { def: 600, check: int(-1, 3600) },
  max_input_vars: { def: 3000, check: int(100, 100000) },
  post_max_size: { def: '512M', check: size(1, 16384, '1M–16G') },
  upload_max_filesize: { def: '512M', check: size(1, 16384, '1M–16G') },
  display_errors: { def: false, check: bool },
  'date.timezone': { def: 'UTC', check: timezone },
};

// ondemand: an idle site costs no memory, which is what lets one server hold
// hundreds of sites. dynamic keeps warm workers for busy sites; static a fixed set.
export const FPM_SETTINGS = {
  pm: { def: 'ondemand', check: oneOf(['ondemand', 'dynamic', 'static']) },
  max_children: { def: 20, check: int(1, 500) },
  start_servers: { def: 2, check: int(1, 500) }, // dynamic only
  min_spare_servers: { def: 1, check: int(1, 500) }, // dynamic only
  max_spare_servers: { def: 3, check: int(1, 500) }, // dynamic only
  process_idle_timeout: { def: 30, check: int(1, 3600) }, // seconds, ondemand only
  max_requests: { def: 500, check: int(0, 100000) },
  request_terminate_timeout: { def: 600, check: int(0, 3600) }, // seconds, 0 = never
};

const defaults = (defs) => Object.fromEntries(Object.entries(defs).map(([k, d]) => [k, d.def]));
export const PHP_DEFAULTS = defaults(PHP_SETTINGS);
export const FPM_DEFAULTS = defaults(FPM_SETTINGS);

// { key: value } → { value: overrides } | { error }. null / '' = back to the default.
function clean(defs, input, what) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { error: `${what} must be an object` };
  const out = {};
  for (const [k, raw] of Object.entries(input)) {
    const d = defs[k];
    if (!d) return { error: `${what}: unknown setting "${k}"` };
    if (raw == null || raw === '') continue;
    const r = d.check(raw);
    if (r.error) return { error: `${k} must be ${r.error}` };
    if (r.v !== d.def) out[k] = r.v;
  }
  return { value: out };
}

export function cleanPhpSettings(input) {
  const r = clean(PHP_SETTINGS, input, 'phpSettings');
  if (r.error) return r;
  const e = { ...PHP_DEFAULTS, ...r.value };
  if (toMB(e.upload_max_filesize) > toMB(e.post_max_size)) return { error: 'upload_max_filesize can\'t be larger than post_max_size (an upload is part of a POST)' };
  return r;
}

export function cleanFpm(input) {
  const r = clean(FPM_SETTINGS, input, 'fpm');
  if (r.error) return r;
  const e = { ...FPM_DEFAULTS, ...r.value };
  if (e.pm === 'dynamic' && !(e.min_spare_servers <= e.start_servers && e.start_servers <= e.max_spare_servers && e.max_spare_servers <= e.max_children)) {
    return { error: 'For dynamic: min spare ≤ start ≤ max spare ≤ max children' };
  }
  return r;
}

// Effective values for a spec (overrides that no longer validate — e.g. a
// default changed under them — fall back to the defaults instead of breaking).
export const phpSettingsOf = (s) => ({ ...PHP_DEFAULTS, ...(cleanPhpSettings(s.phpSettings || {}).value || {}) });
export const fpmOf = (s) => ({ ...FPM_DEFAULTS, ...(cleanFpm(s.fpm || {}).value || {}) });

// Pool lines for the site (after the fixed user/listen/isolation lines).
export function poolLines(s) {
  const f = fpmOf(s);
  const p = phpSettingsOf(s);
  return [
    `pm = ${f.pm}`,
    `pm.max_children = ${f.max_children}`,
    ...(f.pm === 'dynamic' ? [`pm.start_servers = ${f.start_servers}`, `pm.min_spare_servers = ${f.min_spare_servers}`, `pm.max_spare_servers = ${f.max_spare_servers}`] : []),
    ...(f.pm === 'ondemand' ? [`pm.process_idle_timeout = ${f.process_idle_timeout}s`] : []),
    `pm.max_requests = ${f.max_requests}`,
    `request_terminate_timeout = ${f.request_terminate_timeout}s`,
    ...Object.entries(p).map(([k, v]) => (typeof v === 'boolean' ? `php_flag[${k}] = ${v ? 'on' : 'off'}` : `php_value[${k}] = ${v}`)),
  ];
}

// nginx must let through what PHP accepts: body size and how long it waits.
export function nginxLimits(s) {
  const p = phpSettingsOf(s);
  const f = fpmOf(s);
  return {
    bodyMB: Math.max(toMB(p.post_max_size), toMB(p.upload_max_filesize)),
    readTimeout: Math.max(600, p.max_execution_time, f.request_terminate_timeout),
  };
}

// Self-check: node src/lib/phpsettings.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const assert = (await import('node:assert')).strict;
  assert.deepEqual(cleanPhpSettings({ memory_limit: '1g', max_input_vars: '5000', display_errors: false }).value, { memory_limit: '1G', max_input_vars: 5000 });
  assert.ok(cleanPhpSettings({ memory_limit: '512M\nphp_admin_value[open_basedir]=/' }).error);
  assert.ok(cleanPhpSettings({ 'disable_functions': '' }).error);
  assert.ok(cleanPhpSettings({ upload_max_filesize: '2G' }).error); // > post_max_size 512M
  assert.deepEqual(cleanPhpSettings({ upload_max_filesize: '2G', post_max_size: '2G' }).value, { upload_max_filesize: '2G', post_max_size: '2G' });
  assert.ok(cleanPhpSettings({ 'date.timezone': 'Mars/Base' }).error);
  assert.equal(cleanPhpSettings({ 'date.timezone': 'Asia/Jakarta' }).value['date.timezone'], 'Asia/Jakarta');
  assert.ok(cleanFpm({ pm: 'dynamic', start_servers: 10 }).error); // > max_spare 3
  assert.deepEqual(cleanFpm({ pm: 'dynamic', max_children: 40, start_servers: 4, min_spare_servers: 2, max_spare_servers: 8 }).value, { pm: 'dynamic', max_children: 40, start_servers: 4, min_spare_servers: 2, max_spare_servers: 8 });
  const lines = poolLines({ fpm: { pm: 'static', max_children: 8 }, phpSettings: { display_errors: true } });
  assert.ok(lines.includes('pm = static') && !lines.some((l) => l.startsWith('pm.process_idle')) && lines.includes('php_flag[display_errors] = on'));
  assert.deepEqual(nginxLimits({ phpSettings: { post_max_size: '2G', upload_max_filesize: '1G', max_execution_time: 900 } }), { bodyMB: 2048, readTimeout: 900 });
  console.log('phpsettings ok');
}
