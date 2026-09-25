import fs from 'node:fs/promises';
import { run, removePath, nginxReload } from './sys.js';
import { siteDir, clearPageCache } from './sites.js';

// ============================================================
//  nginxrules.js — a site's named custom nginx rules
// ============================================================
// Files in /var/www/<d>/conf/nginx/ (root-owned; the site's vhost includes
// *.conf inside its server block). Name in a header line; a disabled rule is
// the same file renamed to .conf.off. Every save is ONE transaction: write,
// `nginx -t`, and on failure the previous files come back and nginx's own
// error is shown — a bad rule never reaches the running server.
// ============================================================

const HEADER = '# wcloud-name: ';
export const RULE_MAX = 64 * 1024;
const dir = (d) => `${siteDir(d)}/conf/nginx`;
const ID = /^[a-z0-9][a-z0-9-]{0,39}$/;
const slug = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'rule';
const read = async (p) => { try { return await fs.readFile(p, 'utf8'); } catch { return null; } };

export async function listRules(d) {
  let files = [];
  try { files = await fs.readdir(dir(d)); } catch { return []; }
  const out = [];
  for (const f of files.sort()) {
    const m = f.match(/^([a-z0-9][a-z0-9-]*)\.conf(\.off)?$/);
    if (!m) continue;
    const text = (await read(`${dir(d)}/${f}`)) || '';
    const first = text.split('\n', 1)[0];
    const named = first.startsWith(HEADER);
    out.push({ id: m[1], name: named ? first.slice(HEADER.length).trim() : f, enabled: !m[2], content: named ? text.slice(first.length + 1) : text });
  }
  return out;
}

// The first nginx -t complaint, trimmed to the useful part.
async function nginxCheck(helpers) {
  const r = await run(helpers, 'nginx', ['-t'], { quiet: true, timeout: 30_000 });
  if (r.code === 0) return null;
  const line = `${r.stderr}\n${r.stdout}`.split('\n').find((l) => /\[emerg\]|\[alert\]/.test(l)) || 'the configuration test failed';
  return line.replace(/^.*?\[(emerg|alert)\]\s*\d+#\d+:\s*/, '').slice(0, 300);
}

// Apply edits { path: content | null } transactionally. Throws with nginx's
// complaint when the result doesn't pass `nginx -t`.
async function commit(helpers, d, edits) {
  const before = {};
  for (const p of Object.keys(edits)) before[p] = await read(p);
  const put = async (p, c) => { if (c === null) await removePath(p); else await fs.writeFile(p, c, { mode: 0o644 }); };
  await fs.mkdir(dir(d), { recursive: true });
  for (const [p, c] of Object.entries(edits)) await put(p, c);
  const err = await nginxCheck(helpers);
  if (err) {
    for (const [p, c] of Object.entries(before)) await put(p, c);
    throw new Error(`nginx rejected the rule, so nothing changed: ${err}`);
  }
  await nginxReload(helpers);
  await clearPageCache(d);
}

// { id?, name, content, enabled } — no id = new rule (id from the name).
export async function saveRule(helpers, d, { id, name, content, enabled }) {
  let ruleId = id;
  if (!ruleId) {
    const taken = new Set((await listRules(d)).map((r) => r.id));
    const base = slug(name);
    ruleId = base;
    for (let i = 2; taken.has(ruleId); i++) ruleId = `${base}-${i}`;
  }
  if (!ID.test(ruleId)) throw new Error('invalid rule id');
  const on = `${dir(d)}/${ruleId}.conf`;
  const off = `${on}.off`;
  const text = `${HEADER}${name}\n${content.endsWith('\n') ? content : `${content}\n`}`;
  await commit(helpers, d, enabled ? { [on]: text, [off]: null } : { [off]: text, [on]: null });
  return ruleId;
}

export async function deleteRule(helpers, d, id) {
  if (!ID.test(id)) throw new Error('invalid rule id');
  const on = `${dir(d)}/${id}.conf`;
  await commit(helpers, d, { [on]: null, [`${on}.off`]: null });
}
