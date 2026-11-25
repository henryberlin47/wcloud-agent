import fs from 'node:fs/promises';
import { logger } from '../lib/log.js';
import { requireSpec, siteTmp } from '../lib/sites.js';
import { wpCli } from '../lib/wp.js';
import { clearPageCache } from '../lib/cache.js';

// ============================================================
//  plugin / theme — install / activate / deactivate / update / delete
// ============================================================
// wp-cli as the site's own user. A plugin's "delete" is WordPress's own Delete:
// deactivate, run its uninstall routine, remove its files (wp plugin uninstall).
// Themes have no deactivate (activating another replaces it); the active theme
// and its parent can't be deleted. Uploaded zips live in the site's private
// tmp/ and are removed afterwards.
// ============================================================

const lastJson = (r) => { try { return JSON.parse(r.stdout.trim().split('\n').pop()); } catch { return null; } };

const VERB = {
  activate: ['Activate', 'Activated'],
  deactivate: ['Deactivate', 'Deactivated'],
  update: ['Update', 'Updated'],
  delete: ['Delete', 'Deleted'],
  'auto-update-on': ['Turn on auto-updates for', 'Auto-updates on for'],
  'auto-update-off': ['Turn off auto-updates for', 'Auto-updates off for'],
};

// params: { domain, action, plugins?|themes?: [name], all?: bool, slug?, upload?, activate?, replace? }
export async function runPlugin(job, helpers, p, kind = 'plugin') {
  const Kind = kind === 'theme' ? 'Theme' : 'Plugin';
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — it has no ${kind}s.`);
  const wp = await wpCli(helpers, s);
  const must = async (args, what) => {
    const r = await wp(args, { timeout: 600_000 });
    if (r.code !== 0) {
      const out = `${r.stderr}\n${r.stdout}`;
      if (/Destination folder already exists|already installed/i.test(out)) {
        throw new Error(`That ${kind} is already installed. To upload a newer version, tick "Replace it if it's already installed".`);
      }
      const why = out.split('\n').map((l) => l.trim()).filter((l) => /^(Error|Warning):/.test(l)).pop();
      throw new Error(`${what} failed${why ? ` — ${why.replace(/^(Error|Warning):\s*/, '')}` : '.'}`);
    }
    return r;
  };
  const names = p[`${kind}s`] || [];
  const which = p.all ? `all ${kind}s` : names.join(', ');

  if (p.action === 'install') {
    const src = p.upload ? `${siteTmp(s.domain)}/${p.upload}` : p.slug;
    step(p.upload ? `Install the uploaded ${kind}` : `Install ${p.slug} from WordPress.org`);
    try {
      await must([kind, 'install', src, ...(p.activate ? ['--activate'] : []), ...(p.replace ? ['--force'] : [])], `Installing the ${kind}`);
    } finally {
      // The site owns its tmp/: a plain unlink, never a recursive delete as
      // root (it could be led into another directory). A failure here must
      // not hide the install's own error.
      if (p.upload) await fs.unlink(src).catch(() => {});
    }
    ok(p.activate ? `${Kind} installed and activated` : `${Kind} installed`);
    if (s.cache === 'fastcgi') await clearPageCache(s.domain); // pages may render differently now
    done(p.upload ? `${Kind} installed` : `${p.slug} installed`);
    return;
  }

  const [verb, past] = VERB[p.action];
  step(`${verb} ${which}`);
  const target = p.all ? ['--all'] : names;
  switch (p.action) {
    case 'activate': case 'deactivate': case 'update':
      await must([kind, p.action, ...target], `${verb} ${which}`);
      break;
    case 'delete':
      if (kind === 'theme') {
        // wp-cli only guards the active theme; deleting its parent breaks the site too.
        const r = await wp(['theme', 'list', '--fields=name,status', '--format=json'], { quiet: true });
        const inUse = (lastJson(r) || []).filter((t) => names.includes(t.name) && t.status !== 'inactive').map((t) => t.name);
        if (inUse.length) throw new Error(`${inUse.join(', ')} is in use by the site (the active theme or its parent) — activate another theme first.`);
        await must(['theme', 'delete', ...target], `Deleting ${which}`);
      } else await must(['plugin', 'uninstall', '--deactivate', ...target], `Deleting ${which}`);
      break;
    case 'auto-update-on': case 'auto-update-off':
      await must([kind, 'auto-updates', p.action === 'auto-update-on' ? 'enable' : 'disable', ...target], `${verb} ${which}`);
      break;
    default:
      throw new Error(`unknown ${kind} action ${p.action}`);
  }
  if (s.cache === 'fastcgi') await clearPageCache(s.domain); // pages may render differently now
  done(`${past} ${which}`);
}
