import { removePath } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { requireSpec, siteTmp } from '../lib/sites.js';
import { wpCli } from '../lib/wp.js';

// ============================================================
//  plugin — install / activate / deactivate / update / delete plugins
// ============================================================
// wp-cli as the site's own user. "delete" is WordPress's own Delete: deactivate,
// run the plugin's uninstall routine, remove its files (wp plugin uninstall).
// Uploaded zips live in the site's private tmp/ and are removed afterwards.
// ============================================================

const VERB = {
  activate: ['Activate', 'Activated'],
  deactivate: ['Deactivate', 'Deactivated'],
  update: ['Update', 'Updated'],
  delete: ['Delete', 'Deleted'],
  'auto-update-on': ['Turn on auto-updates for', 'Auto-updates on for'],
  'auto-update-off': ['Turn off auto-updates for', 'Auto-updates off for'],
};

// params: { domain, action, plugins?: [name], all?: bool, slug?, upload?, activate?, replace? }
export async function runPlugin(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  const s = await requireSpec(p.domain);
  if (s.type !== 'wordpress') throw new Error(`${p.domain} is a static site — it has no plugins.`);
  const wp = await wpCli(helpers, s);
  const must = async (args, what) => {
    const r = await wp(args, { timeout: 600_000 });
    if (r.code !== 0) {
      const out = `${r.stderr}\n${r.stdout}`;
      if (/Destination folder already exists|already installed/i.test(out)) {
        throw new Error('That plugin is already installed. To upload a newer version, tick "Replace it if it\'s already installed".');
      }
      const why = out.split('\n').map((l) => l.trim()).filter((l) => /^(Error|Warning):/.test(l)).pop();
      throw new Error(`${what} failed${why ? ` — ${why.replace(/^(Error|Warning):\s*/, '')}` : '.'}`);
    }
    return r;
  };
  const names = p.plugins || [];
  const which = p.all ? 'all plugins' : names.join(', ');

  if (p.action === 'install') {
    const src = p.upload ? `${siteTmp(s.domain)}/${p.upload}` : p.slug;
    step(p.upload ? 'Install the uploaded plugin' : `Install ${p.slug} from WordPress.org`);
    try {
      await must(['plugin', 'install', src, ...(p.activate ? ['--activate'] : []), ...(p.replace ? ['--force'] : [])], 'Installing the plugin');
    } finally {
      if (p.upload) await removePath(src);
    }
    ok(p.activate ? 'Plugin installed and activated' : 'Plugin installed');
    done(p.upload ? 'Plugin installed' : `${p.slug} installed`);
    return;
  }

  const [verb, past] = VERB[p.action];
  step(`${verb} ${which}`);
  const target = p.all ? ['--all'] : names;
  switch (p.action) {
    case 'activate': case 'deactivate': case 'update':
      await must(['plugin', p.action, ...target], `${verb} ${which}`);
      break;
    case 'delete':
      await must(['plugin', 'uninstall', '--deactivate', ...target], `Deleting ${which}`);
      break;
    case 'auto-update-on': case 'auto-update-off':
      await must(['plugin', 'auto-updates', p.action === 'auto-update-on' ? 'enable' : 'disable', ...target], `${verb} ${which}`);
      break;
    default:
      throw new Error(`unknown plugin action ${p.action}`);
  }
  done(`${past} ${which}`);
}
