import { wpCli } from './wp.js';

// ============================================================
//  plugins.js — read a WordPress site's plugins (changes: operations/plugin.js)
// ============================================================
// Everything goes through wp-cli as the site's own user (wp.wpCli).

// Plugin "names" are wp-cli's identifiers: the folder (or single file) name.
export const PLUGIN_NAME = /^[A-Za-z0-9._-]{1,100}$/;
// A zip the upload endpoint put in the site's tmp/ (see server.js).
export const UPLOAD_NAME = /^wcloud-upload-[a-f0-9]{16}\.zip$/;

const parse = (r) => { try { return JSON.parse(r.stdout.trim().split('\n').pop()); } catch { return null; } };

// [{ name, title, status, version, update, update_version, auto_update }]
// status: active | inactive | active-network | must-use | dropin
export async function listPlugins(helpers, s) {
  const r = await (await wpCli(helpers, s))(['plugin', 'list', '--format=json',
    '--fields=name,title,status,version,update,update_version,auto_update'], { quiet: true, timeout: 90_000 });
  const list = r.code === 0 ? parse(r) : null;
  if (!Array.isArray(list)) throw new Error('WordPress on this site didn\'t respond — is it installed and working?');
  return list;
}

// WordPress.org directory search.
export async function searchPlugins(helpers, s, q) {
  const r = await (await wpCli(helpers, s))(['plugin', 'search', q, '--per-page=24', '--format=json',
    '--fields=name,slug,version,author,rating,num_ratings,active_installs,short_description'], { quiet: true, timeout: 60_000 });
  const list = r.code === 0 ? parse(r) : null;
  if (!Array.isArray(list)) throw new Error('The WordPress.org plugin directory couldn\'t be reached from this server.');
  return list;
}
