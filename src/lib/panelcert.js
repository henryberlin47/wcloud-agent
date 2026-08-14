import fs from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const pexec = promisify(execFile);

// The WordOps admin panel on :22222. We pin its SSL to the self-signed cert and
// make the file immutable, so nothing (`wo secure`, scripts, hand-edits) can
// repoint it at a deletable site's Let's Encrypt cert — which is what keeps
// breaking `nginx -t` server-wide when that site is later deleted.
const SSL_CONF = '/var/www/22222/conf/nginx/ssl.conf';
const CRT = '/var/www/22222/cert/22222.crt';
const KEY = '/var/www/22222/cert/22222.key';
const DESIRED = `ssl_certificate     ${CRT};\nssl_certificate_key ${KEY};\n`;

const exists = async (p) => { try { await fs.access(p); return true; } catch { return false; } };
const tryExec = async (cmd, args) => { try { await pexec(cmd, args); return true; } catch { return false; } };

// Idempotent: safe to run on every agent start. Only writes/reloads on drift.
export async function enforceAdminPanelCert(log = console.log) {
  if (!(await exists(SSL_CONF))) return; // panel not installed on this box
  if (!(await exists(CRT)) || !(await exists(KEY))) {
    log('[agent] :22222 self-signed cert missing — leaving panel ssl.conf untouched');
    return;
  }
  const current = await fs.readFile(SSL_CONF, 'utf8').catch(() => null);
  if (current !== DESIRED) {
    await tryExec('chattr', ['-i', SSL_CONF]);     // unlock if it was already immutable
    await fs.writeFile(SSL_CONF, DESIRED);
    if (await tryExec('nginx', ['-t'])) await tryExec('systemctl', ['reload', 'nginx']);
    log('[agent] reset :22222 admin panel to self-signed cert');
  }
  await tryExec('chattr', ['+i', SSL_CONF]);       // lock immutable (silent, idempotent)
}
