import fs from 'node:fs/promises';
import net from 'node:net';
import { nginxTest, nginxReload, withLock } from './sys.js';
import { REALIP_CONF } from './sites.js';

// ============================================================
//  realip.js — Cloudflare's IP ranges for nginx's realip module
// ============================================================
// Sites with spec.realIp include REALIP_CONF: requests arriving FROM these
// ranges get their client IP from CF-Connecting-IP (logs, PHP's REMOTE_ADDR).
// Anyone else's header is ignored, so it can't be spoofed. The list ships
// built in and is refreshed from cloudflare.com daily (validated, nginx -t'd).

const BUILTIN = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
  '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

const isCidr = (c) => {
  const [ip, bits] = c.split('/');
  const v = net.isIP(ip);
  return !!v && /^\d+$/.test(bits || '') && Number(bits) <= (v === 4 ? 32 : 128);
};
const render = (cidrs) => [
  '# Managed by wcloud (src/lib/realip.js): Cloudflare\'s IP ranges.',
  ...cidrs.map((c) => `set_real_ip_from ${c};`),
  'real_ip_header CF-Connecting-IP;',
  '',
].join('\n');

// Write the built-in list if the file is missing (a site's vhost includes it).
export async function ensureRealIpConf() {
  try { await fs.access(REALIP_CONF); } catch {
    await fs.mkdir('/etc/nginx/wcloud', { recursive: true });
    await fs.writeFile(REALIP_CONF, render(BUILTIN), { mode: 0o644 });
  }
}

// Fetch the current list; replace the file only if it changed and nginx
// accepts it (restored otherwise).
export async function refreshRealIpConf(helpers) {
  await ensureRealIpConf();
  let cidrs = [];
  try {
    for (const u of ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6']) {
      const r = await fetch(u, { signal: AbortSignal.timeout(15_000) });
      if (!r.ok) return;
      cidrs.push(...(await r.text()).split('\n').map((l) => l.trim()).filter(Boolean));
    }
  } catch { return; } // offline: keep what we have
  if (cidrs.length < 10 || !cidrs.every(isCidr)) return; // doesn't look like the real list
  const want = render(cidrs);
  await withLock('config', async () => {
    const have = await fs.readFile(REALIP_CONF, 'utf8').catch(() => '');
    if (want === have) return;
    await fs.writeFile(REALIP_CONF, want, { mode: 0o644 });
    if (await nginxTest(helpers)) await nginxReload(helpers);
    else await fs.writeFile(REALIP_CONF, have || render(BUILTIN), { mode: 0o644 });
  });
}

export function startRealIpRefresher(helpers) {
  const tick = () => refreshRealIpConf(helpers).catch((e) => console.error('[agent] realip refresh:', e.message));
  setTimeout(tick, 60_000).unref();
  setInterval(tick, 24 * 3600_000).unref();
}
