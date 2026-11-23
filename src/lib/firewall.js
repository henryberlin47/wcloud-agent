import fs from 'node:fs/promises';
import { isIP } from 'node:net';
import config from '../config.js';
import { run, pathExists, withLock, sshdRun } from './sys.js';

// ============================================================
//  firewall.js — the server's firewall (nftables, one table of ours)
// ============================================================
// /etc/wcloud/firewall.json is the source of truth (like a site's spec);
// render() turns it into /etc/wcloud/firewall.nft. The file declares and
// deletes `inet wcloud_fw` before rebuilding it, so `nft -f` swaps our table in
// one transaction and never touches ufw, fail2ban or anyone else's tables.
// Blocked addresses drop in both directions, with the firewall on or off.
// Changes: op `firewall` (operations/firewall.js). Read: GET /api/firewall.
// ============================================================

const DIR = '/etc/wcloud';
const SETTINGS = `${DIR}/firewall.json`;
const RULES = `${DIR}/firewall.nft`;
const UNIT = '/etc/systemd/system/wcloud-firewall.service';
const NFT = '/usr/sbin/nft';
const MAX_BLOCKED = 500;
const DEFAULTS = { enabled: false, sshFrom: [], blocked: [], openPorts: [] };
const APT_ENV = { DEBIAN_FRONTEND: 'noninteractive', NEEDRESTART_MODE: 'a' };
const quiet = { quiet: true, timeout: 30_000 };

// Reloads the rules at boot (and on `systemctl restart`): no ExecStop, so a stop keeps them loaded.
const UNIT_TEXT = `[Unit]
Description=wcloud firewall (nftables table inet wcloud_fw)
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${NFT} -f ${RULES}

[Install]
WantedBy=multi-user.target
`;

// "1.2.3.4", "10.0.0.0/8", "2001:db8::/32" → 4 or 6 (its family); 0 when it isn't one.
export function addrFamily(v) {
  if (typeof v !== 'string') return 0;
  const [a, bits, extra] = v.split('/');
  const f = isIP(a);
  if (!f || extra !== undefined) return 0;
  return bits === undefined || (/^\d+$/.test(bits) && +bits <= (f === 4 ? 32 : 128)) ? f : 0;
}
// A block must not cover most of the internet: 0.0.0.0/0 or ::/0 would cut this server off.
export const tooWide = (v) => { const bits = v.split('/')[1]; return bits !== undefined && +bits < (addrFamily(v) === 4 ? 8 : 32); };

// ── Render ───────────────────────────────────────────────────────────────────

// "ip saddr { … } tcp dport N accept" per family; no list (or none valid) = from anywhere.
// An allowlist with nothing valid in it must not lock the portal out, so it opens the port.
const accept = (list, proto, port) => {
  const v4 = list.filter((a) => addrFamily(a) === 4);
  const v6 = list.filter((a) => addrFamily(a) === 6);
  if (!v4.length && !v6.length) return [`${proto} dport ${port} accept`];
  return [
    ...(v4.length ? [`ip saddr { ${v4.join(', ')} } ${proto} dport ${port} accept`] : []),
    ...(v6.length ? [`ip6 saddr { ${v6.join(', ')} } ${proto} dport ${port} accept`] : []),
  ];
};
const set = (name, type, list) => [
  `  set ${name} {`, `    type ${type}`, '    flags interval',
  ...(list.length ? [`    elements = { ${list.join(', ')} }`] : []),
  '  }',
];

/** The whole table as nft text. ctx: { allowedIps (the agent's allowlist), sshPorts, agentPort }. */
export function render(s, { allowedIps = [], sshPorts = [22], agentPort = 8787 } = {}) {
  const b4 = s.blocked.filter((a) => addrFamily(a) === 4);
  const b6 = s.blocked.filter((a) => addrFamily(a) === 6);
  const allow = s.enabled ? [
    'ct state established,related accept',
    'ct state invalid drop',
    'iif lo accept',
    'meta l4proto { icmp, icmpv6 } accept', // IPv6 neighbour discovery and routers ride on ICMPv6
    // DHCP replies (v4, v6): a broadcast offer isn't a tracked connection, and a
    // cloud server that can't renew its lease drops off the network.
    'udp sport 67 udp dport 68 accept',
    'udp sport 547 udp dport 546 accept',
    'tcp dport { 80, 443 } accept',
    'udp dport 443 accept', // HTTP/3
    ...accept(allowedIps, 'tcp', agentPort), // the portal must always reach the agent
    ...sshPorts.flatMap((p) => accept(s.sshFrom, 'tcp', p)),
    ...s.openPorts.map((o) => `${o.proto} dport ${o.port} accept`),
  ] : [];
  return [
    'table inet wcloud_fw', // declared first so the delete works on a fresh server
    'delete table inet wcloud_fw',
    'table inet wcloud_fw {',
    ...set('blocked4', 'ipv4_addr', b4),
    ...set('blocked6', 'ipv6_addr', b6),
    '  chain input {',
    `    type filter hook input priority 0; policy ${s.enabled ? 'drop' : 'accept'};`,
    // Blocks come first: an attacker already connected is cut off, not left to finish.
    '    ip saddr @blocked4 drop',
    '    ip6 saddr @blocked6 drop',
    ...allow.map((r) => `    ${r}`),
    '  }',
    '  chain output {',
    '    type filter hook output priority 0; policy accept;',
    '    ip daddr @blocked4 drop',
    '    ip6 daddr @blocked6 drop',
    '  }',
    '}',
    '',
  ].join('\n');
}

// ── Read ─────────────────────────────────────────────────────────────────────

// Every port sshd listens on; they stay open to the SSH sources. A broken sshd config reads as the default.
async function sshPorts(helpers) {
  const r = await sshdRun(helpers, ['-T'], quiet);
  const ports = [...r.stdout.matchAll(/^port (\d+)$/gm)].map((m) => Number(m[1]));
  return ports.length ? ports : [22];
}

export async function readSettings() {
  const txt = await fs.readFile(SETTINGS, 'utf8').catch((e) => { if (e.code === 'ENOENT') return null; throw e; });
  return txt === null ? { ...DEFAULTS } : JSON.parse(txt);
}

/** `ss -ltnupH` → the listening sockets not bound to loopback: [{ proto, port, addr, process }]. */
export function parseListening(out) {
  const res = [];
  for (const l of out.split('\n')) {
    const c = l.trim().split(/\s+/);
    if (c.length < 5) continue;
    const i = c[4].lastIndexOf(':');
    const addr = c[4].slice(0, i).replace(/^\[|\]$/g, '');
    if (addr.startsWith('127.') || addr === '::1') continue;
    res.push({ proto: c[0], port: Number(c[4].slice(i + 1)), addr, process: (l.match(/users:\(\("([^"]*)"/) || [])[1] || null });
  }
  return res;
}

/** Everything the portal's Server → Firewall card shows (GET /api/firewall). */
export async function firewallStatus(helpers) {
  const s = await readSettings();
  const [ports, ss, unit] = await Promise.all([
    sshPorts(helpers), run(helpers, 'ss', ['-ltnupH'], quiet), run(helpers, 'systemctl', ['is-enabled', 'wcloud-firewall'], quiet),
  ]);
  return {
    available: await pathExists(NFT), enabled: s.enabled, sshPorts: ports, sshFrom: s.sshFrom, blocked: s.blocked, openPorts: s.openPorts,
    agentFrom: config.allowedIps, agentPort: config.port, listening: parseListening(ss.stdout), persisted: unit.stdout.trim() === 'enabled',
  };
}

// ── Apply ────────────────────────────────────────────────────────────────────

/**
 * Apply a change (op params: enabled?, sshFrom?, openPorts?, block?, unblock?):
 * write the settings and the rules, check them with `nft -c`, load them with
 * `nft -f`, keep them across reboots. A failure puts the previous files back;
 * nft applies a file all or nothing, so the kernel never holds half of it.
 * sshPorts: the SSH ports to open instead of sshd's (an SSH port change opens both, then one).
 */
export async function applyFirewall(helpers, p, { sshPorts: ports } = {}) {
  return withLock('firewall', async () => {
    if (!(await pathExists(NFT))) {
      const r = await withLock('apt', () => run(helpers, 'apt-get', ['-o', 'DPkg::Lock::Timeout=600', 'install', '-y', '-q', 'nftables'],
        { env: APT_ENV, timeout: 900_000 }));
      if (r.code !== 0) throw new Error('nftables could not be installed on this server.');
    }
    const cur = await readSettings();
    const next = {
      enabled: p.enabled ?? cur.enabled,
      sshFrom: p.sshFrom ?? cur.sshFrom,
      openPorts: p.openPorts ?? cur.openPorts,
      blocked: [...new Set([...cur.blocked, ...(p.block || [])])].filter((a) => !(p.unblock || []).includes(a)),
    };
    if (next.blocked.length > MAX_BLOCKED) throw new Error(`At most ${MAX_BLOCKED} blocked addresses — unblock some first.`);
    const rules = render(next, { allowedIps: config.allowedIps, sshPorts: ports ?? (await sshPorts(helpers)), agentPort: config.port });

    const prev = await Promise.all([SETTINGS, RULES].map((f) => fs.readFile(f, 'utf8').catch(() => null)));
    const restore = async () => {
      for (const [f, data] of [[SETTINGS, prev[0]], [RULES, prev[1]]]) {
        if (data === null) await fs.rm(f, { force: true }); else await fs.writeFile(f, data);
      }
    };
    const fail = async (what, r) => {
      await restore();
      throw new Error(`${what}, nothing was changed: ${(r.stderr || r.stdout).trim().slice(-300)}`);
    };
    await fs.mkdir(DIR, { recursive: true });
    await fs.writeFile(SETTINGS, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o644 });
    await fs.writeFile(RULES, rules, { mode: 0o644 });
    const check = await run(helpers, NFT, ['-c', '-f', RULES], { timeout: 30_000 });
    if (check.code !== 0) await fail('The firewall rules are invalid', check);
    const load = await run(helpers, NFT, ['-f', RULES], { timeout: 30_000 });
    if (load.code !== 0) await fail('The firewall rules could not be loaded', load);

    await fs.writeFile(UNIT, UNIT_TEXT, { mode: 0o644 });
    await run(helpers, 'systemctl', ['daemon-reload'], quiet);
    const en = await run(helpers, 'systemctl', ['enable', 'wcloud-firewall'], { timeout: 30_000 });
    if (en.code !== 0) throw new Error('The firewall is loaded, but it won\'t come back after a reboot (systemctl enable failed).');
    return next;
  });
}

// Self-check: node src/lib/firewall.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const assert = (await import('node:assert')).strict;
  assert.equal(addrFamily('1.2.3.4'), 4);
  assert.equal(addrFamily('10.0.0.0/8'), 4);
  assert.equal(addrFamily('10.0.0.0/33'), 0);
  assert.equal(addrFamily('2001:db8::/32'), 6);
  assert.equal(addrFamily('2001:db8::/129'), 0);
  assert.equal(addrFamily('1.2.3.4/x'), 0);
  assert.equal(addrFamily('example.com'), 0);
  assert.equal(addrFamily(['1.2.3.4']), 0);
  assert.ok(tooWide('0.0.0.0/0') && tooWide('10.0.0.0/7') && tooWide('::/16'));
  assert.ok(!tooWide('10.0.0.0/8') && !tooWide('2001:db8::/32') && !tooWide('1.2.3.4'));

  const s = { enabled: true, sshFrom: ['192.0.2.1'], blocked: ['203.0.113.7', '2001:db8::/32'], openPorts: [{ port: 3000, proto: 'tcp' }] };
  const on = render(s, { allowedIps: ['198.51.100.2'], sshPorts: [22, 2222], agentPort: 8787 });
  assert.ok(on.includes('policy drop;') && on.includes('policy accept;'));
  assert.ok(on.includes('elements = { 203.0.113.7 }') && on.includes('elements = { 2001:db8::/32 }'));
  assert.ok(on.includes('ip saddr { 198.51.100.2 } tcp dport 8787 accept'));
  assert.ok(on.includes('ip saddr { 192.0.2.1 } tcp dport 22 accept') && on.includes('ip saddr { 192.0.2.1 } tcp dport 2222 accept'));
  assert.ok(on.includes('tcp dport 3000 accept') && on.includes('tcp dport { 80, 443 } accept'));
  const open = render({ ...s, sshFrom: [] }, { allowedIps: [] });
  assert.ok(open.includes('tcp dport 8787 accept') && open.includes('tcp dport 22 accept') && !open.includes('ip saddr {'));
  const off = render({ ...s, enabled: false, blocked: [] });
  assert.ok(off.includes('policy accept;') && !off.includes('policy drop;') && !off.includes('ct state') && !off.includes('elements'));
  assert.ok(render({ ...s, enabled: false }).includes('elements = { 203.0.113.7 }'), 'blocks stay with the firewall off');

  const ss = [
    'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=819,fd=3))',
    'tcp LISTEN 0 4096 [::]:3306 [::]:* users:(("mariadbd",pid=1,fd=2))',
    'tcp LISTEN 0 4 127.0.0.1:6379 0.0.0.0:*',
    'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi",pid=5,fd=3))',
  ].join('\n');
  assert.deepEqual(parseListening(ss), [
    { proto: 'tcp', port: 22, addr: '0.0.0.0', process: 'sshd' },
    { proto: 'tcp', port: 3306, addr: '::', process: 'mariadbd' },
    { proto: 'udp', port: 5353, addr: '0.0.0.0', process: 'avahi' },
  ]);
  console.log('firewall ok');
}
