import { logger } from '../lib/log.js';
import { applyFirewall } from '../lib/firewall.js';

// ============================================================
//  firewall — the server's firewall and blocked addresses (lib/firewall.js)
// ============================================================
// params: { enabled?, sshFrom?, openPorts?, block?: [addr], unblock?: [addr] }
// Each part applies only when given; the whole change is one nft load.
export async function runFirewall(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  step(p.enabled === undefined ? 'Update the firewall' : p.enabled ? 'Turn the firewall on' : 'Turn the firewall off');
  const s = await applyFirewall(helpers, p);
  if (p.block?.length) ok(`Blocked ${p.block.join(', ')} — refused in both directions, firewall on or off`);
  if (p.unblock?.length) ok(`Unblocked ${p.unblock.join(', ')}`);
  ok(s.enabled ? 'Rules loaded — they come back after a reboot' : 'Rules loaded — the firewall is off, only blocked addresses are refused');
  done(`Firewall ${s.enabled ? 'on' : 'off'}: ${s.blocked.length} blocked address${s.blocked.length === 1 ? '' : 'es'}`);
}
