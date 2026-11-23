import { logger } from '../lib/log.js';
import { setHardening, HARDENING } from '../lib/hardening.js';

// ============================================================
//  harden — kernel network and filesystem hardening (lib/hardening.js)
// ============================================================
// params: { on: bool }. On: the sysctl drop-in is written and every value must
// read back as set. Off: the drop-in is removed; the values stay until a reboot.
export async function runHarden(job, helpers, p) {
  const { step, ok, warn, done } = logger(helpers);
  step(p.on ? 'Turn on kernel hardening' : 'Turn off kernel hardening');
  const s = await setHardening(helpers, p.on);
  if (p.on) {
    if (!s.applied) throw new Error(`Some values did not take: ${s.mismatches.map((m) => `${m.key} is ${m.now}, wanted ${m.want}`).join('; ')}`);
    ok(`${HARDENING.length} kernel settings applied and read back`);
    done('Kernel hardening on');
  } else {
    warn('The settings file is removed. The current values stay until the next reboot.');
    done('Kernel hardening off');
  }
}
