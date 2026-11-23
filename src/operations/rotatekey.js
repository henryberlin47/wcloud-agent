import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { logger } from '../lib/log.js';
import { rotateToken } from '../auth.js';

// ============================================================
//  rotatekey — replace AGENT_TOKEN (the portal generates the new one)
// ============================================================
// params: { token } — redacted in job views (key name matches "token"). The env
// file is replaced first (temp file, rename, mode 0600): if that fails nothing
// has changed. Then the agent switches to the new token; the old one keeps
// working for AGENT_TOKEN_GRACE_MS (auth.js) so the portal can read this job.
export const ENV_FILE = fileURLToPath(new URL('../../.env', import.meta.url));

export async function runRotateKey(job, helpers, p) {
  const { step, ok, done } = logger(helpers);
  step('Write the new agent token');
  await writeEnvToken(p.token);
  rotateToken(p.token);
  ok('Saved. The old token stops working in a few minutes.');
  done('Agent token rotated');
}

// Replaces the AGENT_TOKEN line (or appends one) and leaves every other line as it is.
async function writeEnvToken(token) {
  const env = await fs.readFile(ENV_FILE, 'utf8');
  const line = `AGENT_TOKEN=${token}`;
  const next = /^AGENT_TOKEN=.*$/m.test(env)
    ? env.replace(/^AGENT_TOKEN=.*$/m, () => line)
    : `${env.replace(/\n?$/, '\n')}${line}\n`;
  const tmp = `${ENV_FILE}.tmp`;
  await fs.rm(tmp, { force: true }); // an old temp file keeps its mode, so start from none
  await fs.writeFile(tmp, next, { mode: 0o600 });
  await fs.rename(tmp, ENV_FILE);
}
