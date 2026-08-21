// DigitalOcean Spaces (S3) transfer via rclone. Creds are passed per-call as
// subprocess env vars only — never written to a config file, never logged (the
// logger prints command lines, not env). Kept provider-agnostic (plain S3
// params); only DigitalOcean is offered in the portal UI today.
import { run } from './sys.js';

let rcloneChecked = false;

// `rclone version` exit code, or 127 when the binary is missing. A missing
// binary makes run() REJECT (spawn ENOENT) instead of returning a code, so
// "absent" has to be caught here rather than read off a probe result.
async function rcloneProbe(helpers) {
  try {
    const r = await run(helpers, 'rclone', ['version'], { quiet: true, timeout: 10_000 });
    return r.code;
  } catch {
    return 127;
  }
}

// Memoized per process: probe once, self-install if absent (agent boxes
// provisioned before rclone existed don't require a redeploy).
export async function ensureRclone(helpers) {
  if (rcloneChecked) return;
  if ((await rcloneProbe(helpers)) === 0) {
    rcloneChecked = true;
    return;
  }
  helpers.log?.('rclone not found — installing from rclone.org');
  // Fixed URL, no user data — the shell here is controlled.
  const inst = await run(helpers, 'sh', ['-c', 'curl --fail --show-error -sSL https://rclone.org/install.sh | bash'],
    { quiet: true, timeout: 300_000 });
  if (inst.code !== 0 || (await rcloneProbe(helpers)) !== 0) {
    throw new Error('rclone unavailable and install failed');
  }
  rcloneChecked = true;
}

// Env vars that define the `wcloud:` rclone remote for one transfer.
export function spacesEnv({ endpoint, accessKeyId, secretAccessKey }) {
  return {
    RCLONE_CONFIG_wcloud_TYPE: 's3',
    RCLONE_CONFIG_wcloud_PROVIDER: 'DigitalOcean',
    RCLONE_CONFIG_wcloud_ENDPOINT: endpoint,
    RCLONE_CONFIG_wcloud_ACCESS_KEY_ID: accessKeyId,
    RCLONE_CONFIG_wcloud_SECRET_ACCESS_KEY: secretAccessKey,
  };
}

export const remotePath = (space, key) => `wcloud:${space}/${key}`;
