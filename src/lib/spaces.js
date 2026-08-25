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
// rclone only reads a remote-from-env when the remote name in the key is
// UPPERCASE (RCLONE_CONFIG_<REMOTE>_<OPTION>); a lowercase key is ignored, so
// rclone falls back to the config file and fails with "didn't find section in
// config file (wcloud)". The remote is still referenced lowercase (`wcloud:`).
export function spacesEnv({ endpoint, accessKeyId, secretAccessKey }) {
  return {
    RCLONE_CONFIG_WCLOUD_TYPE: 's3',
    RCLONE_CONFIG_WCLOUD_PROVIDER: 'DigitalOcean',
    RCLONE_CONFIG_WCLOUD_ENDPOINT: endpoint,
    RCLONE_CONFIG_WCLOUD_ACCESS_KEY_ID: accessKeyId,
    RCLONE_CONFIG_WCLOUD_SECRET_ACCESS_KEY: secretAccessKey,
    // Never let rclone create the Space. Before uploading, its S3 backend
    // HeadBuckets the destination and CREATES it when that check fails — and a
    // Spaces key normally can't create Spaces, so the whole upload dies with
    // "CreateBucket ... 403 AccessDenied" even though the Space exists and the
    // key can write to it. The Space is always pre-created by the user, so skip
    // the check and go straight to the object write.
    RCLONE_CONFIG_WCLOUD_NO_CHECK_BUCKET: 'true',
  };
}

export const remotePath = (space, key) => `wcloud:${space}/${key}`;

// Turn rclone/S3 noise into something a user can act on. These four cover every
// misconfiguration we've actually hit; anything else falls through to the raw
// tail so nothing is hidden.
export function explainSpacesError(raw, { space, endpoint } = {}) {
  const s = String(raw || '');
  const where = `${space || 'the Space'} at ${endpoint || 'the configured endpoint'}`;
  if (/InvalidAccessKeyId/i.test(s)) {
    return `Access key not recognized — check the Spaces access key (it is not the same as a DigitalOcean API token).`;
  }
  if (/SignatureDoesNotMatch/i.test(s)) {
    return `Secret key does not match the access key — re-enter the Spaces secret.`;
  }
  if (/NoSuchBucket|bucket does not exist|specified bucket does not exist/i.test(s)) {
    return `Space not found: ${where}. Check the Space name, and that its region matches the region selected here.`;
  }
  if (/AccessDenied/i.test(s)) {
    return `Access denied on ${where}. Usually one of: the Space is in a different region than the one selected here, or the key is scoped to a different Space / lacks write permission.`;
  }
  if (/no such host|dial tcp|i\/o timeout|connection refused/i.test(s)) {
    return `Could not reach ${endpoint || 'the endpoint'} — check the region setting and the server's network access.`;
  }
  return s.trim().slice(-300);
}
