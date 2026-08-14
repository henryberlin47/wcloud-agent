import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import config from './config.js';

// Enroll tokens are one-time, so once we've registered we must not try again on
// every restart (the portal would 409). A marker file records success.
const MARKER = path.join(process.cwd(), '.enrolled');

// Register this agent with the portal so the server shows up without a manual
// "add server" form. Best-effort: enrollment must never stop the agent serving.
// A few retries cover a portal/network that isn't ready the instant we boot.
export async function enroll() {
  if (!config.enrollUrl || !config.enrollToken) return;
  if (fs.existsSync(MARKER)) return; // already enrolled (one-time token spent)

  const base_url = config.advertiseUrl || `http://${config.host}:${config.port}`;
  const payload = {
    token: config.enrollToken,
    api_key: config.authToken,
    base_url,
    port: config.port,
    name: config.serverName,
    hostname: os.hostname(),
    version: config.version,
    provision_id: config.provisionId,
  };

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetch(config.enrollUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000),
      });
      if (r.ok) {
        const data = await r.json().catch(() => ({}));
        try { fs.writeFileSync(MARKER, new Date().toISOString()); } catch { /* non-fatal */ }
        console.log(`[agent] enrolled with portal as server ${data.server_id || '?'}`);
        return;
      }
      // 4xx (bad/expired token) won't fix itself — stop retrying.
      const body = (await r.text()).slice(0, 200);
      console.warn(`[agent] enrollment rejected (${r.status}): ${body}`);
      if (r.status >= 400 && r.status < 500) return;
    } catch (e) {
      console.warn(`[agent] enrollment attempt ${attempt} failed: ${e}`);
    }
    if (attempt < 3) await new Promise((res) => setTimeout(res, 5000));
  }
  console.warn('[agent] enrollment did not succeed — re-run the installer to retry.');
}
