// Centralised configuration. All values come from environment variables so
// nothing sensitive is baked into the source. See .env.example.

function parseList(v) {
  if (!v) return [];
  return v.split(',').map((s) => s.trim()).filter(Boolean);
}

const config = {
  // HTTP
  port: parseInt(process.env.AGENT_PORT || '8787', 10),
  // Bind to loopback by default; set AGENT_HOST=0.0.0.0 to expose (behind the
  // IP allowlist + token). Prefer binding to a private/VPN interface.
  host: process.env.AGENT_HOST || '127.0.0.1',

  // Auth
  // Bearer token the control panel must send. REQUIRED — the agent refuses to
  // start without it, so we never accidentally run wide open.
  authToken: process.env.AGENT_TOKEN || '',

  // Comma-separated IP allowlist (control panel egress IPs). Empty = allow any
  // IP that presents a valid token (NOT recommended for a root agent).
  allowedIps: parseList(process.env.AGENT_ALLOWED_IPS),

  // Whether the agent trusts X-Forwarded-For (only enable behind a known proxy).
  trustProxy: process.env.AGENT_TRUST_PROXY === '1',

  // Paths
  binDir: process.env.AGENT_BIN_DIR || '/usr/local/bin',
  wwwDir: process.env.AGENT_WWW_DIR || '/var/www',

  // Job execution
  // Max concurrent jobs. Deploys touch nginx/php-fpm/DB; running several at once
  // risks races (nginx reloads, cron writes). Default 1 = serialize.
  maxConcurrentJobs: parseInt(process.env.AGENT_MAX_CONCURRENT || '1', 10),

  // How long to keep finished jobs (and their logs) in memory, ms.
  jobRetentionMs: parseInt(process.env.AGENT_JOB_RETENTION_MS || String(60 * 60 * 1000), 10),

  // Hard timeout for any single operation, ms. Deploys with SSL can be slow.
  jobTimeoutMs: parseInt(process.env.AGENT_JOB_TIMEOUT_MS || String(20 * 60 * 1000), 10),

  // Identify this server in responses (handy when the panel manages many).
  serverName: process.env.AGENT_SERVER_NAME || process.env.HOSTNAME || 'unknown',
};

export function validateConfig() {
  const problems = [];
  if (!config.authToken) {
    problems.push('AGENT_TOKEN is required (the shared bearer token).');
  } else if (config.authToken.length < 32) {
    problems.push('AGENT_TOKEN should be at least 32 chars (use a random 64-hex token).');
  }
  // Enforce secure default binding
  if (config.host === '0.0.0.0') {
    problems.push(
      'AGENT_HOST=0.0.0.0 is not allowed for security reasons. Set to loopback interface (127.0.0.1) or specific private IP.'
    );
  } else if (config.host !== '127.0.0.1' && config.allowedIps.length === 0) {
    problems.push(
      'Binding to a non-loopback IP without an IP allowlist exposes the agent to any IP. Set AGENT_ALLOWED_IPS to your control panel IP(s).'
    );
  }
  return problems;
}

export default config;