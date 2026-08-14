import express from 'express';
import config, { validateConfig } from './config.js';
import { requireAuth } from './auth.js';
import { getOperation } from './operations/index.js';
import { enqueue, getJob, listJobs, publicView, subscribe, cancelJob } from './jobs.js';
import { woSiteList, run } from './lib/sys.js';
import { enforceAdminPanelCert } from './lib/panelcert.js';
import { getCredentials } from './lib/credentials.js';

// --- startup validation -----------------------------------------------------
const problems = validateConfig();
if (problems.length) {
  console.error('Refusing to start due to configuration problems:');
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}

// Pin the :22222 admin panel to its self-signed cert and lock it immutable, so
// it can't be repointed at a deletable site cert. Idempotent; best-effort.
enforceAdminPanelCert().catch((e) => console.error('[agent] panel-cert enforce failed:', e));

const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', true);
app.use(express.json({ limit: '64kb' }));

// --- health (unauthenticated, minimal) --------------------------------------
// Useful for the panel to see the server is up before auth. Reveals nothing.
app.get('/healthz', (req, res) => {
  res.json({ ok: true, server: config.serverName, time: Date.now() });
});

// Everything below requires auth + passes the IP allowlist.
app.use(requireAuth);

// --- server info ------------------------------------------------------------
app.get('/api/info', async (req, res) => {
  const helpers = { log: () => {}, err: () => {}, onCancel: () => {} };
  const info = {
    server: config.serverName,
    operations: ['deploy', 'update', 'delete', 'ssl', 'purge', 'resetPassword'],
    maxConcurrentJobs: config.maxConcurrentJobs,
  };

  try {
    // OS info
    const osRelease = await run(helpers, 'cat', ['/etc/os-release'], { quiet: true });
    if (osRelease.code === 0) {
      const parse = (s) => Object.fromEntries(s.split('\n').filter(l => l.includes('=')).map(l => {
        const [k, ...v] = l.split('=');
        return [k, v.join('=').replace(/"/g, '')];
      }));
      info.os = parse(osRelease.stdout);
    }

    // Kernel
    const kernel = await run(helpers, 'uname', ['-r'], { quiet: true });
    if (kernel.code === 0) info.kernel = kernel.stdout.trim();

    // Hostname
    const hostname = await run(helpers, 'hostname', [], { quiet: true });
    if (hostname.code === 0) info.hostname = hostname.stdout.trim();

    // Uptime
    const uptime = await run(helpers, 'uptime', ['-p'], { quiet: true });
    if (uptime.code === 0) info.uptime = uptime.stdout.trim();

    // CPU load (1, 5, 15 min)
    const loadavg = await run(helpers, 'cat', ['/proc/loadavg'], { quiet: true });
    if (loadavg.code === 0) {
      const parts = loadavg.stdout.trim().split(' ');
      info.load = { '1m': parts[0], '5m': parts[1], '15m': parts[2] };
    }

    // CPU cores
    const nproc = await run(helpers, 'nproc', [], { quiet: true });
    if (nproc.code === 0) info.cpuCores = parseInt(nproc.stdout.trim(), 10);

    // Memory
    const meminfo = await run(helpers, 'cat', ['/proc/meminfo'], { quiet: true });
    if (meminfo.code === 0) {
      const getMem = (key) => {
        const m = meminfo.stdout.match(new RegExp(`${key}:\\s+(\\d+)`));
        return m ? parseInt(m[1], 10) : 0;
      };
      const total = getMem('MemTotal');
      const available = getMem('MemAvailable');
      const used = total - available;
      info.memory = {
        total: `${(total / 1024 / 1024).toFixed(1)} GB`,
        used: `${(used / 1024 / 1024).toFixed(1)} GB`,
        available: `${(available / 1024 / 1024).toFixed(1)} GB`,
        percent: total > 0 ? Math.round((used / total) * 100) : 0,
      };
    }

    // Disk usage for /
    const df = await run(helpers, 'df', ['-h', '/'], { quiet: true });
    if (df.code === 0) {
      const lines = df.stdout.trim().split('\n');
      if (lines.length > 1) {
        const parts = lines[1].split(/\s+/);
        info.disk = {
          total: parts[1],
          used: parts[2],
          available: parts[3],
          percent: parts[4],
          mount: parts[5],
        };
      }
    }

    // Nginx version
    const nginx = await run(helpers, 'nginx', ['-v'], { quiet: true });
    if (nginx.code === 0 || nginx.stderr.includes('nginx version')) {
      const m = nginx.stderr.match(/nginx\/([\d.]+)/);
      if (m) info.nginx = m[1];
    }

    // PHP version
    const php = await run(helpers, 'php', ['-v'], { quiet: true });
    if (php.code === 0) {
      const m = php.stdout.match(/PHP\s+([\d.]+)/);
      if (m) info.php = m[1];
    }

    // PHP-FPM service status
    const { getPhpVersion } = await import('./lib/sys.js');
    const phpVer = getPhpVersion();
    const phpStatus = await run(helpers, 'systemctl', ['is-active', phpVer.service], { quiet: true });
    info.phpFpm = {
      version: phpVer.version,
      status: phpStatus.stdout.trim() === 'active' ? 'active' : 'inactive',
      service: phpVer.service,
    };

    // MariaDB version + status. Client CLIs (`mysql`/`mariadb`) may be absent on
    // a server-only install, so fall back to the daemon (`mariadbd`/`mysqld`),
    // which is guaranteed present when the service runs. All report the version
    // as `X.Y.Z-MariaDB`; plain MySQL has no `-MariaDB` suffix (`Ver 8.0.36`).
    info.mariadbStatus = 'unknown';
    for (const [bin, arg] of [['mariadb', '-V'], ['mysql', '-V'], ['mariadbd', '--version'], ['mysqld', '--version']]) {
      try {
        const r = await run(helpers, bin, [arg], { quiet: true });
        const out = (r.stdout + r.stderr).replace(/\x1b\[[0-9;]*m/g, '');
        const m = out.match(/(\d+\.\d+\.\d+)-MariaDB/i) || out.match(/Ver\s+(\d+\.\d+)/);
        if (m) { info.mariadb = m[1]; break; }
      } catch {}
    }
    for (const svc of ['mariadb', 'mysql', 'mariadb10.11', 'mariadb10.6']) {
      const ms = await run(helpers, 'systemctl', ['is-active', svc], { quiet: true });
      const s = ms.stdout.trim();
      if (s === 'active') { info.mariadbStatus = 'active'; break; }
      if (s) info.mariadbStatus = s;
    }

    // WordOps version
    const wo = await run(helpers, 'wo', ['--version'], { quiet: true });
    if (wo.code === 0) {
      info.wordops = wo.stdout.trim();
    }

    // Redis version + status
    info.redisStatus = 'unknown';
    try {
      const redis = await run(helpers, 'redis-server', ['--version'], { quiet: true });
      const redisOut = (redis.stdout + redis.stderr).replace(/\x1b\[[0-9;]*m/g, '');
      const redisVer = redisOut.match(/v=([\d.]+)/) || redisOut.match(/v([\d.]+)/);
      if (redisVer) info.redis = redisVer[1];
    } catch {}
    for (const svc of ['redis-server', 'redis', 'redis7', 'redis6', 'redis5']) {
      const rs = await run(helpers, 'systemctl', ['is-active', svc], { quiet: true });
      const s = rs.stdout.trim();
      if (s === 'active') { info.redisStatus = 'active'; break; }
      if (s) info.redisStatus = s;
    }

    // Node.js version
    const node = await run(helpers, 'node', ['--version'], { quiet: true });
    if (node.code === 0) info.node = node.stdout.trim().replace('v', '');

  } catch (e) {
    // Non-critical; info endpoint still returns basic data
    console.error('[agent] info gather error:', e.message);
  }

  res.json(info);
});

// --- list websites on this server ------------------------------------------
// GET /api/sites  ->  { server, sites: [domain, ...] }
// Read-only; runs `wo site list` directly (not a job).
app.get('/api/sites', async (req, res) => {
  // sys.run expects a helpers object; for a one-shot read we discard output.
  const helpers = { log: () => {}, err: () => {}, onCancel: () => {} };
  try {
    const sites = await woSiteList(helpers);
    res.json({ server: config.serverName, count: sites.length, sites });
  } catch (e) {
    res.status(500).json({ error: 'wo_site_list_failed', message: e?.message || 'failed' });
  }
});

// --- start an operation -----------------------------------------------------
// POST /api/op/:type   body = operation params
// Returns { jobId } immediately; watch logs via SSE or poll the job.
app.post('/api/op/:type', (req, res) => {
  const type = req.params.type;
  const op = getOperation(type);
  if (!op) return res.status(404).json({ error: 'unknown_operation', type });

  const { ok, errors, clean } = op.validate(req.body || {});
  if (!ok) return res.status(400).json({ error: 'validation_failed', errors });

  const job = enqueue(type, clean, (j, helpers) => op.run(j, helpers, clean));
  res.status(202).json({ jobId: job.id, state: job.state, view: publicView(job) });
});

// --- list jobs --------------------------------------------------------------
app.get('/api/jobs', (req, res) => {
  res.json({ jobs: listJobs() });
});

// --- job status -------------------------------------------------------------
app.get('/api/jobs/:id', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'not_found' });
  res.json(publicView(job));
});

// --- job logs (full buffer, JSON) -------------------------------------------
app.get('/api/jobs/:id/logs', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'not_found' });
  res.json({ id: job.id, state: job.state, log: job.log });
});

// --- job logs (live stream, SSE) --------------------------------------------
// GET /api/jobs/:id/stream
// Emits event: line   data: {t,stream,line}
//       event: state  data: {state,reason}
// Replays existing log lines first, then streams new ones until terminal.
app.get('/api/jobs/:id/stream', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'not_found' });

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no', // disable nginx buffering if proxied
  });
  res.flushHeaders?.();

  const send = (event, data) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  send('hello', { id: job.id, state: job.state });

  const unsub = subscribe(
    job,
    (entry) => send('line', entry),
    (st) => {
      send('state', st);
      if (['succeeded', 'failed', 'timeout', 'cancelled'].includes(st.state)) {
        // Close the stream once the job is done.
        setTimeout(() => res.end(), 50);
      }
    }
  );

  // Heartbeat so proxies/load balancers don't drop the idle connection.
  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  hb.unref?.();

  req.on('close', () => {
    clearInterval(hb);
    unsub();
  });
});

// --- cancel a job -----------------------------------------------------------
app.post('/api/jobs/:id/cancel', (req, res) => {
  const result = cancelJob(req.params.id);
  if (!result.ok) return res.status(409).json({ error: 'cannot_cancel', reason: result.reason });
  res.json({ ok: true });
});

// --- get recorded WordPress credentials for a domain (set by deploy) --------
// Already behind requireAuth (mounted above). 404 covers both "never
// deployed through this agent" and "captured over an hour ago".
app.get('/api/sites/:domain/credentials', (req, res) => {
  const creds = getCredentials(req.params.domain);
  if (!creds) return res.status(404).json({ error: 'not_found' });
  const { timestamp, ...rest } = creds;
  res.json(rest);
});

// --- 404 + error handlers ---------------------------------------------------
app.use((req, res) => res.status(404).json({ error: 'not_found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('unhandled error:', err);
  res.status(500).json({ error: 'internal_error' });
});

const server = app.listen(config.port, config.host, () => {
  console.log(
    `[agent] ${config.serverName} listening on http://${config.host}:${config.port} ` +
      `(allowlist: ${config.allowedIps.length ? config.allowedIps.join(',') : 'ANY'}, ` +
      `concurrency: ${config.maxConcurrentJobs})`
  );
});

// Graceful shutdown
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log(`\n[agent] ${sig} received, shutting down...`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}