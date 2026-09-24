import express from 'express';
import dns from 'node:dns';
import { execSync, spawn } from 'node:child_process';

// Prefer IPv4 for the agent's own outbound (enrolment, provision log) — fresh
// VPS images often have a broken/unrouted IPv6 that stalls Node's fetch. Mirrors
// the system-wide gai.conf preference init.sh sets.
dns.setDefaultResultOrder('ipv4first');
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import config, { validateConfig } from './config.js';
import { requireAuth } from './auth.js';
import { getOperation } from './operations/index.js';
import { serveExport } from './operations/export.js';
import { enqueue, getJob, listJobs, publicView, subscribe, cancelJob } from './jobs.js';
import { woSiteList, run, getPhpVersion, readCanonical } from './lib/sys.js';
import { listTopLevel, putObject, deleteObject, statObject, explainSpacesError } from './lib/spaces.js';
import { enforceAdminPanelCert } from './lib/panelcert.js';
import { readDbCredentials } from './lib/credentials.js';
import { readSiteSsl } from './lib/certinfo.js';
import { readChallenge } from './lib/acmedns.js';
import { readWpVersion } from './lib/wpinfo.js';
import { enroll } from './enroll.js';
import { normDomain, isDomain } from './operations/index.js';

// --- startup validation -----------------------------------------------------
const problems = validateConfig();
if (problems.length) {
  console.error('Refusing to start due to configuration problems:');
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}

// WordOps' `wo` prompts for a git identity when none is set, which hangs any
// endpoint that shells out to it (e.g. /api/info). Seed one so `wo` stays
// non-interactive — covers servers installed before init.sh did this.
try {
  execSync('git config --global user.name', { stdio: 'ignore' });
} catch {
  try {
    execSync('git config --global user.name wcloud && git config --global user.email agent@wcloud.local', { stdio: 'ignore' });
  } catch { /* git absent or unwritable — best-effort */ }
}

// Pin the :22222 admin panel to its self-signed cert and lock it immutable, so
// it can't be repointed at a deletable site cert. Idempotent; best-effort.
enforceAdminPanelCert().catch((e) => console.error('[agent] panel-cert enforce failed:', e));

const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', true);

// --- health (unauthenticated, minimal) --------------------------------------
// Useful for the panel to see the server is up before auth. Reveals nothing.
app.get('/healthz', (req, res) => {
  res.json({ ok: true, server: config.serverName, version: config.version, commit: config.commit, time: Date.now() });
});

// --- export archive (one-time token, no auth needed) -------------------------
// The token is the access control — one-time use, expires in 1 hour.
app.get('/api/export/:token', async (req, res) => {
  try {
    await serveExport(req.params.token, res);
  } catch (e) {
    console.error('[agent] export serve error:', e.message);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'serve_failed' }));
    }
  }
});

// Everything below requires auth + passes the IP allowlist.
app.use(requireAuth);
// Parse bodies only AFTER auth: unauthenticated callers must not make us parse
// 256kb payloads (or reach the error handler with malformed JSON). 256kb: a
// pasted custom cert+key pair (up to 60KB each, see the ssl op) plus JSON
// overhead must fit in the authenticated body.
app.use(express.json({ limit: '256kb' }));

const NOOP_HELPERS = { log: () => {}, err: () => {} };

// The git checkout this server.js runs from (src/..). On managed servers that's
// /opt/wcloud; derived from the file location so it also works elsewhere.
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// --- server info ------------------------------------------------------------
app.get('/api/info', async (req, res) => {
  const helpers = NOOP_HELPERS;
  const info = {
    server: config.serverName,
    version: config.version,
    commit: config.commit,
    operations: ['deploy', 'update', 'delete', 'ssl', 'sslDnsVerify', 'canonical', 'purge', 'resetPassword', 'export', 'import'],
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
    const df = await run(helpers, 'df', ['-h', '/'], { quiet: true, timeout: 10000 });
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
    const nginx = await run(helpers, 'nginx', ['-v'], { quiet: true, timeout: 8000 });
    if (nginx.code === 0 || nginx.stderr.includes('nginx version')) {
      const m = nginx.stderr.match(/nginx\/([\d.]+)/);
      if (m) info.nginx = m[1];
    }

    // PHP version
    const php = await run(helpers, 'php', ['-v'], { quiet: true, timeout: 8000 });
    if (php.code === 0) {
      const m = php.stdout.match(/PHP\s+([\d.]+)/);
      if (m) info.php = m[1];
    }

    // PHP-FPM service status
    const phpVer = getPhpVersion();
    const phpStatus = await run(helpers, 'systemctl', ['is-active', phpVer.service], { quiet: true, timeout: 10000 });
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
        const r = await run(helpers, bin, [arg], { quiet: true, timeout: 10000 });
        const out = (r.stdout + r.stderr).replace(/\x1b\[[0-9;]*m/g, '');
        const m = out.match(/(\d+\.\d+\.\d+)-MariaDB/i) || out.match(/Ver\s+(\d+\.\d+)/);
        if (m) { info.mariadb = m[1]; break; }
      } catch {}
    }
    for (const svc of ['mariadb', 'mysql', 'mariadb10.11', 'mariadb10.6']) {
      const ms = await run(helpers, 'systemctl', ['is-active', svc], { quiet: true, timeout: 10000 });
      const s = ms.stdout.trim();
      if (s === 'active') { info.mariadbStatus = 'active'; break; }
      if (s) info.mariadbStatus = s;
    }

    // WordOps version. Timeout-guarded: `wo` prompts (and hangs) if git has no
    // identity configured, which would otherwise stall this whole endpoint.
    const wo = await run(helpers, 'wo', ['--version'], { quiet: true, timeout: 8000 });
    if (wo.code === 0) {
      info.wordops = wo.stdout.trim();
    }

    // Redis version + status
    info.redisStatus = 'unknown';
    try {
      const redis = await run(helpers, 'redis-server', ['--version'], { quiet: true, timeout: 8000 });
      const redisOut = (redis.stdout + redis.stderr).replace(/\x1b\[[0-9;]*m/g, '');
      const redisVer = redisOut.match(/v=([\d.]+)/) || redisOut.match(/v([\d.]+)/);
      if (redisVer) info.redis = redisVer[1];
    } catch {}
    for (const svc of ['redis-server', 'redis', 'redis7', 'redis6', 'redis5']) {
      const rs = await run(helpers, 'systemctl', ['is-active', svc], { quiet: true, timeout: 8000 });
      const s = rs.stdout.trim();
      if (s === 'active') { info.redisStatus = 'active'; break; }
      if (s) info.redisStatus = s;
    }

    // Node.js version
    const node = await run(helpers, 'node', ['--version'], { quiet: true, timeout: 8000 });
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
  const helpers = NOOP_HELPERS;
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

  const job = enqueue(type, clean, (j, helpers) => op.run(j, helpers, clean),
    op.timeout ? { timeout: op.timeout } : {});
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

// --- get a site's DB credentials, read live from wp-config.php --------------
// Already behind requireAuth (mounted above). 404 = not a WordPress site the
// agent can read (missing/invalid wp-config.php).
app.get('/api/sites/:domain/credentials', async (req, res) => {
  const helpers = NOOP_HELPERS;
  try {
    const creds = await readDbCredentials(helpers, req.params.domain);
    if (!creds) return res.status(404).json({ error: 'not_found' });
    res.json(creds);
  } catch (e) {
    res.status(500).json({ error: 'read_failed', message: e?.message || 'failed' });
  }
});

// --- WordPress version for a site (live via wp-cli, nothing stored) -----------
app.get('/api/sites/:domain/wp', async (req, res) => {
  const domain = normDomain(req.params.domain);
  if (!isDomain(domain)) return res.status(400).json({ error: 'invalid_domain' });
  try {
    const v = await readWpVersion(NOOP_HELPERS, domain);
    if (!v) return res.status(404).json({ error: 'not_found' });
    res.json({ domain, wp_version: v });
  } catch (e) {
    res.status(500).json({ error: 'read_failed', message: e?.message || 'failed' });
  }
});

// --- live SSL state for a site ------------------------------------------------
// The cert on disk is the source of truth — nothing stored, everything parsed
// on demand. Feeds the site page's SSL status card.
app.get('/api/sites/:domain/ssl', async (req, res) => {
  const domain = normDomain(req.params.domain);
  if (!isDomain(domain)) return res.status(400).json({ error: 'invalid_domain' });
  const helpers = NOOP_HELPERS;
  try {
    res.json(await readSiteSsl(helpers, domain));
  } catch (e) {
    res.status(500).json({ error: 'read_failed', message: e?.message || 'failed' });
  }
});

// --- live domain preference (www / preferred address) ------------------------
// Read from the nginx config on disk, like the SSL state — nothing stored, so
// the site page shows what is actually configured, not what deploy was told.
app.get('/api/sites/:domain/canonical', async (req, res) => {
  const domain = normDomain(req.params.domain);
  if (!isDomain(domain)) return res.status(400).json({ error: 'invalid_domain' });
  try {
    res.json(await readCanonical(NOOP_HELPERS, domain));
  } catch (e) {
    res.status(500).json({ error: 'read_failed', message: e?.message || 'failed' });
  }
});

// --- pending manual DNS-01 challenge for a site -------------------------------
// Step 1 of the manual flow leaves TXT records in a state file (the agent is
// stateless otherwise — jobs die on restart). The portal polls this to show
// the records, so the flow survives page reloads and agent restarts.
app.get('/api/sites/:domain/ssl-challenge', async (req, res) => {
  const domain = normDomain(req.params.domain);
  if (!isDomain(domain)) return res.status(400).json({ error: 'invalid_domain' });
  try {
    const state = await readChallenge(domain);
    res.json(state
      ? { domain, pending: true, started_at: state.started_at, txt_records: state.txt_records }
      : { domain, pending: false });
  } catch (e) {
    res.status(500).json({ error: 'read_failed', message: e?.message || 'failed' });
  }
});

// --- self-update -------------------------------------------------------------
// Pull-only update: hard reset to origin/main (never `git pull` — the checkout
// accumulates local drift; .env/.enrolled are gitignored so config survives) and
// reinstall deps. The restart is scheduled in systemd (systemd-run timer), not
// in this process, so it fires after the response has flushed even though the
// restart SIGTERMs us. Runs as root, so the origin/branch are hardcoded —
// nothing from the request body ever reaches a shell.
let selfUpdating = false;
app.post('/api/self-update', async (req, res) => {
  // The restart stops everything in the unit — a restore/delete/import would be
  // cut off mid-way (wo, mysql, tar killed). ponytail: a job enqueued during the
  // git/npm window can still be cut; recheck before restart if that ever bites.
  if (listJobs().some((j) => j.state === 'queued' || j.state === 'running')) {
    return res.status(409).json({ ok: false, error: 'An operation is running on this server — update once it finishes.' });
  }
  if (selfUpdating) return res.status(409).json({ ok: false, error: 'An update is already in progress.' });
  selfUpdating = true;
  try {
    const helpers = NOOP_HELPERS;
    const git = (args, timeout = 120000) =>
      run(helpers, 'git', args, { cwd: REPO_ROOT, quiet: true, timeout });
    const tail = (r) => (r.stderr || r.stdout || '').trim().split('\n').slice(-3).join(' | ');

    const before = await git(['rev-parse', 'HEAD'], 10000);
    if (before.code !== 0) return res.status(500).json({ ok: false, error: `not a git checkout: ${tail(before)}` });
    const beforeSha = before.stdout.trim();
    const fetchR = await git(['fetch', 'origin']);
    if (fetchR.code !== 0) return res.status(500).json({ ok: false, error: `git fetch failed: ${tail(fetchR)}` });
    const reset = await git(['reset', '--hard', 'origin/main']);
    if (reset.code !== 0) return res.status(500).json({ ok: false, error: `git reset failed: ${tail(reset)}` });
    const after = (await git(['rev-parse', '--short', 'HEAD'], 10000)).stdout.trim();
    const inst = await run(helpers, 'npm', ['install', '--omit=dev', '--no-audit', '--no-fund'],
      { cwd: REPO_ROOT, quiet: true, timeout: 300000 });
    if (inst.code !== 0) {
      // New code + old deps would crash-loop on the next restart/reboot — and a
      // down agent can't be self-updated again. Put the old code back.
      await git(['reset', '--hard', beforeSha]);
      return res.status(500).json({ ok: false, error: `npm install failed (update rolled back): ${tail(inst)}` });
    }

    const version = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')).version;
    res.json({ ok: true, updated: !beforeSha.startsWith(after), old_commit: beforeSha.slice(0, 7), new_commit: after, version });
  } finally {
    selfUpdating = false;
  }
  // Detached: the transient unit (and its 2s delay) lives under systemd, not us.
  try {
    spawn('systemd-run', ['--on-active=2', 'systemctl', 'restart', 'wcloud'], { detached: true, stdio: 'ignore' }).unref();
  } catch (e) {
    console.error('[agent] self-update: failed to schedule restart:', e.message);
  }
});

// --- Spaces validation / deletion (quick calls, not jobs) ------------------
// Creds ride in the authenticated request body, live in the S3 client for the
// duration of one call, and never touch logs or disk.
function spacesBodyOk(p) {
  return typeof p === 'object' && p !== null &&
    typeof p.space === 'string' && /^[a-z0-9][a-z0-9-]*$/.test(p.space) &&
    typeof p.endpoint === 'string' && p.endpoint.length > 0 &&
    typeof p.accessKeyId === 'string' && p.accessKeyId.length > 0 &&
    typeof p.secretAccessKey === 'string' && p.secretAccessKey.length > 0;
}

// Full round-trip: list (read) THEN write + delete a tiny probe object. A
// read-only check passes on a Space the key cannot write to, so a backup would
// still fail — but only after building and encrypting the whole archive. This
// fails in seconds instead, with the reason.
app.post('/api/backup-test', async (req, res) => {
  const p = req.body || {};
  if (!spacesBodyOk(p)) return res.status(400).json({ error: 'validation_failed', errors: ['space, endpoint, accessKeyId, secretAccessKey are required'] });
  const probeKey = `.wcloud-write-test/${randomBytes(8).toString('hex')}`;
  let dirs;
  try {
    dirs = (await listTopLevel(p)).length;
  } catch (e) {
    return res.status(502).json({ error: 'spaces_unreachable', stage: 'read', message: explainSpacesError(e, p) });
  }
  try {
    // Write probe — the step that actually proves a backup can upload.
    await putObject(p, probeKey, 'wcloud write test\n');
  } catch (e) {
    return res.status(502).json({ error: 'spaces_not_writable', stage: 'write', message: explainSpacesError(e, p) });
  }
  // Clean up the probe. A failure here doesn't invalidate the test — the write
  // worked — but say so, since it leaves one stray object behind.
  let note;
  try {
    await deleteObject(p, probeKey);
  } catch {
    note = `wrote OK but could not remove the test object (${probeKey}) — delete it manually`;
  }
  res.json({ ok: true, dirs, writable: true, ...(note ? { note } : {}) });
});

// Does a backup object exist? Agent jobs are in-memory, so an agent restart
// loses the outcome of an upload that already finished. The object itself is
// the source of truth — the portal asks here instead of guessing.
app.post('/api/backup-stat', async (req, res) => {
  const p = req.body || {};
  if (!spacesBodyOk(p)) return res.status(400).json({ error: 'validation_failed', errors: ['space, endpoint, accessKeyId, secretAccessKey are required'] });
  if (typeof p.key !== 'string' || !p.key.startsWith('backups/') || p.key.includes('..')) {
    return res.status(400).json({ error: 'validation_failed', errors: ['key must be a backups/ object key'] });
  }
  try {
    res.json(await statObject(p, p.key));
  } catch (e) {
    res.status(502).json({ error: 'stat_failed', message: explainSpacesError(e, p) });
  }
});

app.post('/api/backup-delete', async (req, res) => {
  const p = req.body || {};
  if (!spacesBodyOk(p)) return res.status(400).json({ error: 'validation_failed', errors: ['space, endpoint, accessKeyId, secretAccessKey are required'] });
  if (typeof p.key !== 'string' || !p.key.startsWith('backups/') || p.key.includes('..')) {
    return res.status(400).json({ error: 'validation_failed', errors: ['key must be a backups/ object key'] });
  }
  try {
    // S3 DELETE is idempotent — a missing key succeeds, which is what retention
    // pruning wants (the row goes away either way).
    await deleteObject(p, p.key);
    res.json({ ok: true, deleted: true });
  } catch (e) {
    res.status(502).json({ error: 'delete_failed', message: explainSpacesError(e, p) });
  }
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
  enroll(); // self-register with the portal if PORTAL_ENROLL_URL/ENROLL_TOKEN are set
});

// Graceful shutdown
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log(`\n[agent] ${sig} received, shutting down...`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}