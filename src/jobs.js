import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import config from './config.js';

// Job states
export const STATE = {
  QUEUED: 'queued',
  RUNNING: 'running',
  SUCCEEDED: 'succeeded',
  FAILED: 'failed',
  TIMEOUT: 'timeout',
  CANCELLED: 'cancelled',
};

const TERMINAL = new Set([STATE.SUCCEEDED, STATE.FAILED, STATE.TIMEOUT, STATE.CANCELLED]);

const jobs = new Map();

const queue = [];

function makeJob(type, params) {
  const id = crypto.randomUUID();
  const job = {
    id,
    type,
    params,
    state: STATE.QUEUED,
    createdAt: Date.now(),
    startedAt: null,
    finishedAt: null,
    exitReason: null,
    log: [],
    logCap: 5000,
    result: null, // ops can set this to return structured data
    _emitter: new EventEmitter(),
    // One signal per job: cancel and timeout abort it, and every consumer
    // listens (run() kills its process group and refuses to start new commands;
    // S3 transfers abort). A per-command callback slot used to go stale between
    // commands and during transfers, so cancel/timeout killed nothing.
    _abort: new AbortController(),
    _cancelRequested: false,
  };
  job._emitter.setMaxListeners(50);
  jobs.set(id, job);
  return job;
}

export function getJob(id) {
  return jobs.get(id);
}

export function listJobs() {
  return [...jobs.values()]
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(publicView);
}

export function publicView(job) {
  return {
    id: job.id,
    type: job.type,
    params: redactParams(job.params),
    state: job.state,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    exitReason: job.exitReason,
    logLines: job.log.length,
    result: job.result ? redactParams(job.result) : null,
  };
}

function redactParams(params = {}) {
  if (!params || typeof params !== 'object') return params;
  const clone = { ...params };
  for (const k of Object.keys(clone)) {
    // cert = the pasted fullchain (public, but never echoed either); key = secret.
    if (/pass|secret|token|key|cert/i.test(k)) clone[k] = '***';
  }
  return clone;
}

export function appendLog(job, line, stream = 'stdout') {
  const entry = { t: Date.now(), stream, line: String(line) };
  job.log.push(entry);
  if (job.log.length > job.logCap) job.log.shift();
  job._emitter.emit('line', entry);
}

function setState(job, state, reason = null) {
  job.state = state;
  if (reason) job.exitReason = reason;
  if (TERMINAL.has(state)) job.finishedAt = Date.now();
  // One line per start/finish in the agent's own log (journalctl -u wcloud —
  // the portal's server "Agent log" tab); the step-by-step log stays on the job.
  if (state === STATE.RUNNING || TERMINAL.has(state)) {
    const took = TERMINAL.has(state) && job.startedAt ? ` in ${((job.finishedAt - job.startedAt) / 1000).toFixed(1)}s` : '';
    (state === STATE.SUCCEEDED || state === STATE.RUNNING ? console.log : console.error)(
      `[job] ${job.type}${job.params?.domain ? ` ${job.params.domain}` : ''} ${state}${took}${reason ? `: ${reason}` : ''} (${job.id.slice(0, 8)})`);
  }
  job._emitter.emit('state', { state, reason });
  if (TERMINAL.has(state)) scheduleCleanup(job);
}

function scheduleCleanup(job) {
  setTimeout(() => {
    jobs.delete(job.id);
  }, config.jobRetentionMs).unref?.();
}

export function subscribe(job, onLine, onState) {
  for (const entry of job.log) onLine(entry);
  if (TERMINAL.has(job.state)) {
    onState({ state: job.state, reason: job.exitReason });
    return () => {};
  }
  job._emitter.on('line', onLine);
  job._emitter.on('state', onState);
  return () => {
    job._emitter.off('line', onLine);
    job._emitter.off('state', onState);
  };
}

export function enqueue(type, params, runner, opts = {}) {
  const job = makeJob(type, params);
  job._runner = runner;
  job._timeout = opts.timeout || null; // per-op override (e.g. long backups)
  queue.push(job);
  drain();
  return job;
}

// Up to maxConcurrentJobs at once, oldest first — but never two jobs on the
// same site (each reads and rewrites that site's spec), and a job without a
// site (reconcile: every site) runs alone. Server-wide sections inside jobs
// (config writes + reloads, apt, acme.sh) take turns via sys.withLock.
const active = new Set(); // running jobs
const siteOf = (job) => job.params?.domain || null;
function canStart(job) {
  if (!active.size) return true;
  const d = siteOf(job);
  if (!d) return false;
  for (const a of active) if (!siteOf(a) || siteOf(a) === d) return false;
  return true;
}
function drain() {
  for (let i = 0; i < queue.length && active.size < config.maxConcurrentJobs;) {
    const job = queue[i];
    if (job.state === STATE.CANCELLED) { queue.splice(i, 1); continue; }
    // A site-less job waits for everything before it and holds back what's after.
    if (!siteOf(job) && active.size) break;
    if (!canStart(job)) { i++; continue; }
    queue.splice(i, 1);
    void startJob(job);
  }
}

async function startJob(job) {
  active.add(job);
  job.startedAt = Date.now();
  setState(job, STATE.RUNNING);

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    job._abort.abort('timeout');
  }, job._timeout || config.jobTimeoutMs);
  timer.unref?.();

  const helpers = {
    log: (line) => appendLog(job, line, 'stdout'),
    err: (line) => appendLog(job, line, 'stderr'),
    signal: job._abort.signal,
  };

  try {
    await job._runner(job, helpers);
    if (timedOut) {
      setState(job, STATE.TIMEOUT, 'operation exceeded time limit');
    } else {
      setState(job, STATE.SUCCEEDED);
    }
  } catch (e) {
    if (timedOut) {
      setState(job, STATE.TIMEOUT, 'operation exceeded time limit');
    } else if (job._cancelRequested) {
      appendLog(job, 'Cancelled.', 'stderr');
      setState(job, STATE.CANCELLED, 'cancelled while running');
    } else {
      appendLog(job, `ERROR: ${e?.message || e}`, 'stderr');
      setState(job, STATE.FAILED, e?.message || 'operation failed');
    }
  } finally {
    clearTimeout(timer);
    active.delete(job);
    drain();
  }
}

export function cancelJob(id) {
  const job = jobs.get(id);
  if (!job) return { ok: false, reason: 'not_found' };
  if (TERMINAL.has(job.state)) return { ok: false, reason: 'already_finished' };
  if (job.state === STATE.QUEUED) {
    setState(job, STATE.CANCELLED, 'cancelled while queued');
    return { ok: true };
  }
  job._cancelRequested = true;
  job._abort.abort('cancelled');
  return { ok: true };
}
