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

// In-memory job store. For a single-server agent this is fine; jobs are
// ephemeral operational records, not durable state. Restarting the agent
// forgets history (acceptable — the control panel is the system of record).
const jobs = new Map();

let running = 0;
const queue = [];

// Each job gets its own emitter for log/line + state events (SSE subscribes).
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
    exitReason: null, // human string on failure
    // Ring buffer of log lines (cap to avoid unbounded memory).
    log: [],
    logCap: 5000,
    _emitter: new EventEmitter(),
    _cancel: null, // set to a cancel function while running
  };
  job._emitter.setMaxListeners(50); // many SSE clients could attach
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

// What we expose over the API (no emitter, no internals).
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
  };
}

// Never echo secrets (DB passwords, tokens) back in job views.
function redactParams(params = {}) {
  const clone = { ...params };
  for (const k of Object.keys(clone)) {
    if (/pass|secret|token|key/i.test(k)) clone[k] = '***';
  }
  return clone;
}

// Append a log line, emit it, and trim the ring buffer.
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
  job._emitter.emit('state', { state, reason });
  if (TERMINAL.has(state)) scheduleCleanup(job);
}

function scheduleCleanup(job) {
  setTimeout(() => {
    jobs.delete(job.id);
  }, config.jobRetentionMs).unref?.();
}

// Subscribe to a job's live events. Returns an unsubscribe function.
// Immediately replays existing log lines so a late SSE client sees full history.
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

/**
 * Enqueue a new job.
 * @param {string} type  operation name (deploy/update/delete/ssl/purge/resetPassword)
 * @param {object} params validated params for the operation
 * @param {function} runner  async (job, helpers) => void ; throws on failure
 * @returns {object} the job (public view via publicView)
 */
export function enqueue(type, params, runner) {
  const job = makeJob(type, params);
  job._runner = runner;
  queue.push(job);
  drain();
  return job;
}

// Attempt to start queued jobs up to the concurrency limit.
function drain() {
  while (running < config.maxConcurrentJobs && queue.length > 0) {
    const job = queue.shift();
    if (job.state === STATE.CANCELLED) continue;
    void startJob(job);
  }
}

async function startJob(job) {
  running += 1;
  job.startedAt = Date.now();
  setState(job, STATE.RUNNING);

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    if (typeof job._cancel === 'function') job._cancel('timeout');
  }, config.jobTimeoutMs);
  timer.unref?.();

  const helpers = {
    log: (line) => appendLog(job, line, 'stdout'),
    err: (line) => appendLog(job, line, 'stderr'),
    // Operations set this so the runner can be interrupted (e.g. kill a child).
    onCancel: (fn) => {
      job._cancel = fn;
    },
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
    } else {
      appendLog(job, `ERROR: ${e?.message || e}`, 'stderr');
      setState(job, STATE.FAILED, e?.message || 'operation failed');
    }
  } finally {
    clearTimeout(timer);
    job._cancel = null;
    running -= 1;
    drain();
  }
}

// Cancel a queued or running job. Running jobs need a cooperative cancel fn.
export function cancelJob(id) {
  const job = jobs.get(id);
  if (!job) return { ok: false, reason: 'not_found' };
  if (TERMINAL.has(job.state)) return { ok: false, reason: 'already_finished' };
  if (job.state === STATE.QUEUED) {
    setState(job, STATE.CANCELLED, 'cancelled while queued');
    return { ok: true };
  }
  if (typeof job._cancel === 'function') {
    job._cancel('cancelled');
    return { ok: true };
  }
  return { ok: false, reason: 'not_cancellable' };
}