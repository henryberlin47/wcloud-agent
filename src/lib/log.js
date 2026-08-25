// ============================================================
//  log.js — job-log formatting shared by every operation
// ============================================================
// These logs are read by SITE OWNERS in the portal, not by sysadmins tailing a
// terminal. Write them for someone who knows their website but not this
// server's tooling.
//
//   ➜ 1. Create the WordPress site       ← a numbered stage
//        • Downloading WordPress          ← detail inside the stage
//        ✓ Site created                   ← result, past tense
//        ⚠ SSL not issued yet             ← went on, but they should know
//        ✗ Could not reach the database   ← what failed, and what to do
//
//   ✔ Site ready — example.com            ← one closing summary
//
// House rules (keep these when adding logs):
//  1. Name the outcome, not the command. "Web server reloaded", never
//     "nginx -t passed". The tool is an implementation detail; if it fails,
//     run() already dumps the command and its output for diagnosis.
//  2. No raw exit codes in a user-facing line. "(code 3)" tells a site owner
//     nothing — say what broke and what to do about it.
//  3. One idea per stage. Split "Validate + reload nginx, restart cron".
//  4. Results in past tense; stages describe the goal.
//  5. A warning or error should say what it means for the site, and the next
//     step if there is one.
// ============================================================

/**
 * @param {object} helpers            { log, err } from the job runner
 * @param {object} [opts]
 *   nested=true → this operation runs inside another one. Its stages become
 *                 indented detail lines so the parent's numbering stays
 *                 continuous (otherwise both count from 1 and the log reads
 *                 "1, 1, 2, 3, 4, 5, 2").
 */
export function logger(helpers, { nested = false } = {}) {
  let n = 0;
  return {
    /** Start a new numbered stage. */
    step: (label) => {
      if (nested) return helpers.log(`     • ${label}`);
      helpers.log('');
      helpers.log(`➜ ${++n}. ${label}`);
    },
    /** A stage that was deliberately not run. */
    skip: (label) => {
      if (nested) return helpers.log(`     • ${label} — skipped`);
      helpers.log('');
      helpers.log(`➜ ${++n}. ${label} — skipped`);
    },
    info: (m) => helpers.log(`     • ${m}`),
    ok: (m) => helpers.log(`     ✓ ${m}`),
    warn: (m) => helpers.log(`     ⚠ ${m}`),
    err: (m) => helpers.err(`     ✗ ${m}`),
    /** Closing summary of a successful operation. */
    done: (m) => helpers.log(nested ? `     ✓ ${m}` : `\n✔ ${m}`),
    /** Free-form line; prefer done() to close an operation. */
    log: (m) => helpers.log(nested ? `     • ${m}` : `\n${m}`),
  };
}

// Byte counts belong in the log as something a person can read: "56.4 MB",
// not "59156320".
export function humanSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return `${bytes}`;
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}
