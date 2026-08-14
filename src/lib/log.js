// ============================================================
//  log.js — job-log formatting shared by every operation
// ============================================================
// Mirrors the shell scripts' output: numbered sections with indented
// level-prefixed lines underneath. Commands stay silent unless they fail
// (see run() in sys.js), so a healthy run reads as a short checklist.
//
//   ➜ 1. Create WordPress site
//        ✓ Created example.com
//   ➜ 2. Issue SSL certificate
//        ✓ SSL issued
// ============================================================

/**
 * @param {object} helpers            { log, err } from the job runner
 * @param {object} [opts]
 *   nested=true → this operation is running inside another one. Its "steps"
 *                 become indented detail lines so the parent's numbering stays
 *                 continuous.
 */
export function logger(helpers, { nested = false } = {}) {
  let n = 0;
  return {
    /** Start a new numbered section. */
    step: (label) => {
      if (nested) return helpers.log(`     • ${label}`);
      helpers.log('');
      helpers.log(`➜ ${++n}. ${label}`);
    },
    /** A section that was deliberately not run. */
    skip: (label) => {
      if (nested) return helpers.log(`     • ${label} — skipped`);
      helpers.log('');
      helpers.log(`➜ ${++n}. ${label} — skipped`);
    },
    info: (m) => helpers.log(`     • ${m}`),
    ok: (m) => helpers.log(`     ✓ ${m}`),
    warn: (m) => helpers.log(`     ⚠ ${m}`),
    err: (m) => helpers.err(`     ✗ ${m}`),
    /** Final summary — unindented on its own, indented when nested. */
    log: (m) => helpers.log(nested ? `     • ${m}` : `\n${m}`),
  };
}
