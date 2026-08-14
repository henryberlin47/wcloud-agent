// ============================================================
//  credentials.js — in-memory store for post-deploy site credentials
// ============================================================
// deploy.js writes here right after provisioning; server.js's
// /api/sites/:domain/credentials route reads from here. Kept in its own
// module (not inside deploy.js) so both can import the same Map instead of
// each holding a disconnected copy.
//
// Not persisted: an agent restart forgets it, same tradeoff as jobs.js.
// ============================================================

const store = new Map();
const TTL_MS = 60 * 60 * 1000; // 1h

export function setCredentials(domain, creds) {
  store.set(domain, { ...creds, timestamp: Date.now() });
}

// Returns null if never captured or past TTL (and evicts it in that case).
export function getCredentials(domain) {
  const entry = store.get(domain);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > TTL_MS) {
    store.delete(domain);
    return null;
  }
  return entry;
}

setInterval(() => {
  const now = Date.now();
  for (const [domain, entry] of store) {
    if (now - entry.timestamp > TTL_MS) store.delete(domain);
  }
}, 5 * 60 * 1000).unref?.();
