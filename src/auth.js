import crypto from 'node:crypto';
import config from './config.js';

// Constant-time string compare to avoid timing attacks on the token.
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) {
    // Still do a compare to keep timing roughly constant, then fail.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

// Resolve the client IP, honouring X-Forwarded-For only when explicitly trusted.
export function clientIp(req) {
  if (config.trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
  }
  // req.socket.remoteAddress may be IPv6-mapped IPv4 (::ffff:1.2.3.4)
  let ip = req.socket?.remoteAddress || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

function ipAllowed(ip) {
  if (config.allowedIps.length === 0) return true; // no allowlist configured
  return config.allowedIps.includes(ip);
}

// Express middleware: enforces IP allowlist first, then bearer token.
export function requireAuth(req, res, next) {
  const ip = clientIp(req);

  if (!ipAllowed(ip)) {
    // Log + echo the source IP so a mismatched allowlist is diagnosable (the
    // caller already knows its own IP, so echoing it leaks nothing). Don't reveal
    // whether the token would have been valid.
    console.warn(`[agent] 403 ip_not_allowed from ${ip} (allowlist: ${config.allowedIps.join(',') || 'none'})`);
    return res.status(403).json({ error: 'forbidden', reason: 'ip_not_allowed', seen_ip: ip });
  }

  const hdr = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(hdr);
  if (!m) {
    return res.status(401).json({ error: 'unauthorized', reason: 'missing_bearer' });
  }
  if (!safeEqual(m[1], config.authToken)) {
    return res.status(401).json({ error: 'unauthorized', reason: 'bad_token' });
  }

  req.clientIp = ip;
  next();
}