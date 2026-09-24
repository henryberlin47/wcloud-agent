import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';

// ============================================================
//  certcheck.js — validate a user-supplied certificate + key
// ============================================================
// Pure, in-memory (the key never touches disk): used by the ssl op (custom mode)
// and by deploy (custom certificate at creation), so both refuse a bad pair
// BEFORE anything on the box changes. Node crypto, not openssl: identical on
// every OpenSSL/LibreSSL build, and the public-key compare covers RSA/EC/Ed25519.
// checkHost() does RFC 6125 SAN matching (incl. single-label wildcards).
//
// Throws Error(user-facing message) when unusable; returns { warnings, validTo }.
export function checkCustomCert(domain, cert, key, { www = false } = {}) {
  let x509;
  try {
    x509 = new X509Certificate(cert);
  } catch {
    throw new Error('That does not look like a valid certificate. Use the full-chain certificate in PEM format (it starts with "-----BEGIN CERTIFICATE-----"). Nothing was changed.');
  }
  let pub;
  try {
    pub = createPublicKey(createPrivateKey(key));
  } catch {
    throw new Error('That does not look like a valid private key. Use the key in PEM format (it starts with "-----BEGIN PRIVATE KEY-----"); password-protected keys are not supported. Nothing was changed.');
  }
  const der = (k) => k.export({ type: 'spki', format: 'der' });
  if (!der(x509.publicKey).equals(der(pub))) {
    throw new Error('The certificate and private key do not belong together. Re-copy both from your certificate provider. Nothing was changed.');
  }
  if (!x509.checkHost(domain)) {
    throw new Error(`This certificate is not valid for ${domain} — it was issued for a different domain. Nothing was changed.`);
  }
  const now = Date.now();
  if (Date.parse(x509.validTo) < now) {
    throw new Error(`This certificate expired on ${new Date(x509.validTo).toDateString()}. Get a renewed one from your provider. Nothing was changed.`);
  }
  if (Date.parse(x509.validFrom) > now) {
    throw new Error(`This certificate isn't valid until ${new Date(x509.validFrom).toDateString()}. Nothing was changed.`);
  }

  const warnings = [];
  if (www && !x509.checkHost(`www.${domain}`)) {
    warnings.push(`This certificate does not cover www.${domain}, so that address will show a security warning over HTTPS.`);
  }
  if (x509.subject === x509.issuer) {
    warnings.push('This certificate is self-signed — browsers will show a warning. Fine for testing, not for visitors.');
  }
  return { warnings, validTo: x509.validTo };
}
