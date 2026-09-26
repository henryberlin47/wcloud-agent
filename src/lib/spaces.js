// DigitalOcean Spaces (S3) transfer via the AWS SDK. Creds are passed per call
// from the authenticated request body, live only in the client object for that
// one transfer, and are never written to disk or logged. Kept provider-agnostic
// (plain S3 params); only DigitalOcean is offered in the portal UI today.
//
// Replaces a shelled-out `rclone`: no external binary, no runtime self-install
// (which fetched and ran a remote script as root), no config-file/env-name
// coupling. lib-storage's Upload does multipart automatically, so archives
// larger than S3's 5GB single-PUT limit still work.
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { S3Client, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command, PutObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';

// Spaces endpoints are regional hosts ("nyc3.digitaloceanspaces.com"). The SDK
// wants a URL; the portal sends a bare host, so tolerate either.
const toUrl = (endpoint) => (/^https?:\/\//i.test(endpoint) ? endpoint : `https://${endpoint}`);

// Region is baked into the endpoint for Spaces, but SigV4 still needs a value
// to sign with, and it must match the endpoint's region or the signature is
// rejected — so derive it from the host rather than hardcoding "us-east-1".
const regionFromEndpoint = (endpoint) => {
  const m = String(endpoint).match(/(?:^|\/\/)([a-z0-9-]+)\.digitaloceanspaces\.com/i);
  return m ? m[1] : 'us-east-1';
};

export function s3Client({ endpoint, accessKeyId, secretAccessKey }) {
  return new S3Client({
    endpoint: toUrl(endpoint),
    region: regionFromEndpoint(endpoint),
    credentials: { accessKeyId, secretAccessKey },
    // Spaces: virtual-hosted-style (<space>.<region>...). Other S3-compatible
    // stores (MinIO, …) usually want path-style.
    forcePathStyle: !/digitaloceanspaces\.com/i.test(String(endpoint)),
    maxAttempts: 5,        // transient 5xx/network retries, like rclone's
  });
}

// --- transfers ---------------------------------------------------------------
// Every call takes { space, endpoint, accessKeyId, secretAccessKey } plus a key.
// Nothing here creates the bucket: the Space is always pre-created by the user,
// and a Spaces key usually can't create one anyway.

// Stream a local file up. Upload() switches to multipart past the part size, so
// this handles archives of any size without buffering them in memory.
// `signal` is the job's AbortSignal: cancel/timeout abort the transfer instead
// of letting it hold the single job slot until it ends on its own (and
// Upload.abort() also aborts the multipart upload server-side, so no orphaned
// parts keep billing the user's Space).
export async function uploadFile(p, key, filePath, { signal } = {}) {
  signal?.throwIfAborted();
  const client = s3Client(p);
  const up = new Upload({
    client,
    params: { Bucket: p.space, Key: key, Body: createReadStream(filePath) },
    partSize: 64 * 1024 * 1024, // 64MB parts → 5GB max object needs ~80 parts
    queueSize: 3,               // modest concurrency; these boxes also serve sites
  });
  const onAbort = () => { up.abort().catch(() => {}); };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    await up.done();
  } finally {
    signal?.removeEventListener('abort', onAbort);
    client.destroy();
  }
}

// Stream an object down to a local path.
export async function downloadFile(p, key, filePath, { signal } = {}) {
  const client = s3Client(p);
  try {
    const r = await client.send(new GetObjectCommand({ Bucket: p.space, Key: key }), { abortSignal: signal });
    if (!r.Body) throw new Error('empty response body from Spaces');
    await pipeline(r.Body, createWriteStream(filePath, { mode: 0o600 }), { signal });
  } finally {
    client.destroy();
  }
}

export async function putObject(p, key, body) {
  const client = s3Client(p);
  try {
    await client.send(new PutObjectCommand({ Bucket: p.space, Key: key, Body: body }));
  } finally {
    client.destroy();
  }
}

// Does the object exist, and how big is it? The authoritative answer to "did
// that backup actually land?" when the agent job that uploaded it is gone
// (jobs are in-memory, so an agent restart loses the outcome).
export async function statObject(p, key) {
  const client = s3Client(p);
  try {
    const r = await client.send(new HeadObjectCommand({ Bucket: p.space, Key: key }));
    return { exists: true, size: r.ContentLength ?? null };
  } catch (e) {
    if (e?.name === 'NotFound' || e?.$metadata?.httpStatusCode === 404) return { exists: false, size: null };
    throw e;
  } finally {
    client.destroy();
  }
}

export async function deleteObject(p, key) {
  const client = s3Client(p);
  try {
    await client.send(new DeleteObjectCommand({ Bucket: p.space, Key: key }));
  } finally {
    client.destroy();
  }
}

// Top-level prefixes in the Space — the cheap "can we read?" probe.
export async function listTopLevel(p) {
  const client = s3Client(p);
  try {
    const r = await client.send(new ListObjectsV2Command({ Bucket: p.space, Delimiter: '/', MaxKeys: 1000 }));
    return (r.CommonPrefixes || []).map((c) => c.Prefix).filter(Boolean);
  } finally {
    client.destroy();
  }
}

// --- errors ------------------------------------------------------------------
// Turn SDK/S3 noise into something a user can act on. These cover every
// misconfiguration we've actually hit; anything else falls through to the raw
// message so nothing is hidden.
// Flatten an Error into searchable text. Connection failures arrive as an
// AggregateError whose own message is just "AggregateError" (Node tries IPv6
// and IPv4 in parallel and bundles both failures), and the SDK wraps causes —
// so the real code (ECONNREFUSED/ENOTFOUND) is only in the nested errors.
function errText(e, depth = 0) {
  if (e == null || depth > 3) return '';
  if (typeof e === 'string') return e;
  const parts = [e.name, e.Code, e.code, e.message, e.$metadata?.httpStatusCode];
  if (Array.isArray(e.errors)) parts.push(...e.errors.map((x) => errText(x, depth + 1)));
  if (e.cause) parts.push(errText(e.cause, depth + 1));
  return parts.filter(Boolean).join(' ');
}

export function explainSpacesError(raw, { space, endpoint } = {}) {
  // Accept an Error, an SDK exception, or an already-flattened string.
  const s = errText(raw);
  const where = `${space || 'the Space'} at ${endpoint || 'the configured endpoint'}`;
  if (/InvalidAccessKeyId/i.test(s)) {
    return `Access key not recognized — check the Spaces access key (it is not the same as a DigitalOcean API token).`;
  }
  if (/SignatureDoesNotMatch/i.test(s)) {
    return `Secret key does not match the access key — re-enter the Spaces secret.`;
  }
  if (/NoSuchBucket|bucket does not exist|specified bucket does not exist/i.test(s)) {
    return `Space not found: ${where}. Check the Space name, and that its region matches the region selected here.`;
  }
  if (/NoSuchKey|NotFound/i.test(s)) {
    return `That backup object no longer exists in ${space || 'the Space'}.`;
  }
  if (/AccessDenied|\b403\b/i.test(s)) {
    return `Access denied on ${where}. Usually one of: the Space is in a different region than the one selected here, or the key is scoped to a different Space / lacks write permission.`;
  }
  if (/ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ETIMEDOUT|getaddrinfo|socket hang up/i.test(s)) {
    return `Could not reach ${endpoint || 'the endpoint'} — check the region setting and the server's network access.`;
  }
  return String(s).trim().slice(-300) || 'unknown Spaces error';
}
