import { createHash, verify, timingSafeEqual } from 'node:crypto';

export const MAX_BODY = 16 * 1024 * 1024;
export const MAX_ENVELOPE = 512 * 1024;

export function bodyHash(body) {
  return createHash('sha256').update(body).digest('hex');
}

export function signingString(method, path, timestamp, nonce, body) {
  return `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyHash(body)}`;
}

export function verifyRequest({ publicKeyPem, signatureB64, method, path, timestamp, nonce, body, now = Date.now() }) {
  if (!publicKeyPem || !signatureB64 || !timestamp || !nonce) return false;
  const time = Number(timestamp);
  if (!Number.isSafeInteger(time) || Math.abs(now - time) > 5 * 60 * 1000) return false;
  const message = Buffer.from(signingString(method, path, timestamp, nonce, body));
  try { return verify(null, message, publicKeyPem, Buffer.from(signatureB64, 'base64')); } catch { return false; }
}

export function constantTimeStringEqual(a, b) {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

export function validateOpaqueEnvelope(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ENVELOPE * 2) throw new Error('invalid envelope');
  const data = Buffer.from(value, 'base64');
  if (data.length === 0 || data.length > MAX_ENVELOPE) throw new Error('invalid envelope');
  return data;
}

export function validateNonce(nonce) {
  return typeof nonce === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(nonce);
}
