import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export const CHUNK_SIZE = 1024 * 1024;
const ALGORITHM = 'aes-256-gcm';

function aad(fileId, index, total, plainLength) { return Buffer.from(`jubbio-media-v1\0${fileId}\0${index}\0${total}\0${plainLength}`); }

export function encryptChunk(fileId, index, total, plaintext, key) {
  if (!Buffer.isBuffer(plaintext) || key.length !== 32) throw new Error('invalid media input');
  const nonce = randomBytes(12); const cipher = createCipheriv(ALGORITHM, key, nonce);
  cipher.setAAD(aad(fileId, index, total, plaintext.length));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { index, total, plainLength: plaintext.length, nonce: nonce.toString('base64url'), ciphertext: Buffer.concat([ciphertext, cipher.getAuthTag()]).toString('base64') };
}

export function decryptChunk(fileId, part, key) {
  if (key.length !== 32 || part.index < 0 || part.index >= part.total) throw new Error('invalid media part');
  const raw = Buffer.from(part.ciphertext, 'base64'); if (raw.length < 16) throw new Error('truncated media part');
  const nonce = Buffer.from(part.nonce, 'base64url'); if (nonce.length !== 12) throw new Error('invalid nonce');
  const cipherText = raw.subarray(0, -16); const tag = raw.subarray(-16); const decipher = createDecipheriv(ALGORITHM, key, nonce);
  decipher.setAAD(aad(fileId, part.index, part.total, part.plainLength)); decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(cipherText), decipher.final()]);
  if (plaintext.length !== part.plainLength) throw new Error('length mismatch'); return plaintext;
}
