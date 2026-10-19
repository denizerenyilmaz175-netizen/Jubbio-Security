import { createCipheriv, createDecipheriv, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(scrypt);
const AAD = Buffer.from('jubbio-key-vault-v1');

export async function sealSecret(secret, password) {
  const plain = Buffer.from(secret); const pass = Buffer.from(password); const salt = randomBytes(16); const nonce = randomBytes(12);
  try {
    const key = await derive(pass, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
    try { const cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(AAD); const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]); return { version: 1, kdf: 'scrypt', salt: salt.toString('base64'), nonce: nonce.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') }; } finally { key.fill(0); }
  } finally { plain.fill(0); pass.fill(0); }
}

export async function openSecret(record, password) {
  const pass = Buffer.from(password); const salt = Buffer.from(record.salt, 'base64'); const nonce = Buffer.from(record.nonce, 'base64'); const tag = Buffer.from(record.tag, 'base64'); const ciphertext = Buffer.from(record.ciphertext, 'base64');
  try {
    const key = await derive(pass, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
    try { const decipher = createDecipheriv('aes-256-gcm', key, nonce); decipher.setAAD(AAD); decipher.setAuthTag(tag); return Buffer.concat([decipher.update(ciphertext), decipher.final()]); } finally { key.fill(0); }
  } finally { pass.fill(0); salt.fill(0); nonce.fill(0); tag.fill(0); ciphertext.fill(0); }
}

export function equalSecret(a, b) { const aa = Buffer.from(a); const bb = Buffer.from(b); try { return aa.length === bb.length && timingSafeEqual(aa, bb); } finally { aa.fill(0); bb.fill(0); } }
