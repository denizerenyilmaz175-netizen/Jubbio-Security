import { generateKeyPairSync, sign, createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';
import { encryptChunk, decryptChunk } from '../client/media.mjs';

const port = 18080 + Math.floor(Math.random() * 3000); const data = await mkdtemp(join(tmpdir(), 'jubbio-e2e-'));
const child = spawn(process.execPath, ['server/src/server.mjs'], { cwd: new URL('..', import.meta.url).pathname, env: { ...process.env, PORT: String(port), DATA_DIR: data, INVITE_CODE: 'test-invite' }, stdio: ['ignore', 'pipe', 'pipe'] });
child.stderr.on('data', b => process.stderr.write(b)); await wait(300);
const base = `http://127.0.0.1:${port}`;
function client(id) { const keys = generateKeyPairSync('ed25519'); return { id, keys, pub: keys.publicKey.export({ type: 'spki', format: 'pem' }) }; }
const alice = client('alice@local'); const bob = client('bob@local');
async function req(method, path, c, body = Buffer.alloc(0), extra = {}, signedBody = body) {
  const ts = String(Date.now()); const nonce = randomBytes(18).toString('base64url'); const bh = createHash('sha256').update(signedBody).digest('hex'); const canonical = `${method}\n${path}\n${ts}\n${nonce}\n${bh}`;
  const headers = { 'x-device-id': c.id, 'x-timestamp': ts, 'x-nonce': nonce, 'x-signature': sign(null, Buffer.from(canonical), c.keys.privateKey).toString('base64'), ...extra };
  const r = await fetch(base + path, { method, headers, body: body.length ? body : undefined }); const bytes = Buffer.from(await r.arrayBuffer()); const text = bytes.toString('utf8'); return { r, bytes, text, json: () => JSON.parse(text) };
}
try {
  for (const c of [alice, bob]) { const r = await fetch(base + '/v1/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ deviceId: c.id, publicKeyPem: c.pub, inviteCode: 'test-invite' }) }); if (r.status !== 201) throw new Error('register failed'); }
  const envelope = Buffer.from('opaque-libsignal-ciphertext-v1').toString('base64'); const rb = await req('POST', '/v1/relay', alice, Buffer.from(JSON.stringify({ recipient: bob.id, envelopeB64: envelope }), 'utf8'), { 'content-type': 'application/json' }); if (rb.r.status !== 202) throw new Error('relay failed');
  const inbox = await req('GET', `/v1/inbox/${bob.id}`, bob); if (inbox.r.status !== 200 || inbox.json().messages[0].envelopeB64 !== envelope) throw new Error('inbox failed');
  const replay = await req('POST', '/v1/relay', alice, Buffer.from(JSON.stringify({ recipient: bob.id, envelopeB64: envelope }), 'utf8'), { 'content-type': 'application/json' }); if (replay.r.status !== 202) throw new Error('replay transport test setup failed');
  const original = Buffer.from(JSON.stringify({ recipient: bob.id, envelopeB64: envelope }), 'utf8'); const altered = Buffer.from(JSON.stringify({ recipient: bob.id, envelopeB64: Buffer.from('altered').toString('base64') }), 'utf8'); const tampered = await req('POST', '/v1/relay', alice, altered, { 'content-type': 'application/json' }, original); if (tampered.r.status !== 401) throw new Error('tampered signature accepted');
  const fileKey = randomBytes(32); const fileId = 'test-file'; const plain = Buffer.from('secret encrypted media'); const part = encryptChunk(fileId, 0, 1, plain, fileKey);
  const init = await req('POST', '/v1/media/' + fileId, alice, Buffer.from(JSON.stringify({ chunkCount: 1, size: Buffer.from(part.ciphertext, 'base64').length, contentType: 'application/octet-stream' })), { 'content-type': 'application/json' }); if (init.r.status !== 201) throw new Error('media init failed');
  const rawPart = Buffer.from(part.ciphertext, 'base64'); const put = await req('PUT', `/v1/media/${init.json().mediaId}/chunks/0`, alice, rawPart, { 'x-chunk-count': '1', 'x-chunk-sha256': createHash('sha256').update(rawPart).digest('hex') }); if (put.r.status !== 201) throw new Error('media upload failed');
  const get = await req('GET', `/v1/media/${init.json().mediaId}/chunks/0`, alice); const downloaded = get.bytes; const recovered = decryptChunk(fileId, { ...part, ciphertext: downloaded.toString('base64') }, fileKey); if (!recovered.equals(plain)) throw new Error('media decrypt failed');
  console.log('PASS: register, signed relay, bad-signature rejection, inbox, encrypted media chunk round-trip');
} finally { child.kill('SIGTERM'); await rm(data, { recursive: true, force: true }); }
