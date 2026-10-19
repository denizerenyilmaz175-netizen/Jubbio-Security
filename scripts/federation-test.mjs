import { generateKeyPairSync, sign, createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';

const root = new URL('..', import.meta.url).pathname; const aPort = 19080 + Math.floor(Math.random() * 1000); const bPort = aPort + 1; const aData = await mkdtemp(join(tmpdir(), 'jubbio-a-')); const bData = await mkdtemp(join(tmpdir(), 'jubbio-b-'));
const sa = generateKeyPairSync('ed25519'); const sb = generateKeyPairSync('ed25519');
const pem = k => k.publicKey.export({ type: 'spki', format: 'pem' }); const privatePem = k => k.privateKey.export({ type: 'pkcs8', format: 'pem' });
const peer = (url, key) => JSON.stringify({ b: { url: `http://127.0.0.1:${bPort}`, publicKeyPem: pem(sb) }, a: { url: `http://127.0.0.1:${aPort}`, publicKeyPem: pem(sa) } });
function start(id, port, data, key, peers) { return spawn(process.execPath, ['server/src/server.mjs'], { cwd: root, env: { ...process.env, SERVER_ID: id, PORT: String(port), DATA_DIR: data, INVITE_CODE: 'test-invite', FEDERATION_PRIVATE_KEY_PEM: privatePem(key), FEDERATION_PEERS_JSON: peers }, stdio: ['ignore', 'ignore', 'pipe'] }); }
const pA = start('a', aPort, aData, sa, peer('a', sb)); const pB = start('b', bPort, bData, sb, peer('b', sa));
function device(id) { const keys = generateKeyPairSync('ed25519'); return { id, keys, publicKeyPem: pem(keys) }; }
async function register(base, d) { const r = await fetch(base + '/v1/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ deviceId: d.id, publicKeyPem: d.publicKeyPem, inviteCode: 'test-invite' }) }); if (r.status !== 201) throw new Error('register'); }
async function call(base, method, path, d, payload) { const body = payload === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(payload)); const ts = String(Date.now()); const nonce = randomBytes(18).toString('base64url'); const canonical = `${method}\n${path}\n${ts}\n${nonce}\n${createHash('sha256').update(body).digest('hex')}`; const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-device-id': d.id, 'x-timestamp': ts, 'x-nonce': nonce, 'x-signature': sign(null, Buffer.from(canonical), d.keys.privateKey).toString('base64') }, body: body.length ? body : undefined }); return { r, data: await r.json() }; }
try {
  await wait(350); const A = `http://127.0.0.1:${aPort}`; const B = `http://127.0.0.1:${bPort}`; const alice = device('alice@a'); const carol = device('carol@a'); const bob = device('bob@b');
  await register(A, alice); await register(A, carol); await register(B, bob);
  const envelope = Buffer.from('opaque-cross-server-envelope').toString('base64'); const sent = await call(A, 'POST', '/v1/relay', alice, { recipient: bob.id, envelopeB64: envelope }); if (sent.r.status !== 202 || !sent.data.federated) throw new Error('not queued for federation');
  await wait(5500); const inbox = await call(B, 'GET', `/v1/inbox/${bob.id}`, bob, undefined); if (inbox.r.status !== 200 || inbox.data.messages[0]?.envelopeB64 !== envelope) throw new Error('federation delivery failed');
  console.log('PASS: two servers, three users, pinned peer signing, opaque cross-server delivery');
} finally { pA.kill('SIGTERM'); pB.kill('SIGTERM'); await rm(aData, { recursive: true, force: true }); await rm(bData, { recursive: true, force: true }); }
