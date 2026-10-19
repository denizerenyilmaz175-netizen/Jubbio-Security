import http from 'node:http';
import { createHash, createPublicKey, randomUUID, sign } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { WebSocketServer } from 'ws';
import { Store } from './store.mjs';
import { MAX_BODY, validateNonce, validateOpaqueEnvelope, verifyRequest } from './crypto.mjs';

const PORT = Number(process.env.PORT || 8080);
const DATA_DIR = process.env.DATA_DIR || '/data';
const INVITE_CODE = process.env.INVITE_CODE || '';
const MESSAGE_TTL_MS = Number(process.env.MESSAGE_TTL_MS || 7 * 24 * 3600 * 1000);
const MEDIA_TTL_MS = Number(process.env.MEDIA_TTL_MS || 7 * 24 * 3600 * 1000);
const SERVER_ID = process.env.SERVER_ID || 'local';
const PEERS = JSON.parse(process.env.FEDERATION_PEERS_JSON || '{}');
const seenNonces = new Map();
const store = new Store(DATA_DIR);
const sockets = new Map();
const buckets = new Map();

function json(res, status, value) { const b = Buffer.from(JSON.stringify(value)); res.writeHead(status, { 'content-type': 'application/json', 'content-length': b.length, 'x-content-type-options': 'nosniff', 'cache-control': 'no-store' }); res.end(b); }
function fail(res, status = 400) { json(res, status, { error: 'request_rejected' }); }
function headers(res) { res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains'); res.setHeader('x-frame-options', 'DENY'); res.setHeader('referrer-policy', 'no-referrer'); }
async function body(req, limit = MAX_BODY) { const chunks = []; let total = 0; for await (const c of req) { total += c.length; if (total > limit) throw new Error('body_limit'); chunks.push(c); } return Buffer.concat(chunks); }
async function jsonBody(req) { const b = await body(req, 2 * 1024 * 1024); return JSON.parse(b.toString('utf8')); }
function rateLimit(key, max = 120) { const now = Date.now(); const x = buckets.get(key) || { at: now, count: 0 }; if (now - x.at > 60_000) { x.at = now; x.count = 0; } x.count++; buckets.set(key, x); return x.count <= max; }
function auth(req, raw, deviceId) {
  const d = store.device(deviceId); if (!d || !validateNonce(req.headers['x-nonce'])) return false;
  const nonceKey = `device:${deviceId}:${req.headers['x-nonce']}`; if (seenNonces.has(nonceKey)) return false;
  const valid = verifyRequest({ publicKeyPem: d.publicKeyPem, signatureB64: req.headers['x-signature'], method: req.method, path: new URL(req.url, 'http://localhost').pathname, timestamp: req.headers['x-timestamp'], nonce: req.headers['x-nonce'], body: raw });
  if (valid) seenNonces.set(nonceKey, Date.now() + 5 * 60 * 1000); return valid;
}
function peerAuth(req, raw) {
  const peerId = String(req.headers['x-peer-id'] || ''); const peer = PEERS[peerId]; if (!peer || !validateNonce(req.headers['x-nonce'])) return false;
  const nonceKey = `peer:${peerId}:${req.headers['x-nonce']}`; if (seenNonces.has(nonceKey)) return false;
  const valid = verifyRequest({ publicKeyPem: peer.publicKeyPem, signatureB64: req.headers['x-signature'], method: req.method, path: new URL(req.url, 'http://localhost').pathname, timestamp: req.headers['x-timestamp'], nonce: req.headers['x-nonce'], body: raw });
  if (valid) seenNonces.set(nonceKey, Date.now() + 5 * 60 * 1000); return valid;
}
function notify(deviceId, item) { const set = sockets.get(deviceId); if (!set) return; for (const ws of set) if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'message_available', id: item.id })); }
async function mediaChunk(req, id, index, raw) {
  const hash = createHash('sha256').update(raw).digest('hex');
  if (hash !== req.headers['x-chunk-sha256']) throw new Error('chunk_hash');
  const meta = store.media(id); if (!meta) throw new Error('media_missing');
  const count = Number(req.headers['x-chunk-count']); if (!Number.isInteger(count) || count !== meta.chunkCount || index < 0 || index >= count) throw new Error('chunk_index');
  await writeFile(join(DATA_DIR, 'media', `${id}.${index}`), raw, { flag: 'wx', mode: 0o600 });
}

const server = http.createServer(async (req, res) => {
  headers(res);
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (!rateLimit(`${req.socket.remoteAddress}:${req.method}:${url.pathname}`)) return fail(res, 429);
    if (req.method === 'GET' && url.pathname === '/v1/health') return json(res, 200, { ok: true, e2ee: 'opaque-relay' });

    if (req.method === 'POST' && url.pathname === '/v1/register') {
      const p = await jsonBody(req);
      if (!INVITE_CODE || p.inviteCode !== INVITE_CODE || typeof p.deviceId !== 'string' || typeof p.publicKeyPem !== 'string') return fail(res, 400);
      try { createPublicKey(p.publicKeyPem); } catch { return fail(res, 400); }
      await store.registerDevice(p.deviceId, p.publicKeyPem); return json(res, 201, { ok: true, deviceId: p.deviceId });
    }

    const match = url.pathname.match(/^\/v1\/inbox\/([^/]+)$/);
    if (req.method === 'GET' && match) {
      const raw = Buffer.alloc(0); if (!auth(req, raw, match[1])) return fail(res, 401);
      return json(res, 200, { messages: await store.inbox(match[1]) });
    }

    if (req.method === 'POST' && url.pathname === '/v1/relay') {
      const raw = await body(req, 2 * 1024 * 1024); const sender = String(req.headers['x-device-id'] || '');
      if (!auth(req, raw, sender)) return fail(res, 401);
      const p = JSON.parse(raw.toString('utf8')); validateOpaqueEnvelope(p.envelopeB64);
      if (typeof p.recipient !== 'string' || p.recipient.length > 256) return fail(res, 400);
      const recipientDomain = p.recipient.includes('@') ? p.recipient.split('@')[1].split('/')[0] : SERVER_ID;
      if (recipientDomain !== SERVER_ID && PEERS[recipientDomain]) {
        await store.addFederationJob({ peerId: recipientDomain, recipient: p.recipient, envelopeB64: p.envelopeB64 });
        return json(res, 202, { accepted: true, federated: true });
      }
      const item = await store.enqueueMessage(p.recipient, sender, p.envelopeB64, Date.now() + MESSAGE_TTL_MS); notify(p.recipient, item);
      return json(res, 202, { accepted: true, id: item.id });
    }

    if (req.method === 'POST' && url.pathname === '/v1/federation/relay') {
      const raw = await body(req, 2 * 1024 * 1024); if (!peerAuth(req, raw)) return fail(res, 401);
      const p = JSON.parse(raw.toString('utf8')); validateOpaqueEnvelope(p.envelopeB64);
      if (typeof p.recipient !== 'string' || !p.recipient.includes('@')) return fail(res, 400);
      const item = await store.enqueueMessage(p.recipient, `federation:${req.headers['x-peer-id']}`, p.envelopeB64, Date.now() + MESSAGE_TTL_MS); notify(p.recipient, item);
      return json(res, 202, { accepted: true });
    }

    const mediaInit = url.pathname.match(/^\/v1\/media\/([A-Za-z0-9_-]+)$/);
    if (req.method === 'POST' && mediaInit) {
      const raw = await body(req, 64 * 1024); const owner = String(req.headers['x-device-id'] || ''); if (!auth(req, raw, owner)) return fail(res, 401);
      const p = JSON.parse(raw.toString('utf8')); const chunkCount = Number(p.chunkCount); const size = Number(p.size);
      if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > 10000 || !Number.isSafeInteger(size) || size < 1 || size > 2 * 1024 * 1024 * 1024) return fail(res, 400);
      const id = randomUUID().replaceAll('-', ''); await store.createMedia(id, { owner, chunkCount, size, contentType: String(p.contentType || 'application/octet-stream'), expiresAt: Date.now() + MEDIA_TTL_MS });
      return json(res, 201, { mediaId: id, expiresAt: Date.now() + MEDIA_TTL_MS });
    }
    const chunkMatch = url.pathname.match(/^\/v1\/media\/([A-Za-z0-9_-]+)\/chunks\/(\d+)$/);
    if (req.method === 'PUT' && chunkMatch) {
      const raw = await body(req, 8 * 1024 * 1024); const owner = String(req.headers['x-device-id'] || ''); if (!auth(req, raw, owner)) return fail(res, 401);
      if (store.media(chunkMatch[1])?.owner !== owner) return fail(res, 403); await mediaChunk(req, chunkMatch[1], Number(chunkMatch[2]), raw); return json(res, 201, { accepted: true });
    }
    const mediaGet = url.pathname.match(/^\/v1\/media\/([A-Za-z0-9_-]+)\/chunks\/(\d+)$/);
    if (req.method === 'GET' && mediaGet) {
      const raw = Buffer.alloc(0); const requester = String(req.headers['x-device-id'] || ''); if (!auth(req, raw, requester)) return fail(res, 401);
      const meta = store.media(mediaGet[1]); if (!meta) return fail(res, 404); const part = await readFile(join(DATA_DIR, 'media', `${mediaGet[1]}.${Number(mediaGet[2])}`)); res.writeHead(200, { 'content-type': 'application/octet-stream', 'cache-control': 'no-store' }); return res.end(part);
    }
    return fail(res, 404);
  } catch (e) { return fail(res, e.message === 'body_limit' ? 413 : 400); }
});

const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost'); if (url.pathname !== '/v1/ws') return socket.destroy();
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws));
});
wss.on('connection', ws => {
  let deviceId = null;
  ws.once('message', raw => { try { const p = JSON.parse(raw); if (p.type !== 'auth' || !store.device(p.deviceId)) return ws.close(1008); deviceId = p.deviceId; if (!sockets.has(deviceId)) sockets.set(deviceId, new Set()); sockets.get(deviceId).add(ws); ws.send(JSON.stringify({ type: 'ready' })); } catch { ws.close(1008); } });
  ws.on('close', () => { if (deviceId && sockets.has(deviceId)) sockets.get(deviceId).delete(ws); });
});

await store.init();
setInterval(() => store.purgeExpired().catch(() => {}), 60_000).unref();
const federationPrivateKey = process.env.FEDERATION_PRIVATE_KEY_PEM || (process.env.FEDERATION_PRIVATE_KEY_PATH ? await readFile(process.env.FEDERATION_PRIVATE_KEY_PATH, 'utf8') : null);
async function federationTick() {
  if (!federationPrivateKey) return;
  for (const job of await store.dueFederationJobs()) {
    const peer = PEERS[job.peerId]; if (!peer?.url) continue;
    const path = '/v1/federation/relay'; const payload = Buffer.from(JSON.stringify({ recipient: job.recipient, envelopeB64: job.envelopeB64 }));
    const timestamp = String(Date.now()); const nonce = randomUUID().replaceAll('-', ''); const canonical = `${'POST'}\n${path}\n${timestamp}\n${nonce}\n${createHash('sha256').update(payload).digest('hex')}`;
    try {
      const response = await fetch(`${peer.url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-peer-id': SERVER_ID, 'x-timestamp': timestamp, 'x-nonce': nonce, 'x-signature': sign(null, Buffer.from(canonical), federationPrivateKey).toString('base64') }, body: payload });
      if (response.ok) await store.completeFederationJob(job.id); else throw new Error('peer rejected');
    } catch { await store.updateFederationJob(job.id, { attempts: job.attempts + 1, nextTryAt: Date.now() + Math.min(3_600_000, 1000 * 2 ** Math.min(job.attempts, 12)) }); }
  }
}
setInterval(() => federationTick().catch(() => {}), 5000).unref();
setInterval(() => { const now = Date.now(); for (const [key, expires] of seenNonces) if (expires < now) seenNonces.delete(key); }, 60_000).unref();
server.listen(PORT, '0.0.0.0', () => console.log(`Jubbio Security relay listening on ${PORT}`));
