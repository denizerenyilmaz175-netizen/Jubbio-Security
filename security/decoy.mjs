import http from 'node:http';
import { appendFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const port = Number(process.env.DECOY_PORT || 9090); const path = process.env.DECOY_AUDIT || '/decoy-data/events.log';
await mkdir('/decoy-data', { recursive: true });
function event(req) { const ip = String(req.socket.remoteAddress || 'redacted'); const record = { at: new Date().toISOString(), type: 'decoy_access', method: req.method, path: req.url?.slice(0, 256), ipHash: createHash('sha256').update(ip).digest('hex') }; return appendFile(path, JSON.stringify(record) + '\n', { mode: 0o600 }); }
http.createServer(async (req, res) => { await event(req).catch(() => {}); res.writeHead(404, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end('{"error":"not_found"}'); }).listen(port, '0.0.0.0', () => console.log(`isolated decoy listening on ${port}`));
