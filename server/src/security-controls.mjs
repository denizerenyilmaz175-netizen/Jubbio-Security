import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';

const DECAY_MS = 10 * 60 * 1000;
const RETENTION_MS = 30 * 24 * 3600 * 1000;

export class RiskEngine {
  constructor() { this.items = new Map(); }
  score(key, delta, now = Date.now()) {
    const old = this.items.get(key) || { score: 0, at: now, lockedUntil: 0 };
    const elapsed = Math.max(0, now - old.at); const decayed = old.score * Math.pow(0.5, elapsed / DECAY_MS);
    const score = Math.max(0, Math.min(100, decayed + delta));
    const lockedUntil = score >= 90 ? now + 30 * 60 * 1000 : old.lockedUntil;
    const value = { score, at: now, lockedUntil }; this.items.set(key, value); return this.action(value, now);
  }
  action(value, now = Date.now()) {
    if (value.lockedUntil > now || value.score >= 90) return 'lock';
    if (value.score >= 60) return 'challenge';
    if (value.score >= 30) return 'slow';
    return 'allow';
  }
  isBlocked(key, now = Date.now()) { const v = this.items.get(key); return Boolean(v && this.action(v, now) === 'lock'); }
  get(key) { return this.items.get(key) || { score: 0, lockedUntil: 0 }; }
}

export class AuditChain {
  constructor(path) { this.path = path; this.previous = '0'.repeat(64); }
  async init() {
    await mkdir(dirname(this.path), { recursive: true });
    try { const lines = (await readFile(this.path, 'utf8')).trim().split('\n').filter(Boolean); if (lines.length) this.previous = JSON.parse(lines.at(-1)).hash; } catch {}
  }
  async record(type, fields = {}) {
    const safe = { type, at: new Date().toISOString(), ip: fields.ip || 'redacted', actor: fields.actor || 'redacted', score: Number(fields.score || 0) };
    const payload = JSON.stringify({ previous: this.previous, event: safe }); const hash = createHash('sha256').update(payload).digest('hex');
    await appendFile(this.path, JSON.stringify({ ...safe, previous: this.previous, hash }) + '\n', { mode: 0o600 }); this.previous = hash;
  }
  static retentionMs() { return RETENTION_MS; }
}

export function securityAction(risk, key, delta) { return risk.score(key, delta); }
