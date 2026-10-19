import { mkdir, readFile, rename, writeFile, appendFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';

export class Store {
  constructor(root) { this.root = root; this.statePath = join(root, 'state.json'); this.state = { devices: {}, messages: [], media: {}, federation: [] }; }
  async init() {
    await mkdir(this.root, { recursive: true });
    try { this.state = JSON.parse(await readFile(this.statePath, 'utf8')); } catch { await this.flush(); }
    await mkdir(join(this.root, 'media'), { recursive: true });
  }
  async flush() {
    const tmp = `${this.statePath}.tmp`;
    await writeFile(tmp, JSON.stringify(this.state), { mode: 0o600 });
    await rename(tmp, this.statePath);
  }
  async registerDevice(deviceId, publicKeyPem) {
    this.state.devices[deviceId] = { publicKeyPem, createdAt: Date.now() }; await this.flush();
  }
  device(deviceId) { return this.state.devices[deviceId]; }
  async enqueueMessage(recipient, sender, envelopeB64, expiresAt) {
    const item = { id: randomUUID(), recipient, sender, envelopeB64, createdAt: Date.now(), expiresAt, deliveredAt: null };
    this.state.messages.push(item); await this.flush(); return item;
  }
  async inbox(recipient) {
    const now = Date.now();
    this.state.messages = this.state.messages.filter(m => m.expiresAt > now);
    const items = this.state.messages.filter(m => m.recipient === recipient && !m.deliveredAt);
    for (const item of items) item.deliveredAt = now;
    await this.flush(); return items;
  }
  async createMedia(id, meta) { this.state.media[id] = { ...meta, id, createdAt: Date.now() }; await this.flush(); return this.state.media[id]; }
  media(id) { return this.state.media[id]; }
  async addFederationJob(job) { this.state.federation.push({ ...job, id: randomUUID(), attempts: 0, nextTryAt: Date.now() }); await this.flush(); }
  async dueFederationJobs() { return this.state.federation.filter(j => j.nextTryAt <= Date.now()); }
  async updateFederationJob(id, patch) { const j = this.state.federation.find(x => x.id === id); if (j) Object.assign(j, patch); await this.flush(); }
  async completeFederationJob(id) { this.state.federation = this.state.federation.filter(x => x.id !== id); await this.flush(); }
  async purgeExpired() { const now = Date.now(); this.state.messages = this.state.messages.filter(x => x.expiresAt > now); for (const [id, m] of Object.entries(this.state.media)) if (m.expiresAt <= now) delete this.state.media[id]; await this.flush(); }
}
