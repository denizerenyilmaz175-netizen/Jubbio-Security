import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditChain, RiskEngine } from '../server/src/security-controls.mjs';
import { sealSecret, openSecret } from '../client/key-vault.mjs';

const dir = await mkdtemp(join(tmpdir(), 'jubbio-security-')); try {
  const risk = new RiskEngine(); if (risk.score('ip:test', 95) !== 'lock' || !risk.isBlocked('ip:test')) throw new Error('risk policy failed');
  const auditPath = join(dir, 'events.log'); const audit = new AuditChain(auditPath); await audit.init(); await audit.record('test_event', { ip: '127.0.0.1', actor: 'test', score: 1 }); await audit.record('test_event_2', { ip: '127.0.0.1', actor: 'test', score: 2 }); const lines = (await readFile(auditPath, 'utf8')).trim().split('\n').map(JSON.parse); if (lines.length !== 2 || lines[1].previous !== lines[0].hash) throw new Error('audit chain failed');
  const sealed = await sealSecret(Buffer.from('private-key-material'), 'correct horse battery staple'); const opened = await openSecret(sealed, 'correct horse battery staple'); if (opened.toString() !== 'private-key-material') throw new Error('vault round-trip failed'); opened.fill(0); let rejected = false; try { await openSecret(sealed, 'wrong'); } catch { rejected = true; } if (!rejected) throw new Error('wrong password accepted');
  console.log('PASS: risk escalation, hash-chain audit, password vault and wrong-password rejection');
} finally { await rm(dir, { recursive: true, force: true }); }
