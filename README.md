# Jubbio Security

A self-hosted security and transport layer for Jubbio clients using Signal/libsignal-based end-to-end encryption, signed REST and WebSocket APIs, opaque relay, federation, and encrypted media transfer.

## Security boundary

The server **never creates or reads message or file plaintext**. The `envelopeB64` value received by the server must be an E2EE envelope produced by a libsignal client. Media chunks must already be encrypted on the client with an authenticated encryption scheme. This repository does not implement a homemade Signal protocol. Production clients must use a pinned and reviewed `@signalapp/libsignal-client` release or an approved native libsignal binding.

No system can honestly guarantee that data is “unbreakable” or impossible to steal. A fully compromised device can read plaintext from memory, the screen, or the keyboard. Some delivery metadata is also visible to the server.

## Included components

- `server/`: Node.js 22 REST and WebSocket opaque relay.
- `client/media.mjs`: Client-side AES-256-GCM authenticated and ordered media chunk encryption example.
- `client/key-vault.mjs`: Local password vault using scrypt and AES-256-GCM; secret buffers are cleared on a best-effort basis after use.
- `server/src/security-controls.mjs`: Time-decaying risk scoring and content-free hash-chained security audit events.
- `security/decoy.mjs`: Isolated decoy/honeypot service that is not connected to the real relay network.
- `scripts/e2e-test.mjs`: Signed relay, invalid-signature rejection, inbox, and encrypted media round-trip test.
- `scripts/federation-test.mjs`: Two-server, three-user pinned-peer federation test with opaque cross-server delivery.
- `scripts/security-controls-test.mjs`: Risk escalation, audit-chain, password-vault, and wrong-password rejection test.
- `docker-compose.yml`: One-command container deployment.
- `docs/E2EE-ARCHITECTURE.md`: Threat model, Signal/libsignal architecture, federation design, and hardening roadmap.

## One-command deployment

```bash
cp .env.example .env
# Replace INVITE_CODE with a long random value.

docker compose up -d --build
curl http://localhost:8080/v1/health
```

Production deployments must enforce TLS 1.3 through a reverse proxy or direct TLS termination. Do not expose the development HTTP listener directly to the public internet. Back up the `jubbio_data` volume using encryption; never store the backup key in plaintext on the server.

To start the isolated decoy profile:

```bash
docker compose --profile decoy up -d --build
```

The decoy service is placed on a separate Docker network and must not be connected to the real relay network. High-risk traffic should be routed by a separately managed reverse proxy/WAF policy on an isolated host or network segment.

## Local development and tests

```bash
npm --prefix server install
node scripts/e2e-test.mjs
node scripts/federation-test.mjs
node scripts/security-controls-test.mjs

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure

cargo check --manifest-path rust/libsignal_bridge/Cargo.toml
npm --prefix server audit --omit=dev --audit-level=high
```

The tests cover device public-key registration, Ed25519-signed relay requests, invalid-signature rejection, inbox delivery, AES-256-GCM media chunk round trips, two-server federation, pinned peer signing, risk escalation, hash-chain audit events, and password-vault failure handling. The test envelope named `opaque-libsignal-ciphertext-v1` is only a transport fixture; it is not a real Signal ciphertext. A production client must replace it with output from libsignal.

## API

### Device registration

`POST /v1/register` with:

```json
{
  "deviceId": "user@server/device",
  "publicKeyPem": "...",
  "inviteCode": "..."
}
```

### Signed relay

`POST /v1/relay` with:

```json
{
  "recipient": "user@server/device",
  "envelopeB64": "<libsignal ciphertext>"
}
```

Every request is signed with Ed25519 headers: `x-device-id`, `x-timestamp`, `x-nonce`, and `x-signature`. The canonical signed message is:

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(REQUEST_BODY)
```

Timestamps are accepted within a five-minute window. Nonces are single-use in a TTL cache. In a multi-instance production deployment, the cache must move to a shared atomic Redis or SQL store.

### Inbox

`GET /v1/inbox/:deviceId` returns pending opaque envelopes for that device and requires the same signed headers.

### Encrypted media

1. Call `POST /v1/media/:clientFileId` with the chunk count and total size.
2. Upload an already encrypted chunk with `PUT /v1/media/:mediaId/chunks/:index`; `x-chunk-sha256` and `x-chunk-count` are required.
3. Download the opaque blob with `GET /v1/media/:mediaId/chunks/:index`.
4. Send the file key and manifest only inside a libsignal E2EE message. The server must never receive the file key.

### WebSocket

After connecting to `GET /v1/ws`, the first message must be:

```json
{
  "type": "auth",
  "deviceId": "...",
  "timestamp": "...",
  "nonce": "...",
  "signature": "..."
}
```

The WebSocket signature covers `WS\n/v1/ws\nTIMESTAMP\nNONCE\nSHA256(empty)`. The channel emits only `message_available` notifications; message contents are never published as WebSocket plaintext.

## Required before production

- Connect real libsignal sessions on Android, iOS, and desktop with prekey bundles and Double Ratchet.
- Move nonce replay state to an atomic, TTL-backed shared store.
- Pin every federation peer public key and keep the federation private key in a secret file or HSM instead of a normal environment variable.
- Use mutual TLS and a production-grade federation worker.
- Terminate REST and WebSocket traffic behind TLS 1.3 with a certificate rotation plan.
- Add QR/security-code verification, device approval, and identity-change warnings.
- Replace the starter JSON store with PostgreSQL or SQLite suitable for the deployment scale.
- Authorize media downloads using recipient-side E2EE access tickets; the current example is owner-only.
- Complete fuzzing, two-server/three-user federation tests, plaintext-at-rest scans, an independent security review, and a bug bounty before production use.
- Define retention, access control, and privacy-law handling for IP and security-event metadata.

## References

- [Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal PQXDH specification](https://signal.org/docs/specifications/pqxdh/)
- [Official libsignal repository](https://github.com/signalapp/libsignal)
