# Jubbio Security

Jubbio için Signal/libsignal tabanlı E2EE istemcileri taşıyacak, REST + WebSocket erişimli, imzalı ve opaque relay/federation sunucusu.

## Güvenlik sınırı

Sunucu **mesaj plaintext’ini ve dosya plaintext’ini üretmez**. Sunucuya gelen `envelopeB64` libsignal istemcisinde üretilmiş E2EE zarfı, medya parçaları ise istemcide AEAD ile şifrelenmiş blob olmalıdır. Bu repository sunucuda sahte bir Signal uygulaması yazmaz. Gerçek cihaz oturumları için istemci tarafında sürümü sabitlenmiş `@signalapp/libsignal-client` kullanılmalıdır.

“Veri çalınamaz” veya “kırılamaz” garantisi yoktur. Ele geçirilmiş cihazın ekranı, belleği veya klavyesi plaintext’i görebilir; metadata da kısmen sunucuya görünür.

## Çalışan bileşenler

- `server/`: Node.js 22 REST + WebSocket opaque relay.
- `client/media.mjs`: İstemci tarafında AES-256-GCM ile authenticated, sıralı medya parçası şifreleme örneği.
- `client/key-vault.mjs`: scrypt + AES-256-GCM ile yerel parola kasası; anahtar buffer’ları işlem sonunda temizlenir.
- `server/src/security-controls.mjs`: zamanla azalan risk puanı ve hash-zincirli, içeriksiz olay günlüğü.
- `security/decoy.mjs`: gerçek relay ağına bağlı olmayan izole decoy/honeypot servisi.
- `scripts/e2e-test.mjs`: İki cihazla imzalı relay, bozuk imza reddi, inbox ve medya round-trip testi.
- `scripts/federation-test.mjs`: İki sunucu ve üç kullanıcıyla pinned peer signing ve opaque cross-server delivery testi.
- `docker-compose.yml`: Tek komutla izole Docker kurulumu.
- `docs/E2EE-ARCHITECTURE.md`: Tehdit modeli, Signal/libsignal mimarisi, federasyon ve yol haritası.

## Tek komutla kurulum

```bash
cp .env.example .env
# .env içindeki INVITE_CODE değerini uzun rastgele bir değerle değiştir

docker compose up -d --build
curl http://localhost:8080/v1/health
```

TLS üretimde reverse proxy veya doğrudan TLS terminasyonu ile **zorunlu** yapılmalıdır. Geliştirme HTTP’si public internete açılmamalıdır. `jubbio_data` volume’ünü düzenli ve şifreli olarak yedekleyin; backup anahtarını sunucuda plaintext tutmayın.

## Yerel çalıştırma ve test

```bash
cd server
npm install
cd ..
node scripts/e2e-test.mjs
node scripts/federation-test.mjs
node scripts/security-controls-test.mjs
```

Test şunları kanıtlar: cihaz public key kaydı, Ed25519 imzalı relay, imza bozulmasının reddi, inbox teslimi, AES-256-GCM medya chunk round-trip’i ve diskte yalnızca testin şifreli medya blob’unun tutulması. Testteki `opaque-libsignal-ciphertext-v1` gerçek Signal ciphertext değildir; gerçek istemci bunun yerine libsignal çıktısı vermelidir.

## API

### Kayıt

`POST /v1/register` gövdesi: `{ "deviceId": "user@server/device", "publicKeyPem": "...", "inviteCode": "..." }`.

### İmzalı relay

`POST /v1/relay` gövdesi: `{ "recipient": "user@server/device", "envelopeB64": "<libsignal ciphertext>" }`.

Her istek şu başlıklarla Ed25519 imzalanır: `x-device-id`, `x-timestamp`, `x-nonce`, `x-signature`. İmzalanan canonical metin:

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(REQUEST_BODY)
```

Zaman damgası 5 dakika penceresindedir. Sunucu nonce’ları TTL’li replay cache içinde tek kullanımlık olarak kabul eder; çoklu instance üretiminde bu cache Redis/SQL gibi ortak atomik store’a taşınmalıdır.

### Inbox

`GET /v1/inbox/:deviceId` aynı imzalı başlıklarla yalnızca o cihazın bekleyen opaque envelope’larını döndürür.

### Medya

1. `POST /v1/media/:clientFileId` ile chunk sayısını ve boyutu bildir.
2. `PUT /v1/media/:mediaId/chunks/:index` ile zaten AEAD şifreli chunk’ı gönder; `x-chunk-sha256` ve `x-chunk-count` zorunludur.
3. `GET /v1/media/:mediaId/chunks/:index` ile blob’u al.
4. Dosya anahtarı ve manifesti ayrı libsignal mesajında gönder; sunucu dosya anahtarını hiç görmez.

### WebSocket

`GET /v1/ws` bağlantısından sonra ilk mesaj `{ "type": "auth", "deviceId": "...", "timestamp": "...", "nonce": "...", "signature": "..." }` olmalıdır. WebSocket imzası `WS\n/v1/ws\nTIMESTAMP\nNONCE\nSHA256(empty)` canonical metnini kapsar. Bağlantı yeni mesaj için yalnızca `message_available` bildirimi yollar; mesaj içeriği WebSocket’te plaintext olarak yayınlanmaz.

## Üretim öncesi zorunlu işler

- libsignal istemci oturumlarını Android/iOS/desktop’ta gerçek prekey bundle ve Double Ratchet ile bağla.
- Nonce replay kayıtlarını atomik ve TTL’li bir KV/SQL store’a taşı.
- Federation için `FEDERATION_PEERS_JSON` içinde her peer’ın public key fingerprint’ini/pem’ini sabitle; private server signing key’i env yerine secret file/HSM’de tut.
- Federation peer public key pinning, karşılıklı TLS ve offline retry queue’yu production store/worker ile tamamla.
- REST/WebSocket’i TLS 1.3 arkasında yayınla; certificate rotation planı oluştur.
- Public key değişiminde QR/security-code doğrulaması ve cihaz onayı uygula.
- Postgres/SQLite gibi güvenilir kalıcı store seç; bu başlangıç sürümünün JSON store’u yüksek hacim için uygun değildir.
- Media download authorization’ı alıcının libsignal erişim biletiyle sınırla; örnek endpoint owner-only’dir.
- Fuzz, iki sunucu/üç kullanıcı federasyon testi, disk plaintext taraması, bağımsız protokol denetimi ve bug bounty tamamlanmadan üretime alma.
- Yüksek risk trafiğini decoy’a yönlendirme reverse proxy/WAF seviyesinde yapılmalı; decoy varsayılan compose profiline dahil değildir. Başlatmak için `docker compose --profile decoy up -d --build` kullanılır ve decoy ağı relay ağından ayrıdır.
- Hash-zincirli audit kaydı içerik taşımaz; IP/olay metadata’sı için saklama süresi, KVKK/GDPR ve erişim yetkisi ayrıca uygulanmalıdır.
- Node buffer temizliği best-effort’tur; JavaScript GC üzerinde kesin RAM silme garantisi yoktur. Identity/prekey private key’leri gerçek libsignal ve OS secure storage içinde tutulmalıdır.

## Kaynaklar

- [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/)
- [Official libsignal](https://github.com/signalapp/libsignal)
