# Jubbio Security

Jubbio için Signal Protocol/libsignal tabanlı uçtan uca şifreleme entegrasyon projesi. Bu repository, eski 15 katmanlı özel şifreleme yaklaşımını kullanmaz.

## Güvenlik kararı

C++ katmanı kriptografi uygulamaz. `SignalBackend` arayüzü, sürümü sabitlenmiş ve bağımsız olarak incelenmiş Rust/libsignal bridge ile doldurulmalıdır. Resmi libsignal çekirdeği Rust tabanlıdır; resmi istemci yüzeyleri Java, Swift ve TypeScript’tir. C++ için kendi X3DH/Double Ratchet uygulamamızı yazmak güvenli bir alternatif değildir.

Bridge bağlanmadan mesaj şifreleme yapılmaz; crate bilerek hata döndürür. Bu davranış, eksik entegrasyonun üretimde sahte güvenlik olarak sunulmasını önler.

## Klasörler

- `cpp/`: Jubbio uygulamasının C++ servis sınırı ve testleri.
- `rust/libsignal_bridge/`: libsignal’a bağlanacak FFI sınırı; henüz üretim kriptografisi içermez.
- `docs/E2EE-ARCHITECTURE.md`: tehdit modeli, mimari, anahtar yönetimi, sunucu ve yol haritası.

## C++ derleme

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

## Rust bridge kontrolü

```bash
cd rust/libsignal_bridge
cargo check
```

## Üretim entegrasyonundan önce

1. Hedef platformları kesinleştir: Android, iOS, desktop.
2. Uyumlu libsignal release/commit’ini sabitle ve lisans incelemesi yap.
3. Rust FFI’de opaque session handle, buffer ownership, zeroization ve hata eşlemesini uygula.
4. Public prekey directory, atomik one-time prekey tüketimi ve opaque relay sunucusunu ekle.
5. OS secure storage, QR/security-code doğrulaması, çoklu cihaz ve key-change uyarılarını ekle.
6. Fuzz, integration, device-loss ve bağımsız güvenlik denetimini tamamlamadan üretime alma.

Ayrıntılı kararlar için [`docs/E2EE-ARCHITECTURE.md`](docs/E2EE-ARCHITECTURE.md) dosyasına bakın.
