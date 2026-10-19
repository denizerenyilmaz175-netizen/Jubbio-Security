#include "jubbio_security/e2ee_service.hpp"
#include <cassert>

using namespace jubbio::security;

class RecordingBackend final : public SignalBackend {
public:
    SessionHandle create_or_load_session(const DeviceId&, const PreKeyBundle&) override { created++; return {42}; }
    Bytes encrypt(SessionHandle, const Bytes& p, const Bytes&) override { encrypted++; return p; }
    Bytes decrypt(SessionHandle, const Bytes& c, const Bytes&) override { decrypted++; return c; }
    void destroy_session(SessionHandle) noexcept override { destroyed++; }
    int created = 0, encrypted = 0, decrypted = 0, destroyed = 0;
};

int main() {
    RecordingBackend backend;
    E2eeService service(backend);
    DeviceId peer{"device-1"};
    PreKeyBundle bundle{{1, 2, 3}};
    Bytes message{'h', 'i'};
    assert(service.encrypt_for_device(peer, bundle, message) == message);
    assert(service.decrypt_from_device(peer, bundle, message) == message);
    assert(backend.created == 2 && backend.encrypted == 1 && backend.decrypted == 1 && backend.destroyed == 2);
    return 0;
}
