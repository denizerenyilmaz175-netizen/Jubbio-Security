#include "jubbio_security/e2ee_service.hpp"

namespace jubbio::security {

Bytes E2eeService::encrypt_for_device(const DeviceId& peer, const PreKeyBundle& bundle,
                                      const Bytes& plaintext, const Bytes& associated_data) {
    const auto session = backend_.create_or_load_session(peer, bundle);
    try {
        auto result = backend_.encrypt(session, plaintext, associated_data);
        backend_.destroy_session(session);
        return result;
    } catch (...) {
        backend_.destroy_session(session);
        throw;
    }
}

Bytes E2eeService::decrypt_from_device(const DeviceId& peer, const PreKeyBundle& bundle,
                                      const Bytes& ciphertext, const Bytes& associated_data) {
    const auto session = backend_.create_or_load_session(peer, bundle);
    try {
        auto result = backend_.decrypt(session, ciphertext, associated_data);
        backend_.destroy_session(session);
        return result;
    } catch (...) {
        backend_.destroy_session(session);
        throw;
    }
}

} // namespace jubbio::security
