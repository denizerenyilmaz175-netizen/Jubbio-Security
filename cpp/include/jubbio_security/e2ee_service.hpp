#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace jubbio::security {

using Bytes = std::vector<std::uint8_t>;

struct DeviceId { std::string value; };
struct PreKeyBundle { Bytes encoded; };
struct SessionHandle { std::uint64_t value = 0; };

class E2eeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Implement this interface with the version-pinned Rust/libsignal FFI bridge.
// No cryptographic primitive belongs in this C++ layer.
class SignalBackend {
public:
    virtual ~SignalBackend() = default;
    virtual SessionHandle create_or_load_session(const DeviceId&, const PreKeyBundle&) = 0;
    virtual Bytes encrypt(SessionHandle, const Bytes& plaintext, const Bytes& associated_data) = 0;
    virtual Bytes decrypt(SessionHandle, const Bytes& ciphertext, const Bytes& associated_data) = 0;
    virtual void destroy_session(SessionHandle) noexcept = 0;
};

class E2eeService final {
public:
    explicit E2eeService(SignalBackend& backend) noexcept : backend_(backend) {}

    Bytes encrypt_for_device(const DeviceId& peer, const PreKeyBundle& bundle,
                             const Bytes& plaintext, const Bytes& associated_data = {});
    Bytes decrypt_from_device(const DeviceId& peer, const PreKeyBundle& bundle,
                             const Bytes& ciphertext, const Bytes& associated_data = {});

private:
    SignalBackend& backend_;
};

} // namespace jubbio::security
