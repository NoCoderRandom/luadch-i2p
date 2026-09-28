#ifndef LUADCH_I2P_FORWARDER_H
#define LUADCH_I2P_FORWARDER_H

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

namespace luadch::i2p {

class ForwarderException : public std::runtime_error {
public:
    explicit ForwarderException(const std::string& aMessage) : std::runtime_error(aMessage) { }
};

struct ForwarderOptions {
    std::filesystem::path identityPath = "cfg/i2p-hub.private";
    uint16_t samPort = 7656;
    uint16_t targetPort = 5000;
    uint16_t inboundQuantity = 3;
    uint16_t outboundQuantity = 3;
    std::chrono::milliseconds handshakeTimeout { 10'000 };
    std::chrono::milliseconds sessionTimeout { 90'000 };
};

struct ForwarderStatus {
    std::string publicDestination;
    std::string b32Address;
};

class SamForwarder {
public:
    explicit SamForwarder(ForwarderOptions aOptions = { });
    ~SamForwarder() noexcept;

    SamForwarder(const SamForwarder&) = delete;
    SamForwarder& operator=(const SamForwarder&) = delete;

    ForwarderStatus start();
    void stop() noexcept;
    bool isStarted() const noexcept;

    // Returns false when the SAM control connection has closed or sent data.
    bool checkBridge(std::chrono::milliseconds aTimeout);

private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace luadch::i2p

#endif // LUADCH_I2P_FORWARDER_H
