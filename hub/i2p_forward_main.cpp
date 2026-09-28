#include "i2p_forwarder.h"

#include <charconv>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string_view>

namespace {

volatile std::sig_atomic_t stopRequested = 0;

void handleSignal(int) {
    stopRequested = 1;
}

uint16_t parsePort(std::string_view aValue, const char* aName) {
    unsigned int value = 0;
    const auto result = std::from_chars(aValue.data(), aValue.data() + aValue.size(), value);
    if (result.ec != std::errc() || result.ptr != aValue.data() + aValue.size() || value == 0 || value > 65535) {
        throw luadch::i2p::ForwarderException(std::string("Invalid ") + aName);
    }
    return static_cast<uint16_t>(value);
}

void printUsage() {
    std::cout <<
        "Usage: luadch-i2p-forward [options]\n"
        "  --identity PATH       Persistent private destination (default: cfg/i2p-hub.private)\n"
        "  --sam-port PORT       Numeric-loopback SAM port (default: 7656)\n"
        "  --target-port PORT    Loopback Luadch ADC port (default: 5000)\n"
        "  --inbound-quantity N  I2P inbound tunnels, 1-16 (default: 3)\n"
        "  --outbound-quantity N I2P outbound tunnels, 1-16 (default: 3)\n";
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        luadch::i2p::ForwarderOptions options;
        for (int index = 1; index < argc; ++index) {
            const std::string_view argument(argv[index]);
            if (argument == "--help" || argument == "-h") {
                printUsage();
                return 0;
            }
            if (index + 1 >= argc) {
                throw luadch::i2p::ForwarderException("Missing option value");
            }

            const std::string_view value(argv[++index]);
            if (argument == "--identity") {
                options.identityPath = std::string(value);
            } else if (argument == "--sam-port") {
                options.samPort = parsePort(value, "SAM port");
            } else if (argument == "--target-port") {
                options.targetPort = parsePort(value, "target port");
            } else if (argument == "--inbound-quantity") {
                options.inboundQuantity = parsePort(value, "inbound quantity");
            } else if (argument == "--outbound-quantity") {
                options.outboundQuantity = parsePort(value, "outbound quantity");
            } else {
                throw luadch::i2p::ForwarderException("Unknown option");
            }
        }

        std::signal(SIGINT, handleSignal);
        std::signal(SIGTERM, handleSignal);

        luadch::i2p::SamForwarder forwarder(options);
        const auto status = forwarder.start();
        std::cout << "I2P hub destination: " << status.b32Address << std::endl;
        std::cout << "Forwarding I2P streams to 127.0.0.1:" << options.targetPort << std::endl;

        while (!stopRequested) {
            if (!forwarder.checkBridge(std::chrono::seconds(1))) {
                throw luadch::i2p::ForwarderException("The SAM control connection closed");
            }
        }

        forwarder.stop();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "luadch-i2p-forward: " << error.what() << '\n';
        return 1;
    }
}
