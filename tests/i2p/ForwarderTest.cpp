#include "i2p_forwarder.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

using namespace luadch::i2p;

const std::string& publicDestination() {
    static const std::string destination(516, 'A');
    return destination;
}

const std::string& privateDestination() {
    static const std::string destination(884, 'A');
    return destination;
}

void require(bool aCondition, const std::string& aMessage) {
    if (!aCondition) {
        throw std::runtime_error(aMessage);
    }
}

template<typename Function>
void requireThrows(Function&& aFunction, const std::string& aMessage) {
    try {
        aFunction();
    } catch (const ForwarderException&) {
        return;
    }
    throw std::runtime_error(aMessage);
}

void writeAll(int aSocket, std::string_view aData) {
    size_t offset = 0;
    while (offset < aData.size()) {
#ifdef MSG_NOSIGNAL
        constexpr int SEND_FLAGS = MSG_NOSIGNAL;
#else
        constexpr int SEND_FLAGS = 0;
#endif
        const auto sent = ::send(aSocket, aData.data() + offset, aData.size() - offset, SEND_FLAGS);
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent <= 0) {
            throw std::runtime_error("Fake SAM bridge could not write");
        }
        offset += static_cast<size_t>(sent);
    }
}

void writeLine(int aSocket, const std::string& aLine) {
    writeAll(aSocket, aLine + '\n');
}

std::optional<std::string> readLine(int aSocket) {
    std::string line;
    while (line.size() <= 64 * 1024) {
        char character = 0;
        const auto received = ::recv(aSocket, &character, 1, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received == 0) {
            return std::nullopt;
        }
        if (received < 0) {
            throw std::runtime_error("Fake SAM bridge timed out");
        }
        if (character == '\n') {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return line;
        }
        line += character;
    }
    throw std::runtime_error("Fake SAM bridge received an oversized command");
}

std::string requireLine(int aSocket) {
    const auto line = readLine(aSocket);
    if (!line) {
        throw std::runtime_error("Fake SAM bridge connection closed unexpectedly");
    }
    return *line;
}

class FakeSamBridge {
public:
    FakeSamBridge() {
        const auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket == -1) {
            throw std::runtime_error("Unable to create fake SAM bridge");
        }

        try {
            int enabled = 1;
            if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
                throw std::runtime_error("Unable to configure fake SAM bridge");
            }
            sockaddr_in address { };
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = 0;
            if (bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(socket, 1) != 0) {
                throw std::runtime_error("Unable to listen as fake SAM bridge");
            }
            socklen_t length = sizeof(address);
            if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
                throw std::runtime_error("Unable to read fake SAM bridge port");
            }

            portNumber = ntohs(address.sin_port);
            listener = socket;
            thread = std::thread([this] { run(); });
        } catch (...) {
            ::close(socket);
            throw;
        }
    }

    ~FakeSamBridge() {
        stop();
    }

    uint16_t port() const noexcept {
        return portNumber;
    }

    void closeControl() {
        std::lock_guard lock(socketMutex);
        if (controlSocket != -1) {
            ::shutdown(controlSocket, SHUT_RDWR);
        }
    }

    void assertHealthy() const {
        std::lock_guard lock(failureMutex);
        if (failure) {
            std::rethrow_exception(failure);
        }
    }

    void stop() noexcept {
        if (stopping.exchange(true)) {
            return;
        }
        if (listener != -1) {
            ::shutdown(listener, SHUT_RDWR);
            ::close(listener);
            listener = -1;
        }
        closeControl();
        if (thread.joinable()) {
            thread.join();
        }
    }

private:
    std::atomic<bool> stopping { false };
    int listener = -1;
    int controlSocket = -1;
    uint16_t portNumber = 0;
    std::thread thread;
    std::mutex socketMutex;
    mutable std::mutex failureMutex;
    std::exception_ptr failure;

    void recordFailure() noexcept {
        std::lock_guard lock(failureMutex);
        if (!failure) {
            failure = std::current_exception();
        }
    }

    void run() noexcept {
        try {
            const auto client = ::accept(listener, nullptr, nullptr);
            if (client == -1) {
                if (stopping.load()) {
                    return;
                }
                throw std::runtime_error("Fake SAM bridge could not accept");
            }
            timeval timeout { 5, 0 };
            if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
                ::close(client);
                throw std::runtime_error("Fake SAM bridge could not set timeout");
            }
            {
                std::lock_guard lock(socketMutex);
                controlSocket = client;
            }

            require(requireLine(client) == "HELLO VERSION MIN=3.1 MAX=3.3", "Forwarder sent an unexpected HELLO");
            writeLine(client, "HELLO REPLY RESULT=OK VERSION=3.2");

            require(requireLine(client) == "DEST GENERATE SIGNATURE_TYPE=7", "Forwarder did not generate an Ed25519 identity");
            writeLine(client, "DEST REPLY PUB=" + publicDestination() + " PRIV=" + privateDestination());

            const auto session = requireLine(client);
            require(session.starts_with("SESSION CREATE STYLE=STREAM ID=luadch-i2p-"), "Forwarder did not create a STREAM session");
            require(session.find(" SIGNATURE_TYPE=7") != std::string::npos, "Forwarder did not request Ed25519 session identity");
            require(session.find(" i2cp.leaseSetEncType=4") != std::string::npos, "Forwarder did not request an ECIES leaseset");
            require(session.find(" inbound.quantity=3") != std::string::npos, "Forwarder did not set inbound tunnel quantity");
            require(session.find(" outbound.quantity=3") != std::string::npos, "Forwarder did not set outbound tunnel quantity");
            writeLine(client, "SESSION STATUS RESULT=OK");

            require(requireLine(client) == "NAMING LOOKUP NAME=ME", "Forwarder did not resolve its own destination");
            writeLine(client, "NAMING REPLY RESULT=OK VALUE=" + publicDestination());

            const auto forward = requireLine(client);
            require(forward.starts_with("STREAM FORWARD ID=luadch-i2p-"), "Forwarder did not request a stream forward");
            require(forward.find(" HOST=127.0.0.1 PORT=51234") != std::string::npos, "Forwarder did not use its loopback target");
            writeLine(client, "STREAM STATUS RESULT=OK");

            while (readLine(client)) {
                throw std::runtime_error("Forwarder sent an unexpected control command");
            }
            ::close(client);
            std::lock_guard lock(socketMutex);
            controlSocket = -1;
        } catch (...) {
            recordFailure();
        }
    }
};

class TemporaryDirectory {
public:
    explicit TemporaryDirectory(std::filesystem::path aPath) : path(std::move(aPath)) {
        std::filesystem::create_directories(path);
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }

    const std::filesystem::path path;
};

void runTests() {
    requireThrows([] {
        ForwarderOptions options;
        options.identityPath.clear();
        SamForwarder forwarder(options);
    }, "Forwarder accepted an empty identity path");

    const auto name = "luadch-i2p-forwarder-test-" + std::to_string(getpid()) + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    TemporaryDirectory temporaryDirectory(std::filesystem::temp_directory_path() / name);
    const auto identityPath = temporaryDirectory.path / "hub.private";

    FakeSamBridge bridge;
    ForwarderOptions options;
    options.identityPath = identityPath;
    options.samPort = bridge.port();
    options.targetPort = 51234;
    options.handshakeTimeout = std::chrono::seconds(2);
    options.sessionTimeout = std::chrono::seconds(2);

    SamForwarder forwarder(options);
    const auto status = forwarder.start();
    require(status.publicDestination == publicDestination(), "Forwarder stored the wrong public destination");
    require(status.b32Address.size() == 60 && status.b32Address.ends_with(".b32.i2p"), "Forwarder did not calculate a valid b32 destination");
    require(forwarder.isStarted(), "Forwarder did not retain its SAM control connection");
    require(forwarder.checkBridge(std::chrono::milliseconds(50)), "Forwarder considered an idle SAM bridge disconnected");

    std::ifstream identityFile(identityPath, std::ios::binary);
    std::string savedIdentity((std::istreambuf_iterator<char>(identityFile)), std::istreambuf_iterator<char>());
    require(savedIdentity == privateDestination() + '\n', "Forwarder did not persist the generated identity");
    struct stat identityStatus { };
    require(::stat(identityPath.c_str(), &identityStatus) == 0, "Could not inspect persisted identity permissions");
    require((identityStatus.st_mode & (S_IRWXG | S_IRWXO)) == 0, "Persisted identity is readable outside its owner");

    bridge.closeControl();
    require(!forwarder.checkBridge(std::chrono::seconds(2)), "Forwarder did not notice a closed SAM control connection");
    forwarder.stop();
    bridge.stop();
    bridge.assertHealthy();
}

} // namespace

int main() {
    try {
        runTests();
        std::cout << "I2P forwarder integration tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "I2P forwarder integration test failed: " << error.what() << '\n';
        return 1;
    }
}
