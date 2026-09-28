#include "i2p_forwarder.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <string_view>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <arpa/inet.h>

namespace luadch::i2p {

namespace {

constexpr size_t MINIMUM_DESTINATION_LENGTH = 516;
constexpr size_t MAXIMUM_IDENTITY_LENGTH = 16 * 1024;

bool isWhitespace(char aCharacter) noexcept {
    return aCharacter == ' ' || aCharacter == '\t';
}

bool containsLineBreak(std::string_view aValue) noexcept {
    return aValue.find_first_of("\r\n") != std::string_view::npos;
}

bool isBase64Character(char aCharacter) noexcept {
    return (aCharacter >= 'A' && aCharacter <= 'Z') ||
        (aCharacter >= 'a' && aCharacter <= 'z') ||
        (aCharacter >= '0' && aCharacter <= '9') ||
        aCharacter == '+' || aCharacter == '/' || aCharacter == '-' ||
        aCharacter == '~' || aCharacter == '=';
}

bool isEncodedDestination(const std::string& aDestination) noexcept {
    return aDestination.size() >= MINIMUM_DESTINATION_LENGTH &&
        !containsLineBreak(aDestination) &&
        std::all_of(aDestination.begin(), aDestination.end(), isBase64Character);
}

std::string trim(std::string aValue) {
    while (!aValue.empty() && (aValue.back() == '\r' || aValue.back() == '\n' || isWhitespace(aValue.back()))) {
        aValue.pop_back();
    }

    size_t first = 0;
    while (first < aValue.size() && isWhitespace(aValue[first])) {
        ++first;
    }

    return aValue.substr(first);
}

std::string randomHex(size_t aBytes) {
    std::vector<unsigned char> bytes(aBytes);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw ForwarderException("Unable to generate a secure I2P session identifier");
    }

    constexpr char HEX[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result += HEX[byte >> 4];
        result += HEX[byte & 0x0f];
    }

    return result;
}

void cleanse(std::string& aValue) noexcept {
    if (!aValue.empty()) {
        OPENSSL_cleanse(aValue.data(), aValue.size());
        aValue.clear();
    }
}

std::chrono::milliseconds remainingTime(std::chrono::steady_clock::time_point aDeadline) {
    const auto remaining = aDeadline - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::steady_clock::duration::zero()) {
        throw ForwarderException("Timed out waiting for the local SAM bridge");
    }

    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    return milliseconds.count() > 0 ? milliseconds : std::chrono::milliseconds(1);
}

std::vector<std::string> tokenize(std::string_view aLine) {
    std::vector<std::string> tokens;
    std::string token;
    bool quoted = false;
    bool escaped = false;

    for (const auto character : aLine) {
        if (escaped) {
            token += character;
            escaped = false;
            continue;
        }

        if (quoted && character == '\\') {
            escaped = true;
            continue;
        }
        if (character == '"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted && isWhitespace(character)) {
            if (!token.empty()) {
                tokens.push_back(std::move(token));
                token.clear();
            }
            continue;
        }

        token += character;
    }

    if (quoted || escaped) {
        throw ForwarderException("Malformed SAM response");
    }
    if (!token.empty()) {
        tokens.push_back(std::move(token));
    }

    return tokens;
}

struct SamReply {
    std::string command;
    std::string subcommand;
    std::map<std::string, std::string> options;

    std::optional<std::string> get(const std::string& aName) const {
        const auto option = options.find(aName);
        return option == options.end() ? std::nullopt : std::optional<std::string>(option->second);
    }
};

SamReply parseReply(std::string_view aLine) {
    if (containsLineBreak(aLine)) {
        throw ForwarderException("SAM response contains an unexpected line break");
    }

    auto tokens = tokenize(aLine);
    if (tokens.empty()) {
        throw ForwarderException("Empty SAM response");
    }

    SamReply reply;
    reply.command = std::move(tokens.front());
    size_t optionStart = 1;
    if (tokens.size() > 1 && tokens[1].find('=') == std::string::npos) {
        reply.subcommand = std::move(tokens[1]);
        optionStart = 2;
    }

    for (size_t index = optionStart; index < tokens.size(); ++index) {
        const auto separator = tokens[index].find('=');
        const auto name = separator == std::string::npos ? tokens[index] : tokens[index].substr(0, separator);
        const auto value = separator == std::string::npos ? std::string() : tokens[index].substr(separator + 1);
        if (name.empty() || !reply.options.emplace(name, value).second) {
            throw ForwarderException("Malformed SAM response option");
        }
    }

    return reply;
}

bool versionAtLeast(const std::string& aVersion, int aMajor, int aMinor) noexcept {
    const auto separator = aVersion.find('.');
    if (separator == std::string::npos) {
        return false;
    }

    int major = 0;
    int minor = 0;
    const auto majorResult = std::from_chars(aVersion.data(), aVersion.data() + separator, major);
    const auto minorResult = std::from_chars(aVersion.data() + separator + 1, aVersion.data() + aVersion.size(), minor);
    if (majorResult.ec != std::errc() || minorResult.ec != std::errc()) {
        return false;
    }

    return major > aMajor || (major == aMajor && minor >= aMinor);
}

class LocalSocket {
public:
    LocalSocket() noexcept = default;
    ~LocalSocket() noexcept {
        close();
    }

    LocalSocket(LocalSocket&& aOther) noexcept : handle(aOther.handle) {
        aOther.handle = -1;
    }

    LocalSocket& operator=(LocalSocket&& aOther) noexcept {
        if (this != &aOther) {
            close();
            handle = aOther.handle;
            aOther.handle = -1;
        }
        return *this;
    }

    LocalSocket(const LocalSocket&) = delete;
    LocalSocket& operator=(const LocalSocket&) = delete;

    static LocalSocket connect(uint16_t aPort, std::chrono::milliseconds aTimeout) {
        if (aPort == 0 || aTimeout.count() <= 0) {
            throw ForwarderException("Invalid local SAM bridge configuration");
        }

        const auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket == -1) {
            throw ForwarderException("Unable to create a local SAM socket");
        }

        try {
            setBlocking(socket, false);
            sockaddr_in address { };
            address.sin_family = AF_INET;
            address.sin_port = htons(aPort);
            if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
                throw ForwarderException("Unable to configure the local SAM address");
            }

            if (::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == -1) {
                if (errno != EINPROGRESS && errno != EWOULDBLOCK && errno != EAGAIN) {
                    throw ForwarderException("Unable to connect to the local SAM bridge");
                }

                waitFor(socket, false, true, aTimeout);
                int socketError = 0;
                socklen_t socketErrorLength = sizeof(socketError);
                if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength) != 0 || socketError != 0) {
                    throw ForwarderException("Unable to connect to the local SAM bridge");
                }
            }

            setBlocking(socket, true);
            return LocalSocket(socket);
        } catch (...) {
            ::close(socket);
            throw;
        }
    }

    void close() noexcept {
        if (handle != -1) {
            ::close(handle);
            handle = -1;
        }
    }

    bool isOpen() const noexcept {
        return handle != -1;
    }

    void writeLine(std::string_view aLine, std::chrono::milliseconds aTimeout) {
        if (containsLineBreak(aLine)) {
            throw ForwarderException("SAM command contains an unexpected line break");
        }

        write(aLine, aTimeout);
        // i2pd's SAM parser requires CRLF framing; CRLF is also accepted
        // by SAM bridges that tolerate LF-only commands.
        write("\r\n", aTimeout);
    }

    std::string readLine(std::chrono::milliseconds aTimeout, size_t aMaximumLength = 64 * 1024) {
        if (!isOpen()) {
            throw ForwarderException("Local SAM socket is closed");
        }

        const auto deadline = std::chrono::steady_clock::now() + aTimeout;
        std::string line;
        line.reserve(128);
        while (line.size() <= aMaximumLength) {
            waitFor(handle, true, false, remainingTime(deadline));
            char character = 0;
            const auto received = ::recv(handle, &character, 1, 0);
            if (received < 0 && errno == EINTR) {
                continue;
            }
            if (received <= 0) {
                throw ForwarderException("Local SAM bridge closed the connection");
            }
            if (character == '\n') {
                return trim(std::move(line));
            }

            line += character;
        }

        throw ForwarderException("SAM response exceeded the maximum line length");
    }

    bool isQuiet(std::chrono::milliseconds aTimeout) const {
        if (!isOpen()) {
            return false;
        }
        if (aTimeout.count() < 0) {
            throw ForwarderException("Invalid SAM timeout");
        }

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(handle, &readSet);
        timeval timeout {
            static_cast<long>(aTimeout.count() / 1000),
            static_cast<long>((aTimeout.count() % 1000) * 1000),
        };
        const auto result = select(handle + 1, &readSet, nullptr, nullptr, &timeout);
        if (result == 0 || (result < 0 && errno == EINTR)) {
            return true;
        }
        if (result < 0) {
            throw ForwarderException("Unable to monitor the local SAM bridge");
        }

        char character = 0;
        const auto received = ::recv(handle, &character, 1, MSG_PEEK);
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            return true;
        }

        return false;
    }

private:
    explicit LocalSocket(int aHandle) noexcept : handle(aHandle) { }

    int handle = -1;

    static void setBlocking(int aSocket, bool aBlocking) {
        const auto flags = fcntl(aSocket, F_GETFL, 0);
        if (flags == -1 || fcntl(aSocket, F_SETFL, aBlocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK)) == -1) {
            throw ForwarderException("Unable to configure the local SAM socket");
        }
    }

    static void waitFor(int aSocket, bool aRead, bool aWrite, std::chrono::milliseconds aTimeout) {
        if (aTimeout.count() < 0) {
            throw ForwarderException("Invalid SAM timeout");
        }

        const auto deadline = std::chrono::steady_clock::now() + aTimeout;
        while (true) {
            fd_set readSet;
            fd_set writeSet;
            FD_ZERO(&readSet);
            FD_ZERO(&writeSet);
            if (aRead) {
                FD_SET(aSocket, &readSet);
            }
            if (aWrite) {
                FD_SET(aSocket, &writeSet);
            }

            const auto remaining = remainingTime(deadline);
            timeval timeout {
                static_cast<long>(remaining.count() / 1000),
                static_cast<long>((remaining.count() % 1000) * 1000),
            };
            const auto result = select(aSocket + 1, aRead ? &readSet : nullptr, aWrite ? &writeSet : nullptr, nullptr, &timeout);
            if (result > 0) {
                return;
            }
            if (result == 0) {
                throw ForwarderException("Timed out waiting for the local SAM bridge");
            }
            if (errno != EINTR) {
                throw ForwarderException("Local SAM socket wait failed");
            }
        }
    }

    void write(std::string_view aData, std::chrono::milliseconds aTimeout) {
        if (!isOpen()) {
            throw ForwarderException("Local SAM socket is closed");
        }

        const auto deadline = std::chrono::steady_clock::now() + aTimeout;
        size_t offset = 0;
        while (offset < aData.size()) {
            waitFor(handle, false, true, remainingTime(deadline));
#ifdef MSG_NOSIGNAL
            constexpr int SEND_FLAGS = MSG_NOSIGNAL;
#else
            constexpr int SEND_FLAGS = 0;
#endif
            const auto sent = ::send(handle, aData.data() + offset, aData.size() - offset, SEND_FLAGS);
            if (sent < 0 && errno == EINTR) {
                continue;
            }
            if (sent <= 0) {
                throw ForwarderException("Unable to write to the local SAM bridge");
            }

            offset += static_cast<size_t>(sent);
        }
    }
};

SamReply transact(LocalSocket& aSocket, std::string_view aCommand, std::chrono::milliseconds aTimeout) {
    aSocket.writeLine(aCommand, aTimeout);
    return parseReply(aSocket.readLine(aTimeout));
}

void requireOk(const SamReply& aReply, const std::string& aCommand, const std::string& aSubcommand) {
    if (aReply.command != aCommand || aReply.subcommand != aSubcommand) {
        throw ForwarderException("Unexpected SAM response");
    }

    const auto result = aReply.get("RESULT");
    if (!result || *result != "OK") {
        throw ForwarderException("SAM bridge rejected the request");
    }
}

void hello(LocalSocket& aSocket, std::chrono::milliseconds aTimeout) {
    const auto reply = transact(aSocket, "HELLO VERSION MIN=3.1 MAX=3.3", aTimeout);
    requireOk(reply, "HELLO", "REPLY");
    const auto version = reply.get("VERSION");
    if (!version || !versionAtLeast(*version, 3, 1)) {
        throw ForwarderException("SAM bridge does not support SAM 3.1");
    }
}

std::optional<std::string> loadIdentity(const std::filesystem::path& aPath) {
    int flags = O_RDONLY;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int descriptor = ::open(aPath.c_str(), flags);
    if (descriptor == -1) {
        if (errno == ENOENT) {
            return std::nullopt;
        }
        throw ForwarderException("Unable to open the I2P identity file");
    }

    try {
        struct stat status { };
        if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_uid != geteuid() || (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            throw ForwarderException("I2P identity file must be a private regular file");
        }
        if (status.st_size <= 0 || static_cast<uintmax_t>(status.st_size) > MAXIMUM_IDENTITY_LENGTH) {
            throw ForwarderException("I2P identity file has an invalid size");
        }

        std::string identity(static_cast<size_t>(status.st_size), '\0');
        size_t offset = 0;
        while (offset < identity.size()) {
            const auto received = ::read(descriptor, identity.data() + offset, identity.size() - offset);
            if (received < 0 && errno == EINTR) {
                continue;
            }
            if (received <= 0) {
                throw ForwarderException("Unable to read the I2P identity file");
            }
            offset += static_cast<size_t>(received);
        }

        if (::close(descriptor) != 0) {
            descriptor = -1;
            throw ForwarderException("Unable to close the I2P identity file");
        }
        descriptor = -1;

        identity = trim(std::move(identity));
        if (!isEncodedDestination(identity)) {
            throw ForwarderException("I2P identity file is invalid");
        }
        return identity;
    } catch (...) {
        if (descriptor != -1) {
            ::close(descriptor);
        }
        throw;
    }
}

void saveIdentity(const std::filesystem::path& aPath, const std::string& aIdentity) {
    if (!isEncodedDestination(aIdentity)) {
        throw ForwarderException("Refusing to save an invalid I2P identity");
    }

    std::error_code error;
    if (!aPath.parent_path().empty()) {
        std::filesystem::create_directories(aPath.parent_path(), error);
        if (error) {
            throw ForwarderException("Unable to create the I2P identity directory");
        }
    }

    auto temporaryPath = aPath;
    temporaryPath += ".tmp-" + randomHex(8);
    try {
        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        int descriptor = ::open(temporaryPath.c_str(), flags, S_IRUSR | S_IWUSR);
        if (descriptor == -1) {
            throw ForwarderException("Unable to create the I2P identity file");
        }

        try {
            const auto content = aIdentity + '\n';
            size_t offset = 0;
            while (offset < content.size()) {
                const auto written = ::write(descriptor, content.data() + offset, content.size() - offset);
                if (written < 0 && errno == EINTR) {
                    continue;
                }
                if (written <= 0) {
                    throw ForwarderException("Unable to write the I2P identity file");
                }
                offset += static_cast<size_t>(written);
            }

            if (fsync(descriptor) != 0) {
                throw ForwarderException("Unable to finalize the I2P identity file");
            }
            if (::close(descriptor) != 0) {
                descriptor = -1;
                throw ForwarderException("Unable to close the I2P identity file");
            }
            descriptor = -1;
        } catch (...) {
            if (descriptor != -1) {
                ::close(descriptor);
            }
            throw;
        }

        error.clear();
        std::filesystem::rename(temporaryPath, aPath, error);
        if (error) {
            throw ForwarderException("Unable to finalize the I2P identity file");
        }
    } catch (...) {
        std::filesystem::remove(temporaryPath, error);
        throw;
    }
}

std::vector<unsigned char> decodeDestination(const std::string& aDestination) {
    if (!isEncodedDestination(aDestination)) {
        throw ForwarderException("I2P destination is invalid");
    }

    std::string normalized;
    normalized.reserve(aDestination.size() + 3);
    for (const auto character : aDestination) {
        normalized += character == '-' ? '+' : (character == '~' ? '/' : character);
    }
    while (normalized.size() % 4 != 0) {
        normalized += '=';
    }

    std::vector<unsigned char> decoded((normalized.size() / 4) * 3);
    auto decodedLength = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(normalized.data()), static_cast<int>(normalized.size()));
    if (decodedLength < 0) {
        throw ForwarderException("I2P destination is invalid");
    }
    for (auto iterator = normalized.rbegin(); iterator != normalized.rend() && *iterator == '='; ++iterator) {
        --decodedLength;
    }
    if (decodedLength < 0) {
        throw ForwarderException("I2P destination is invalid");
    }

    decoded.resize(static_cast<size_t>(decodedLength));
    return decoded;
}

std::string destinationToB32(const std::string& aDestination) {
    const auto destination = decodeDestination(aDestination);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest { };
    unsigned int digestLength = 0;
    if (EVP_Digest(destination.data(), destination.size(), digest.data(), &digestLength, EVP_sha256(), nullptr) != 1 || digestLength != 32) {
        throw ForwarderException("Unable to calculate the I2P destination hash");
    }

    constexpr char BASE32[] = "abcdefghijklmnopqrstuvwxyz234567";
    std::string result;
    result.reserve(52 + 8);
    unsigned int buffer = 0;
    int bits = 0;
    for (unsigned int index = 0; index < digestLength; ++index) {
        buffer = (buffer << 8) | digest[index];
        bits += 8;
        while (bits >= 5) {
            result += BASE32[(buffer >> (bits - 5)) & 0x1f];
            bits -= 5;
        }
    }
    if (bits > 0) {
        result += BASE32[(buffer << (5 - bits)) & 0x1f];
    }

    return result + ".b32.i2p";
}

} // namespace

class SamForwarder::Impl {
public:
    explicit Impl(ForwarderOptions aOptions) : options(std::move(aOptions)) {
        if (options.identityPath.empty() || options.samPort == 0 || options.targetPort == 0 ||
            options.inboundQuantity == 0 || options.inboundQuantity > 16 ||
            options.outboundQuantity == 0 || options.outboundQuantity > 16 ||
            options.handshakeTimeout.count() <= 0 || options.sessionTimeout.count() <= 0) {
            throw ForwarderException("Invalid I2P forwarder configuration");
        }
    }

    ForwarderStatus start() {
        if (controlSocket && controlSocket->isOpen()) {
            return status;
        }

        controlSocket.reset();
        status = { };
        std::string privateDestination;
        try {
            auto socket = std::make_unique<LocalSocket>(LocalSocket::connect(options.samPort, options.handshakeTimeout));
            hello(*socket, options.handshakeTimeout);

            const auto existingIdentity = loadIdentity(options.identityPath);
            if (existingIdentity) {
                privateDestination = *existingIdentity;
            } else {
                const auto generated = transact(*socket, "DEST GENERATE SIGNATURE_TYPE=7", options.sessionTimeout);
                if (generated.command != "DEST" || generated.subcommand != "REPLY") {
                    throw ForwarderException("Unexpected SAM response while generating the I2P identity");
                }

                const auto publicDestination = generated.get("PUB");
                const auto generatedPrivateDestination = generated.get("PRIV");
                if (!publicDestination || !generatedPrivateDestination || !isEncodedDestination(*publicDestination) || !isEncodedDestination(*generatedPrivateDestination)) {
                    throw ForwarderException("SAM bridge returned an invalid I2P identity");
                }

                saveIdentity(options.identityPath, *generatedPrivateDestination);
                privateDestination = *generatedPrivateDestination;
            }

            const auto sessionId = "luadch-i2p-" + randomHex(12);
            std::string sessionCommand = "SESSION CREATE STYLE=STREAM ID=" + sessionId +
                " DESTINATION=" + privateDestination +
                " SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4 inbound.quantity=" + std::to_string(options.inboundQuantity) +
                " outbound.quantity=" + std::to_string(options.outboundQuantity);
            try {
                requireOk(transact(*socket, sessionCommand, options.sessionTimeout), "SESSION", "STATUS");
            } catch (...) {
                cleanse(sessionCommand);
                throw;
            }
            cleanse(sessionCommand);
            cleanse(privateDestination);

            const auto naming = transact(*socket, "NAMING LOOKUP NAME=ME", options.handshakeTimeout);
            requireOk(naming, "NAMING", "REPLY");
            const auto publicDestination = naming.get("VALUE");
            if (!publicDestination || !isEncodedDestination(*publicDestination)) {
                throw ForwarderException("SAM bridge did not return the active I2P destination");
            }

            status.publicDestination = *publicDestination;
            status.b32Address = destinationToB32(status.publicDestination);

            const auto forwardCommand = "STREAM FORWARD ID=" + sessionId + " HOST=127.0.0.1 PORT=" + std::to_string(options.targetPort);
            requireOk(transact(*socket, forwardCommand, options.sessionTimeout), "STREAM", "STATUS");
            controlSocket = std::move(socket);
            return status;
        } catch (...) {
            cleanse(privateDestination);
            controlSocket.reset();
            status = { };
            throw;
        }
    }

    void stop() noexcept {
        controlSocket.reset();
        status = { };
    }

    bool isStarted() const noexcept {
        return controlSocket && controlSocket->isOpen();
    }

    bool checkBridge(std::chrono::milliseconds aTimeout) {
        return controlSocket && controlSocket->isQuiet(aTimeout);
    }

private:
    ForwarderOptions options;
    std::unique_ptr<LocalSocket> controlSocket;
    ForwarderStatus status;
};

SamForwarder::SamForwarder(ForwarderOptions aOptions) : impl(std::make_unique<Impl>(std::move(aOptions))) { }

SamForwarder::~SamForwarder() noexcept = default;

ForwarderStatus SamForwarder::start() {
    return impl->start();
}

void SamForwarder::stop() noexcept {
    impl->stop();
}

bool SamForwarder::isStarted() const noexcept {
    return impl->isStarted();
}

bool SamForwarder::checkBridge(std::chrono::milliseconds aTimeout) {
    return impl->checkBridge(aTimeout);
}

} // namespace luadch::i2p
