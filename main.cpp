// sifrprobe — zero-dependency TCP and HTTP first-byte latency prober.
//   sifrprobe host[:port] [-n COUNT] [-t TIMEOUT_MS] [--json] [--http]
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "stats.hpp"

namespace {

using Clock = std::chrono::steady_clock;
using Duration = std::chrono::duration<double, std::milli>;

struct Socket {
    int fd = -1;
    explicit Socket(int descriptor) : fd(descriptor) {}
    ~Socket() { if (fd >= 0) close(fd); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};

bool set_nonblocking(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

struct ProbeResult {
    bool connected = false;
    bool received_first_byte = false;
    double connect_ms = 0.0;
    double first_byte_ms = 0.0;
    // errno from the connect attempt, or 0 for a clean timeout. Distinguishing
    // "refused in 0.02 ms" from "no answer in 2000 ms" matters for diagnostics.
    int os_error = 0;
};

struct Target {
    std::string text;
    std::string host;
    std::string port;
    bool explicit_port = false;
};

bool parse_positive(const char* text, int& value) {
    const char* const end = text + std::strlen(text);
    const auto result = std::from_chars(text, end, value);
    return result.ec == std::errc{} && result.ptr == end && value > 0;
}

bool parse_target(const std::string& text, Target& target) {
    target.text = text;
    if (text.empty()) return false;

    // A single colon separates a host and port. Literal IPv6 addresses use
    // [address]:port; without brackets there is no unambiguous port separator.
    const std::size_t closing = text.back() == ']' ? text.size() - 1 : text.find(']');
    if (text.front() == '[') {
        if (closing == std::string::npos) return false;
        target.host = text.substr(1, closing - 1);
        if (closing + 1 == text.size()) return !target.host.empty();
        if (text[closing + 1] != ':') return false;
        target.port = text.substr(closing + 2);
        target.explicit_port = true;
        return !target.host.empty() && !target.port.empty();
    }

    if (text.find('[') != std::string::npos || closing != std::string::npos) return false;
    const std::size_t colon = text.rfind(':');
    if (colon != std::string::npos && text.find(':') == colon) {
        target.host = text.substr(0, colon);
        target.port = text.substr(colon + 1);
        target.explicit_port = true;
    } else {
        target.host = text;
    }
    return !target.host.empty() && !target.port.empty();
}

void print_duration(const char* label, const sifrprobe::Percentiles& stats) {
    std::printf("  %-10s min %.3f  p50 %.3f  p90 %.3f  p99 %.3f  max %.3f  mean %.3f ms\n",
                label, stats.min, stats.p50, stats.p90, stats.p99, stats.max, stats.mean);
}

void print_json_stats(const char* label, const sifrprobe::Percentiles& stats) {
    std::printf(",\"%s\":{\"min\":%.3f,\"p50\":%.3f,\"p90\":%.3f,\"p99\":%.3f,"
                "\"max\":%.3f,\"mean\":%.3f}",
                label, stats.min, stats.p50, stats.p90, stats.p99, stats.max, stats.mean);
}

std::string json_escape(const std::string& text) {
    std::string escaped;
    for (const unsigned char byte : text) {
        switch (byte) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (byte < 0x20U) {
                    char encoded[7];
                    std::snprintf(encoded, sizeof encoded, "\\u%04x", byte);
                    escaped += encoded;
                } else {
                    escaped += static_cast<char>(byte);
                }
        }
    }
    return escaped;
}

// Wait for the socket event, without ever exceeding the remaining deadline.
// Interrupted waits do not consume a separate timeout budget.
bool wait_for(int fd, bool writing, Clock::time_point deadline) {
    for (;;) {
        const auto now = Clock::now();
        if (now >= deadline) return false;
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        const auto microseconds = std::max<std::chrono::microseconds::rep>(1, remaining.count());
        timeval timeout{
            static_cast<time_t>(microseconds / 1'000'000),
            static_cast<suseconds_t>(microseconds % 1'000'000)
        };
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        const int rc = select(fd + 1, writing ? nullptr : &fds,
                              writing ? &fds : nullptr, nullptr, &timeout);
        if (rc > 0) return true;
        if (rc == 0) return false;
        if (errno != EINTR) return false;
    }
}

bool finish_connect(int fd, Clock::time_point deadline, int& os_error) {
    if (!wait_for(fd, true, deadline)) return false;  // timeout; os_error stays 0
    socklen_t length = sizeof os_error;
    return getsockopt(fd, SOL_SOCKET, SO_ERROR, &os_error, &length) == 0 && os_error == 0;
}

bool send_all(int fd, const std::string& data, Clock::time_point deadline) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        if (!wait_for(fd, true, deadline)) return false;
        const ssize_t sent = send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

// A sample's connect and first-byte timers share one deadline. This makes the
// HTTP timeout a whole-operation timeout, not a fresh timeout for every phase.
ProbeResult probe(const addrinfo& address, int timeout_ms, bool http,
                  const std::string& host) {
    ProbeResult result;
    Socket socket{::socket(address.ai_family, address.ai_socktype, address.ai_protocol)};
    if (socket.fd < 0 || !set_nonblocking(socket.fd)) return result;

    const auto start = Clock::now();
    const auto deadline = start + std::chrono::milliseconds(timeout_ms);
    int connect_error = 0;
    if (connect(socket.fd, address.ai_addr, address.ai_addrlen) < 0 && errno != EINPROGRESS) {
        connect_error = errno;
    } else if (!finish_connect(socket.fd, deadline, connect_error)) {
        if (connect_error == 0) connect_error = ETIMEDOUT;
        return result;
    }
    if (connect_error != 0) {
        result.os_error = connect_error;
        return result;
    }

    const auto connected = Clock::now();
    result.connected = true;
    result.connect_ms = Duration(connected - start).count();
    if (!http) return result;

    const std::string request = "GET / HTTP/1.0\r\nHost: " + host +
                                "\r\nConnection: close\r\n\r\n";
    if (!send_all(socket.fd, request, deadline)) return result;
    if (!wait_for(socket.fd, false, deadline)) return result;

    char byte;
    const ssize_t received = recv(socket.fd, &byte, 1, 0);
    if (received > 0) {
        result.received_first_byte = true;
        result.first_byte_ms = Duration(Clock::now() - connected).count();
    } else if (received < 0 && errno == EINTR) {
        // Rare, but a signal must not turn a connected socket into a fake sample.
        if (wait_for(socket.fd, false, deadline)) {
            const ssize_t retry = recv(socket.fd, &byte, 1, 0);
            if (retry > 0) {
                result.received_first_byte = true;
                result.first_byte_ms = Duration(Clock::now() - connected).count();
            }
        }
    }
    return result;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: sifrprobe host[:port] [-n COUNT] [-t TIMEOUT_MS] [--http] [--json]\n"
                     "       sifrprobe [IPv6-address]:port ...\n");
        return 2;
    }

    Target target;
    if (!parse_target(argv[1], target)) {
        std::fprintf(stderr, "invalid target: %s\n", argv[1]);
        return 2;
    }
    int count = 10;
    int timeout_ms = 2000;
    bool http = false;
    bool json = false;
    for (int i = 2; i < argc; ++i) {
        if (!std::strcmp(argv[i], "-n") && i + 1 < argc && parse_positive(argv[i + 1], count)) {
            ++i;
        } else if (!std::strcmp(argv[i], "-t") && i + 1 < argc && parse_positive(argv[i + 1], timeout_ms)) {
            ++i;
        } else if (!std::strcmp(argv[i], "--http")) {
            http = true;
        } else if (!std::strcmp(argv[i], "--json")) {
            json = true;
        } else {
            std::fprintf(stderr, "invalid argument: %s\n", argv[i]);
            return 2;
        }
    }
    if (count > 1'000'000) {
        std::fprintf(stderr, "count exceeds 1000000\n");
        return 2;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* addresses = nullptr;
    const int resolve_error = getaddrinfo(target.host.c_str(), target.port.c_str(), &hints, &addresses);
    if (resolve_error != 0) {
        std::fprintf(stderr, "resolve failed: %s: %s\n", target.host.c_str(), gai_strerror(resolve_error));
        return 1;
    }

    std::vector<double> connects;
    std::vector<double> first_bytes;
    connects.reserve(static_cast<std::size_t>(count));
    first_bytes.reserve(static_cast<std::size_t>(count));
    int connected = 0;
    int first_byte_ok = 0;
    for (int i = 0; i < count; ++i) {
        bool any_address = false;
        int last_error = 0;
        for (const addrinfo* address = addresses; address != nullptr; address = address->ai_next) {
            any_address = true;
            const ProbeResult sample = probe(*address, timeout_ms, http, target.host);
            if (!sample.connected) {
                last_error = sample.os_error;
                continue;
            }
            connects.push_back(sample.connect_ms);
            ++connected;
            if (sample.received_first_byte) {
                first_bytes.push_back(sample.first_byte_ms);
                ++first_byte_ok;
            }
            break;
        }
        if (connected + (http ? 0 : 0) <= i && !any_address) {
            std::fprintf(stderr, "sample %d: no addresses available\n", i + 1);
        } else if (connected <= i || (http && first_byte_ok < connected)) {
            if (last_error == ECONNREFUSED) {
                std::fprintf(stderr, "sample %d: connection refused\n", i + 1);
            } else if (last_error == ENETUNREACH || last_error == EHOSTUNREACH) {
                std::fprintf(stderr, "sample %d: %s\n", i + 1,
                             last_error == ENETUNREACH ? "network unreachable" : "host unreachable");
            } else if (last_error == ETIMEDOUT || last_error == 0) {
                std::fprintf(stderr, "sample %d: %s timed out after %d ms\n",
                             i + 1, http ? "connect or first-byte" : "connect", timeout_ms);
            } else {
                std::fprintf(stderr, "sample %d: connect failed: %s\n",
                             i + 1, std::strerror(last_error));
            }
        }
    }
    freeaddrinfo(addresses);

    // TCP-only samples are successful when connect completes. HTTP samples are
    // successful only when a byte arrives, regardless of whether it is valid HTTP.
    const int ok = http ? first_byte_ok : connected;
    const auto c = sifrprobe::summarize(connects);
    const auto f = sifrprobe::summarize(first_bytes);
    if (json) {
        std::printf("{\"target\":\"%s\",\"count\":%d,\"ok\":%d,"
                    "\"connected\":%d,\"first_byte_ok\":%d",
                    json_escape(target.text).c_str(), count, ok, connected, first_byte_ok);
        print_json_stats("connect", c);
        if (http) print_json_stats("first_byte", f);
        std::printf("}\n");
    } else {
        std::printf("sifrprobe %s  ok=%d/%d connected=%d", target.text.c_str(), ok, count, connected);
        if (http) std::printf(" first_byte_ok=%d", first_byte_ok);
        std::printf("\n");
        print_duration("connect", c);
        if (http) print_duration("first_byte", f);
    }

    // Partial HTTP success is nonzero: transport connectivity alone is not a
    // successful request, and scripting should not hide a failed sample.
    return ok == count ? 0 : 1;
}
