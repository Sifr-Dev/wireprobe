#pragma once

// Pure, network-free pieces of sifrprobe: argument/target parsing, JSON string
// escaping, and the errno-to-diagnostic mapping. Kept separate from main.cpp so
// they can be exercised by the deterministic test harness (tests/verify.cpp)
// without opening a socket.

#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>

namespace sifrprobe {

struct Target {
    std::string text;
    std::string host;
    std::string port;
    bool explicit_port = false;
};

inline bool parse_positive(const char* text, int& value) {
    const char* const end = text + std::strlen(text);
    const auto result = std::from_chars(text, end, value);
    return result.ec == std::errc{} && result.ptr == end && value > 0;
}

inline bool parse_target(const std::string& text, Target& target) {
    // Reset every field: a reused Target must not inherit the port (or the
    // explicit_port flag) of a previous parse, which would make a bare host
    // look like it carried a port and be accepted.
    target = Target{};
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

inline std::string json_escape(const std::string& text) {
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

// The probe speaks HTTP/1.0 with Connection: close so the server ends the
// response after the body. Request framing is a fixed byte sequence, which is
// exactly the kind of protocol detail a test can pin down without a socket.
inline std::string http_get_request(const std::string& host) {
    return "GET / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
}

// A failed sample is reported by the phase it failed in and the cause the
// kernel actually delivered. A timeout is only ever the absence of an event;
// an EOF or a reset is a real answer from the peer and must not be folded into
// "timed out". Both the mapping and its rendering are pure functions so tests
// can pin them down without a socket.
enum class Phase {
    Connect,
    Send,
    FirstByte,
};

enum class FailureCause {
    None,
    Refused,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionReset,
    PeerClosed,
    TimedOut,
    Other,
};

inline FailureCause classify_socket_error(int os_error) {
    switch (os_error) {
        case ECONNREFUSED: return FailureCause::Refused;
        case ENETUNREACH: return FailureCause::NetworkUnreachable;
        case EHOSTUNREACH: return FailureCause::HostUnreachable;
        case ECONNRESET:
        case EPIPE: return FailureCause::ConnectionReset;
        case ETIMEDOUT: return FailureCause::TimedOut;
        default: return FailureCause::Other;
    }
}

// Maps a real connect errno to a cause. There is deliberately no "errno 0 means
// timed out" rule: zero is not an error, and treating it as a timeout is the
// exact sentinel that used to make a peer close look like a deadline expiry.
// A timeout is set by the caller that observed the deadline expire, never
// inferred from a missing error.
inline FailureCause classify_connect_failure(int os_error) {
    if (os_error == 0) return FailureCause::None;
    return classify_socket_error(os_error);
}

// recv() == 0 means the peer closed cleanly after the request was sent: that
// is a definite response, not a timeout. A non-zero errno is the kernel's
// verdict on the connection.
inline FailureCause classify_first_byte_failure(int os_error, bool peer_closed) {
    if (peer_closed) return FailureCause::PeerClosed;
    if (os_error == 0) return FailureCause::Other;
    return classify_socket_error(os_error);
}

inline const char* failure_cause_key(FailureCause cause) {
    switch (cause) {
        case FailureCause::None: return "none";
        case FailureCause::Refused: return "refused";
        case FailureCause::NetworkUnreachable: return "network_unreachable";
        case FailureCause::HostUnreachable: return "host_unreachable";
        case FailureCause::ConnectionReset: return "connection_reset";
        case FailureCause::PeerClosed: return "peer_closed";
        case FailureCause::TimedOut: return "timed_out";
        case FailureCause::Other: return "other";
    }
    return "other";
}

inline std::string describe_failure(Phase phase, FailureCause cause, int os_error,
                                    int timeout_ms) {
    if (cause == FailureCause::None) return {};
    const std::string after = std::to_string(timeout_ms) + " ms";
    if (phase == Phase::Connect) {
        switch (cause) {
            case FailureCause::Refused: return "connection refused";
            case FailureCause::NetworkUnreachable: return "network unreachable";
            case FailureCause::HostUnreachable: return "host unreachable";
            case FailureCause::ConnectionReset: return "connection reset while connecting";
            case FailureCause::TimedOut: return "connect timed out after " + after;
            case FailureCause::PeerClosed: return "connection closed by peer while connecting";
            case FailureCause::Other:
                return "connect failed: " +
                       (os_error != 0 ? std::strerror(os_error) : std::string("unknown error"));
            case FailureCause::None: break;
        }
    }
    switch (cause) {
        case FailureCause::PeerClosed: return "connection closed by peer before first byte";
        case FailureCause::ConnectionReset: return "connection reset by peer before first byte";
        case FailureCause::TimedOut:
            return (phase == Phase::Send ? "request send timed out after "
                                         : "first byte timed out after ") +
                   after;
        case FailureCause::Refused: return "connection refused before first byte";
        case FailureCause::NetworkUnreachable: return "network unreachable before first byte";
        case FailureCause::HostUnreachable: return "host unreachable before first byte";
        case FailureCause::Other:
            return std::string(phase == Phase::Send ? "request send failed: "
                                                    : "first byte failed: ") +
                   (os_error != 0 ? std::strerror(os_error) : std::string("unknown error"));
        case FailureCause::None: break;
    }
    return {};
}

}  // namespace sifrprobe
