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

// A sample that never connected is reported by cause. The distinction between
// "refused immediately" and "no answer within the deadline" is the point of the
// diagnostic, so it is a separate pure function that tests can pin down.
enum class ConnectFailure {
    Refused,
    NetworkUnreachable,
    HostUnreachable,
    TimedOut,
    Other,
};

inline ConnectFailure classify_connect_failure(int os_error) {
    switch (os_error) {
        case ECONNREFUSED: return ConnectFailure::Refused;
        case ENETUNREACH: return ConnectFailure::NetworkUnreachable;
        case EHOSTUNREACH: return ConnectFailure::HostUnreachable;
        // 0 means the deadline expired without a connect error being set.
        case 0:
        case ETIMEDOUT: return ConnectFailure::TimedOut;
        default: return ConnectFailure::Other;
    }
}

}  // namespace sifrprobe
