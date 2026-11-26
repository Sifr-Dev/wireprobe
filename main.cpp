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

#include "probe.hpp"
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
    // The phase the sample failed in (meaningful only when ok is false) and the
    // cause the kernel or the peer actually delivered. Distinguishing
    // "refused in 0.02 ms" from "no answer in 2000 ms" — and a peer close from
    // a deadline expiry — is the point of the diagnostic.
    sifrprobe::Phase failed_phase = sifrprobe::Phase::Connect;
    sifrprobe::FailureCause cause = sifrprobe::FailureCause::None;
    int os_error = 0;
};

using sifrprobe::parse_positive;
using sifrprobe::parse_target;
using sifrprobe::Target;

void print_duration(const char* label, const sifrprobe::Percentiles& stats) {
    std::printf("  %-10s min %.3f  p50 %.3f  p90 %.3f  p99 %.3f  max %.3f  mean %.3f ms\n",
                label, stats.min, stats.p50, stats.p90, stats.p99, stats.max, stats.mean);
}

void print_json_stats(const char* label, const sifrprobe::Percentiles& stats) {
    std::printf(",\"%s\":{\"min\":%.3f,\"p50\":%.3f,\"p90\":%.3f,\"p99\":%.3f,"
                "\"max\":%.3f,\"mean\":%.3f}",
                label, stats.min, stats.p50, stats.p90, stats.p99, stats.max, stats.mean);
}

using sifrprobe::json_escape;

// Outcome of waiting for a socket event. A deadline expiry and a real select()
// failure are different facts: only the former is a timeout.
enum class WaitStatus {
    Ready,
    TimedOut,
    Failed,
};

// Wait for the socket event, without ever exceeding the remaining deadline.
// Interrupted waits do not consume a separate timeout budget.
WaitStatus wait_for(int fd, bool writing, Clock::time_point deadline) {
    for (;;) {
        const auto now = Clock::now();
        if (now >= deadline) return WaitStatus::TimedOut;
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
        if (rc > 0) return WaitStatus::Ready;
        if (rc == 0) return WaitStatus::TimedOut;
        if (errno != EINTR) return WaitStatus::Failed;
    }
}

// A negative return from connect() only means "in progress" for EINPROGRESS
// (and its platform aliases). Anything else is a definite connect failure and
// must not be retried through SO_ERROR, which would report 0 and be misread as
// a timeout.
bool connect_in_progress(int error) {
    return error == EINPROGRESS || error == EWOULDBLOCK || error == EALREADY;
}

// Returns true when the connect completed successfully. On failure, fills the
// phase/cause the sample ended with.
bool finish_connect(int fd, Clock::time_point deadline, ProbeResult& result) {
    const WaitStatus status = wait_for(fd, true, deadline);
    if (status == WaitStatus::TimedOut) {
        result.failed_phase = sifrprobe::Phase::Connect;
        result.cause = sifrprobe::FailureCause::TimedOut;
        return false;
    }
    if (status == WaitStatus::Failed) {
        result.failed_phase = sifrprobe::Phase::Connect;
        result.os_error = errno;
        result.cause = sifrprobe::classify_connect_failure(errno);
        return false;
    }
    int socket_error = 0;
    socklen_t length = sizeof socket_error;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) != 0) {
        result.failed_phase = sifrprobe::Phase::Connect;
        result.os_error = errno;
        result.cause = sifrprobe::classify_connect_failure(errno);
        return false;
    }
    if (socket_error != 0) {
        result.failed_phase = sifrprobe::Phase::Connect;
        result.os_error = socket_error;
        result.cause = sifrprobe::classify_connect_failure(socket_error);
        return false;
    }
    return true;
}

bool send_all(int fd, const std::string& data, Clock::time_point deadline,
              ProbeResult& result) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const WaitStatus status = wait_for(fd, true, deadline);
        if (status == WaitStatus::TimedOut) {
            result.failed_phase = sifrprobe::Phase::Send;
            result.cause = sifrprobe::FailureCause::TimedOut;
            return false;
        }
        if (status == WaitStatus::Failed) {
            result.failed_phase = sifrprobe::Phase::Send;
            result.os_error = errno;
            result.cause = sifrprobe::classify_socket_error(errno);
            return false;
        }
        const ssize_t sent = send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;  // spurious writability; wait_for() re-checks the deadline
        } else {
            result.failed_phase = sifrprobe::Phase::Send;
            result.os_error = sent == 0 ? 0 : errno;
            result.cause = sifrprobe::classify_socket_error(result.os_error);
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
    if (socket.fd < 0) {
        result.failed_phase = sifrprobe::Phase::Connect;
        result.os_error = errno;
        result.cause = sifrprobe::classify_socket_error(errno);
        return result;
    }
    if (!set_nonblocking(socket.fd)) {
        result.failed_phase = sifrprobe::Phase::Connect;
        result.os_error = errno;
        result.cause = sifrprobe::classify_socket_error(errno);
        return result;
    }

    const auto start = Clock::now();
    const auto deadline = start + std::chrono::milliseconds(timeout_ms);
    if (connect(socket.fd, address.ai_addr, address.ai_addrlen) < 0 &&
        !connect_in_progress(errno)) {
        result.failed_phase = sifrprobe::Phase::Connect;
        result.os_error = errno;
        result.cause = sifrprobe::classify_connect_failure(errno);
        return result;
    }
    if (!finish_connect(socket.fd, deadline, result)) return result;

    const auto connected = Clock::now();
    result.connected = true;
    result.connect_ms = Duration(connected - start).count();
    if (!http) return result;

    const std::string request = sifrprobe::http_get_request(host);
    if (!send_all(socket.fd, request, deadline, result)) return result;

    for (;;) {
        const WaitStatus status = wait_for(socket.fd, false, deadline);
        if (status == WaitStatus::TimedOut) {
            result.failed_phase = sifrprobe::Phase::FirstByte;
            result.cause = sifrprobe::FailureCause::TimedOut;
            return result;
        }
        if (status == WaitStatus::Failed) {
            result.failed_phase = sifrprobe::Phase::FirstByte;
            result.os_error = errno;
            result.cause = sifrprobe::classify_first_byte_failure(errno, false);
            return result;
        }
        char byte;
        const ssize_t received = recv(socket.fd, &byte, 1, 0);
        if (received > 0) {
            result.received_first_byte = true;
            result.first_byte_ms = Duration(Clock::now() - connected).count();
            return result;
        }
        if (received == 0) {
            // A clean FIN before any byte is a peer decision, not a deadline expiry.
            result.failed_phase = sifrprobe::Phase::FirstByte;
            result.cause = sifrprobe::FailureCause::PeerClosed;
            return result;
        }
        if (errno == EINTR) continue;  // a signal must not fake a sample failure
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;  // wait_for() re-checks the deadline
        result.failed_phase = sifrprobe::Phase::FirstByte;
        result.os_error = errno;
        result.cause = sifrprobe::classify_first_byte_failure(errno, false);
        return result;
    }
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
        // Each sample is judged on its own outcome. Cumulative counters must
        // never decide whether *this* sample failed: once one sample fails,
        // comparing running totals to the index would blame every later,
        // successful sample too.
        ProbeResult sample;
        bool attempted = false;
        for (const addrinfo* address = addresses; address != nullptr; address = address->ai_next) {
            attempted = true;
            sample = probe(*address, timeout_ms, http, target.host);
            if (sample.connected) break;  // one address per sample, as before
        }
        if (!attempted) {
            std::fprintf(stderr, "sample %d: no addresses available\n", i + 1);
            continue;
        }
        if (!sample.connected) {
            // Every failure path sets a cause; fall back to a named cause rather
            // than printing an empty diagnostic if one is ever missed.
            const auto cause = sample.cause == sifrprobe::FailureCause::None
                                   ? sifrprobe::FailureCause::Other
                                   : sample.cause;
            std::fprintf(stderr, "sample %d: %s\n", i + 1,
                         sifrprobe::describe_failure(sample.failed_phase, cause,
                                                     sample.os_error, timeout_ms)
                             .c_str());
            continue;
        }
        connects.push_back(sample.connect_ms);
        ++connected;
        if (sample.received_first_byte) {
            first_bytes.push_back(sample.first_byte_ms);
            ++first_byte_ok;
        } else if (http) {
            const auto cause = sample.cause == sifrprobe::FailureCause::None
                                   ? sifrprobe::FailureCause::Other
                                   : sample.cause;
            std::fprintf(stderr, "sample %d: %s\n", i + 1,
                         sifrprobe::describe_failure(sample.failed_phase, cause,
                                                     sample.os_error, timeout_ms)
                             .c_str());
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
