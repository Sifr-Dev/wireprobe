// sifrprobe deterministic verification harness.
//
//   verify [path-to-sifrprobe]
//
// Exercises the real, network-free logic used by the prober: percentile
// statistics, target/argument parsing, JSON escaping, HTTP request framing,
// connect-failure classification, and the CLI's argument-error exit path.
// Nothing here opens a socket or resolves a name. If a path to the built
// binary is supplied, the CLI checks run against that binary with inputs that
// are rejected before any DNS or connect call.
//
// Exit status: 0 when every check passes, 1 otherwise.

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "../probe.hpp"
#include "../stats.hpp"

namespace {

int g_checks = 0;
int g_failures = 0;
const char* g_section = "";

void section(const char* name) {
    g_section = name;
    std::printf("\n[%s]\n", name);
}

void check(bool condition, const char* expression, int line) {
    ++g_checks;
    if (condition) return;
    ++g_failures;
    std::printf("  FAIL %s:%d  %s\n", g_section, line, expression);
}

#define CHECK(expr) check((expr), #expr, __LINE__)

bool close_enough(double actual, double expected) {
    const double delta = actual - expected;
    return (delta < 0 ? -delta : delta) < 1e-9;
}

void expect_stats(const std::vector<double>& values, double min, double p50,
                  double p90, double p99, double max, double mean) {
    const auto stats = sifrprobe::summarize(values);
    CHECK(close_enough(stats.min, min));
    CHECK(close_enough(stats.p50, p50));
    CHECK(close_enough(stats.p90, p90));
    CHECK(close_enough(stats.p99, p99));
    CHECK(close_enough(stats.max, max));
    CHECK(close_enough(stats.mean, mean));
}

void test_stats() {
    section("stats: empty and single-sample inputs");
    expect_stats({}, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    expect_stats({5.0}, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0);
    expect_stats({0.25}, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25);

    section("stats: nearest-order-statistic percentiles");
    // n = 10, index = round(q * (n - 1)).
    expect_stats({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 1.0, 6.0, 9.0, 10.0, 10.0, 5.5);
    // n = 4: p50 -> index 2, p90/p99 -> index 3.
    expect_stats({10, 20, 30, 40}, 10.0, 30.0, 40.0, 40.0, 40.0, 25.0);
    // n = 2: p50 -> index 1 (upper of the pair).
    expect_stats({1, 2}, 1.0, 2.0, 2.0, 2.0, 2.0, 1.5);
    // n = 3, duplicates collapse to the same order statistic.
    expect_stats({7, 7, 7}, 7.0, 7.0, 7.0, 7.0, 7.0, 7.0);

    section("stats: input order must not matter and input must not be mutated");
    std::vector<double> shuffled{9, 1, 8, 2, 7, 3, 6, 4, 5, 0};
    const std::vector<double> original = shuffled;
    const auto sorted_stats = sifrprobe::summarize(shuffled);
    CHECK(shuffled == original);  // summarize() must work on a copy
    CHECK(close_enough(sorted_stats.min, 0.0));
    CHECK(close_enough(sorted_stats.p50, 5.0));
    CHECK(close_enough(sorted_stats.max, 9.0));
    CHECK(close_enough(sorted_stats.mean, 4.5));

    section("stats: monotonic percentiles on a deterministic 1000-sample set");
    std::vector<double> many;
    many.reserve(1000);
    unsigned int state = 12345U;  // fixed LCG seed: no wall clock, no rand()
    for (int i = 0; i < 1000; ++i) {
        state = state * 1664525U + 1013904223U;
        many.push_back(static_cast<double>(state % 10000U) / 8.0);
    }
    const auto m = sifrprobe::summarize(many);
    CHECK(m.min <= m.p50);
    CHECK(m.p50 <= m.p90);
    CHECK(m.p90 <= m.p99);
    CHECK(m.p99 <= m.max);
    CHECK(m.min <= m.mean && m.mean <= m.max);
    // A constant series has zero spread regardless of sample count.
    expect_stats(std::vector<double>(1000, 3.5), 3.5, 3.5, 3.5, 3.5, 3.5, 3.5);
}

void test_parse_positive() {
    section("parse_positive: accepts only a full positive decimal integer");
    int value = 0;
    CHECK(sifrprobe::parse_positive("1", value) && value == 1);
    CHECK(sifrprobe::parse_positive("20", value) && value == 20);
    CHECK(sifrprobe::parse_positive("1000000", value) && value == 1000000);
    CHECK(!sifrprobe::parse_positive("0", value));
    CHECK(!sifrprobe::parse_positive("-1", value));
    CHECK(!sifrprobe::parse_positive("+5", value));
    CHECK(!sifrprobe::parse_positive("abc", value));
    CHECK(!sifrprobe::parse_positive("10x", value));
    CHECK(!sifrprobe::parse_positive("", value));
    CHECK(!sifrprobe::parse_positive(" 10", value));
    CHECK(!sifrprobe::parse_positive("9999999999999999999999", value));  // out of range
}

void test_parse_target() {
    section("parse_target: host:port forms");
    sifrprobe::Target target;

    CHECK(sifrprobe::parse_target("example.com:80", target));
    CHECK(target.text == "example.com:80");
    CHECK(target.host == "example.com");
    CHECK(target.port == "80");
    CHECK(target.explicit_port);

    CHECK(sifrprobe::parse_target("127.0.0.1:8899", target));
    CHECK(target.host == "127.0.0.1");
    CHECK(target.port == "8899");

    CHECK(sifrprobe::parse_target("localhost:http", target));  // service names
    CHECK(target.port == "http");

    section("parse_target: bracketed IPv6");
    CHECK(sifrprobe::parse_target("[::1]:8080", target));
    CHECK(target.host == "::1");
    CHECK(target.port == "8080");
    CHECK(target.explicit_port);

    CHECK(sifrprobe::parse_target("[fe80::1%eth0]:443", target));
    CHECK(target.host == "fe80::1%eth0");
    CHECK(target.port == "443");

    // Bracketed IPv6 without a port is accepted with no explicit port.
    CHECK(sifrprobe::parse_target("[::1]", target));
    CHECK(target.host == "::1");
    CHECK(target.port.empty());
    CHECK(!target.explicit_port);

    section("parse_target: rejected inputs leave no ambiguous host/port split");
    // Documented behaviour today: a bare host without a port is rejected by
    // parse_target even though the usage string reads host[:port].
    CHECK(!sifrprobe::parse_target("example.com", target));
    CHECK(!sifrprobe::parse_target("", target));
    CHECK(!sifrprobe::parse_target(":80", target));
    CHECK(!sifrprobe::parse_target("host:", target));
    CHECK(!sifrprobe::parse_target("[::1", target));
    CHECK(!sifrprobe::parse_target("[]", target));
    CHECK(!sifrprobe::parse_target("[::1]x", target));
    CHECK(!sifrprobe::parse_target("[::1]:", target));
    CHECK(!sifrprobe::parse_target("host:80:90", target));  // unbracketed multi-colon
    CHECK(!sifrprobe::parse_target("a]b", target));
    CHECK(!sifrprobe::parse_target("[a]b]c", target));
}

void test_json_escape() {
    section("json_escape: JSON-safe strings");
    CHECK(sifrprobe::json_escape("plain") == "plain");
    CHECK(sifrprobe::json_escape("a\"b\\c") == "a\\\"b\\\\c");
    CHECK(sifrprobe::json_escape("\b\f\n\r\t") == "\\b\\f\\n\\r\\t");
    CHECK(sifrprobe::json_escape("\x01\x1f") == "\\u0001\\u001f");
    CHECK(sifrprobe::json_escape(std::string("\x7f", 1)) == std::string("\x7f", 1));  // DEL is not a JSON escape
    CHECK(sifrprobe::json_escape("host:80") == "host:80");
    CHECK(sifrprobe::json_escape("") == "");
    // Bytes >= 0x80 are passed through unchanged (valid UTF-8 stays intact).
    CHECK(sifrprobe::json_escape("caf\xc3\xa9") == "caf\xc3\xa9");
}

void test_http_request() {
    section("http_get_request: exact HTTP/1.0 framing");
    const std::string request = sifrprobe::http_get_request("example.com");
    CHECK(request == "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    CHECK(request.find("\r\n\r\n") == request.size() - 4);  // exactly one blank-line terminator
    CHECK(request.find("Host: example.com") != std::string::npos);
    CHECK(request.find("\n\n") == std::string::npos);      // every newline is CRLF
}

void test_connect_failure() {
    section("classify_connect_failure: diagnostics map to causes");
    CHECK(sifrprobe::classify_connect_failure(ECONNREFUSED) == sifrprobe::FailureCause::Refused);
    CHECK(sifrprobe::classify_connect_failure(ENETUNREACH) == sifrprobe::FailureCause::NetworkUnreachable);
    CHECK(sifrprobe::classify_connect_failure(EHOSTUNREACH) == sifrprobe::FailureCause::HostUnreachable);
    CHECK(sifrprobe::classify_connect_failure(ETIMEDOUT) == sifrprobe::FailureCause::TimedOut);
    // Zero is not an error: it must never be interpreted as a timeout. Timeouts
    // are set by the caller that watched the deadline expire.
    CHECK(sifrprobe::classify_connect_failure(0) == sifrprobe::FailureCause::None);
    CHECK(sifrprobe::classify_connect_failure(ECONNRESET) == sifrprobe::FailureCause::ConnectionReset);
    CHECK(sifrprobe::classify_connect_failure(EACCES) == sifrprobe::FailureCause::Other);
    CHECK(sifrprobe::classify_connect_failure(EMFILE) == sifrprobe::FailureCause::Other);

    section("classify_first_byte_failure: a peer that closes is not a timeout");
    // The whole point: recv()==0 is a definite answer, and errno==0 without a
    // peer close must not be silently promoted to TimedOut either.
    CHECK(sifrprobe::classify_first_byte_failure(0, true) == sifrprobe::FailureCause::PeerClosed);
    CHECK(sifrprobe::classify_first_byte_failure(ECONNRESET, true) == sifrprobe::FailureCause::PeerClosed);
    CHECK(sifrprobe::classify_first_byte_failure(ECONNRESET, false) == sifrprobe::FailureCause::ConnectionReset);
    CHECK(sifrprobe::classify_first_byte_failure(0, false) != sifrprobe::FailureCause::TimedOut);
    CHECK(sifrprobe::classify_first_byte_failure(ETIMEDOUT, false) == sifrprobe::FailureCause::TimedOut);

    section("describe_failure: phase and cause survive to the operator");
    const auto connect_timeout = sifrprobe::describe_failure(
        sifrprobe::Phase::Connect, sifrprobe::FailureCause::TimedOut, 0, 2000);
    CHECK(connect_timeout.find("connect timed out") != std::string::npos);
    CHECK(connect_timeout.find("2000") != std::string::npos);
    const auto first_byte_timeout = sifrprobe::describe_failure(
        sifrprobe::Phase::FirstByte, sifrprobe::FailureCause::TimedOut, 0, 300);
    CHECK(first_byte_timeout.find("first byte timed out") != std::string::npos);
    CHECK(first_byte_timeout.find("300") != std::string::npos);
    const auto send_timeout = sifrprobe::describe_failure(
        sifrprobe::Phase::Send, sifrprobe::FailureCause::TimedOut, 0, 300);
    CHECK(send_timeout.find("request send timed out") != std::string::npos);
    CHECK(send_timeout.find("first byte") == std::string::npos);
    const auto peer_closed = sifrprobe::describe_failure(
        sifrprobe::Phase::FirstByte, sifrprobe::FailureCause::PeerClosed, 0, 300);
    CHECK(peer_closed.find("closed by peer") != std::string::npos);
    CHECK(peer_closed.find("timed out") == std::string::npos);
    const auto reset = sifrprobe::describe_failure(
        sifrprobe::Phase::FirstByte, sifrprobe::FailureCause::ConnectionReset, ECONNRESET, 300);
    CHECK(reset.find("reset") != std::string::npos);
    CHECK(reset.find("timed out") == std::string::npos);
    for (const auto cause : {sifrprobe::FailureCause::Refused,
                             sifrprobe::FailureCause::NetworkUnreachable,
                             sifrprobe::FailureCause::HostUnreachable,
                             sifrprobe::FailureCause::ConnectionReset,
                             sifrprobe::FailureCause::PeerClosed,
                             sifrprobe::FailureCause::TimedOut,
                             sifrprobe::FailureCause::Other}) {
        CHECK(std::strlen(sifrprobe::failure_cause_key(cause)) > 0);
        CHECK(sifrprobe::describe_failure(sifrprobe::Phase::Connect, cause, ECONNREFUSED, 10) !=
              std::string());
        CHECK(sifrprobe::describe_failure(sifrprobe::Phase::FirstByte, cause, ECONNREFUSED, 10) !=
              std::string());
    }
    CHECK(sifrprobe::describe_failure(sifrprobe::Phase::Connect,
                                      sifrprobe::FailureCause::None, 0, 10)
              .empty());
}

// --- Loopback fixtures -------------------------------------------------------
//
// These drive the real binary against a real kernel socket on 127.0.0.1, which
// is the only way to prove how a peer FIN and a peer RST are classified. The
// server runs in a child process on an ephemeral port it reports back through a
// pipe, so there is no fixed port to collide with and no external network.

enum class ServerMode {
    CloseImmediately,  // accept, then FIN without reading or writing
    ResetImmediately,  // accept, then abortive close (RST, SO_LINGER 0)
    CloseAfterRequest, // read the request, then FIN with no response byte
    SendOneByte,       // accept, write one byte (a "first byte" success)
    StaySilent,        // accept, hold the connection open past the deadline
    CloseFirstThenSendBytes,  // connection 1: FIN; connections 2..n: one byte each
};

// Start a loopback server. Returns the child pid, or -1. `connections` is how
// many accepts the fixture serves before exiting; tests pass the sample count.
// The child is left running; stop_loopback_server() reaps it.
pid_t start_loopback_server(ServerMode mode, int& port, int connections = 1) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0 ||
        listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    socklen_t length = sizeof address;
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        close(fd);
        return -1;
    }
    port = ntohs(address.sin_port);

    int ready[2];
    if (pipe(ready) != 0) {
        close(fd);
        return -1;
    }
    const pid_t pid = fork();
    if (pid < 0) {
        close(fd);
        close(ready[0]);
        close(ready[1]);
        return -1;
    }
    if (pid == 0) {
        close(ready[0]);
        const char go = '1';
        if (write(ready[1], &go, 1) != 1) _exit(1);
        close(ready[1]);
        int served = 0;
        for (int i = 0; i < connections; ++i) {
            const int client = accept(fd, nullptr, nullptr);
            if (client < 0) break;
            ++served;
            const bool close_this_one =
                mode == ServerMode::CloseImmediately ||
                mode == ServerMode::CloseAfterRequest ||
                (mode == ServerMode::CloseFirstThenSendBytes && i == 0);
            if (mode == ServerMode::ResetImmediately) {
                linger abortive{};
                abortive.l_onoff = 1;
                abortive.l_linger = 0;
                setsockopt(client, SOL_SOCKET, SO_LINGER, &abortive, sizeof abortive);
            } else if (close_this_one) {
                if (mode == ServerMode::CloseAfterRequest) {
                    char buffer[512];
                    // Drain the request so the FIN is delivered after the client sent it.
                    while (recv(client, buffer, sizeof buffer, 0) > 0) {
                        if (std::strstr(buffer, "\r\n\r\n") != nullptr) break;
                    }
                }
            } else if (mode == ServerMode::SendOneByte ||
                       mode == ServerMode::CloseFirstThenSendBytes) {
                const char byte = 'H';
                (void)!write(client, &byte, 1);
            } else if (mode == ServerMode::StaySilent) {
                // Hold the connection well past any deadline the tests use, then
                // let the closing FD release the client.
                poll(nullptr, 0, 500);
            }
            close(client);
        }
        close(fd);
        (void)served;
        _exit(0);
    }
    close(fd);
    close(ready[1]);
    char go = 0;
    const bool started = read(ready[0], &go, 1) == 1;
    close(ready[0]);
    return started ? pid : -1;
}

void stop_loopback_server(pid_t pid) {
    if (pid <= 0) return;
    int status = 0;
    waitpid(pid, &status, 0);
}

// Run the prober against the fixture and capture both streams.
struct CliRun {
    int status = -1;
    std::string stderr_text;
    std::string stdout_text;
};

CliRun run_cli_capture_all(const std::string& binary, std::vector<const char*> argv) {
    argv.push_back(nullptr);
    int out[2];
    int err[2];
    if (pipe(out) != 0) return {};
    if (pipe(err) != 0) {
        close(out[0]);
        close(out[1]);
        return {};
    }
    const pid_t pid = fork();
    if (pid < 0) {
        for (int fd : {out[0], out[1], err[0], err[1]}) close(fd);
        return {};
    }
    if (pid == 0) {
        dup2(out[1], STDOUT_FILENO);
        dup2(err[1], STDERR_FILENO);
        for (int fd : {out[0], out[1], err[0], err[1]}) close(fd);
        execv(binary.c_str(), const_cast<char* const*>(argv.data()));
        _exit(127);
    }
    close(out[1]);
    close(err[1]);
    CliRun run;
    char buffer[512];
    ssize_t got = 0;
    while ((got = read(out[0], buffer, sizeof buffer)) > 0) run.stdout_text.append(buffer, got);
    while ((got = read(err[0], buffer, sizeof buffer)) > 0) run.stderr_text.append(buffer, got);
    close(out[0]);
    close(err[0]);
    int status = 0;
    if (waitpid(pid, &status, 0) == pid && WIFEXITED(status)) run.status = WEXITSTATUS(status);
    return run;
}

void test_loopback_http_classification(const char* binary) {
    section("loopback: a peer FIN before the first byte is 'closed by peer', not a timeout");
    {
        int port = 0;
        const pid_t server = start_loopback_server(ServerMode::CloseImmediately, port);
        CHECK(server > 0);
        if (server > 0) {
            const std::string target = "127.0.0.1:" + std::to_string(port);
            const CliRun run = run_cli_capture_all(
                binary, {"sifrprobe", target.c_str(), "-n", "1", "-t", "1500", "--http"});
            stop_loopback_server(server);
            CHECK(run.status == 1);
            CHECK(run.stdout_text.find("connected=1") != std::string::npos);
            CHECK(run.stdout_text.find("first_byte_ok=0") != std::string::npos);
            const bool closed = run.stderr_text.find("closed by peer") != std::string::npos;
            const bool reset = run.stderr_text.find("reset by peer") != std::string::npos;
            CHECK(closed || reset);
            // The failure was a peer decision, so it must not be blamed on the clock.
            CHECK(run.stderr_text.find("timed out") == std::string::npos);
            std::printf("  observed diagnostic: %s", run.stderr_text.c_str());
        }
    }

    section("loopback: an abortive close (RST) is diagnosed as a reset, not a timeout");
    {
        int port = 0;
        const pid_t server = start_loopback_server(ServerMode::ResetImmediately, port);
        CHECK(server > 0);
        if (server > 0) {
            const std::string target = "127.0.0.1:" + std::to_string(port);
            const CliRun run = run_cli_capture_all(
                binary, {"sifrprobe", target.c_str(), "-n", "1", "-t", "1500", "--http"});
            stop_loopback_server(server);
            CHECK(run.status == 1);
            CHECK(run.stderr_text.find("reset") != std::string::npos);
            CHECK(run.stderr_text.find("timed out") == std::string::npos);
            std::printf("  observed diagnostic: %s", run.stderr_text.c_str());
        }
    }

    section("loopback: a vivid close after the request is still a peer close");
    {
        int port = 0;
        const pid_t server = start_loopback_server(ServerMode::CloseAfterRequest, port);
        CHECK(server > 0);
        if (server > 0) {
            const std::string target = "127.0.0.1:" + std::to_string(port);
            const CliRun run = run_cli_capture_all(
                binary, {"sifrprobe", target.c_str(), "-n", "1", "-t", "1500", "--http"});
            stop_loopback_server(server);
            CHECK(run.status == 1);
            CHECK(run.stderr_text.find("closed by peer") != std::string::npos);
            CHECK(run.stderr_text.find("timed out") == std::string::npos);
        }
    }

    section("loopback: only the failing sample is blamed, not every later one");
    {
        // Sample 1 gets a FIN before any byte; samples 2 and 3 get a byte.
        // Before the per-sample fix, `connected <= i` compared running totals to
        // the sample index, so one early failure made stderr claim all three
        // samples had failed. Exactly one diagnostic line is correct.
        int port = 0;
        const pid_t server = start_loopback_server(ServerMode::CloseFirstThenSendBytes, port, 3);
        CHECK(server > 0);
        if (server > 0) {
            const std::string target = "127.0.0.1:" + std::to_string(port);
            const CliRun run = run_cli_capture_all(
                binary, {"sifrprobe", target.c_str(), "-n", "3", "-t", "1500", "--http"});
            stop_loopback_server(server);
            CHECK(run.status == 1);
            CHECK(run.stdout_text.find("ok=2/3") != std::string::npos);
            CHECK(run.stdout_text.find("connected=3") != std::string::npos);
            CHECK(run.stdout_text.find("first_byte_ok=2") != std::string::npos);
            // Count "sample " diagnostic lines: exactly one sample failed.
            int blamed = 0;
            std::size_t at = run.stderr_text.find("sample ");
            while (at != std::string::npos) {
                ++blamed;
                at = run.stderr_text.find("sample ", at + 1);
            }
            CHECK(blamed == 1);
            const bool first = run.stderr_text.find("sample 1:") != std::string::npos;
            CHECK(first);
            CHECK(run.stderr_text.find("sample 2:") == std::string::npos);
            CHECK(run.stderr_text.find("sample 3:") == std::string::npos);
            std::printf("  observed diagnostics: %s", run.stderr_text.c_str());
        }
    }

    section("loopback: a holding peer hits the deadline and reports first-byte timeout");
    {
        int port = 0;
        const pid_t server = start_loopback_server(ServerMode::StaySilent, port);
        CHECK(server > 0);
        if (server > 0) {
            const std::string target = "127.0.0.1:" + std::to_string(port);
            const auto started = std::chrono::steady_clock::now();
            const CliRun run = run_cli_capture_all(
                binary, {"sifrprobe", target.c_str(), "-n", "1", "-t", "250", "--http"});
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started)
                                     .count();
            stop_loopback_server(server);
            CHECK(run.status == 1);
            CHECK(run.stderr_text.find("first byte timed out") != std::string::npos);
            // The whole-operation deadline is honoured within a loose bound.
            CHECK(elapsed >= 200 && elapsed < 1500);
            std::printf("  observed diagnostic: %s  (elapsed %lld ms)\n",
                        run.stderr_text.c_str(), static_cast<long long>(elapsed));
        }
    }
}

// Run the real binary, discarding its output. Returns the exit status, or -1.
int run_cli(const std::string& binary, std::vector<const char*> argv) {
    argv.push_back(nullptr);
    const pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (freopen("/dev/null", "w", stderr) == nullptr) std::_Exit(127);
        if (freopen("/dev/null", "w", stdout) == nullptr) std::_Exit(127);
        execv(binary.c_str(), const_cast<char* const*>(argv.data()));
        std::_Exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Run the real binary and capture stderr for diagnostic assertions.
int run_cli_capture_stderr(const std::string& binary, std::vector<const char*> argv,
                           std::string& stderr_text) {
    argv.push_back(nullptr);
    int fds[2];
    if (pipe(fds) != 0) return -1;
    const pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(fds[1], STDERR_FILENO);
        if (freopen("/dev/null", "w", stdout) == nullptr) std::_Exit(127);
        close(fds[0]);
        close(fds[1]);
        execv(binary.c_str(), const_cast<char* const*>(argv.data()));
        std::_Exit(127);
    }
    close(fds[1]);
    stderr_text.clear();
    char buffer[512];
    ssize_t got = 0;
    while ((got = read(fds[0], buffer, sizeof buffer)) > 0) {
        stderr_text.append(buffer, static_cast<std::size_t>(got));
    }
    close(fds[0]);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void test_cli(const char* binary) {
    section("cli: argument errors are exit code 2, before any network call");
    CHECK(run_cli(binary, {"sifrprobe"}) == 2);
    CHECK(run_cli(binary, {"sifrprobe", "example.com"}) == 2);  // no port
    CHECK(run_cli(binary, {"sifrprobe", "127.0.0.1:1", "-n", "0"}) == 2);
    CHECK(run_cli(binary, {"sifrprobe", "127.0.0.1:1", "--bogus"}) == 2);
    CHECK(run_cli(binary, {"sifrprobe", "[::1"}) == 2);
    CHECK(run_cli(binary, {"sifrprobe", "127.0.0.1:1", "-n", "1000001"}) == 2);

    section("cli: a refused loopback connect is diagnosed, not silently zeroed");
    // 127.0.0.1:1 has no listener: the kernel answers the SYN with RST at once,
    // so this never waits on the deadline and never leaves the loopback
    // interface. -t 400 bounds the check if a local firewall drops the SYN.
    std::string stderr_text;
    const int status = run_cli_capture_stderr(
        binary, {"sifrprobe", "127.0.0.1:1", "-n", "1", "-t", "400"}, stderr_text);
    CHECK(status == 1);  // ok != count is the documented failure exit
    const bool refused = stderr_text.find("connection refused") != std::string::npos;
    const bool timed_out = stderr_text.find("timed out") != std::string::npos;
    CHECK(refused || timed_out);
    // A refused/unreachable socket must be named as such; falling back to a bare
    // timeout hides the RST the kernel already delivered.
    std::printf("  observed diagnostic: %s%s\n",
                refused ? "connection refused" : "",
                timed_out ? "timed out" : "");
}

}  // namespace

int main(int argc, char** argv) {
    std::printf("sifrprobe verification harness\n");
    test_stats();
    test_parse_positive();
    test_parse_target();
    test_json_escape();
    test_http_request();
    test_connect_failure();
    if (argc > 1) {
        test_cli(argv[1]);
        test_loopback_http_classification(argv[1]);
    } else {
        std::printf("\n[cli] skipped: pass the sifrprobe binary path to enable\n");
    }

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
