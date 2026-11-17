// sifr-probe — zero-dependency TCP latency prober.
// Measures connect RTT and (for HTTP) first-byte time, prints min/p50/p90/p99/max
// or machine-readable JSON (--json). POSIX sockets only; links nothing.
//   sifrprobe host[:port] [-n COUNT] [-t TIMEOUT_MS] [--json] [--http]
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

static double now_ms() {
    timeval tv; gettimeofday(&tv, nullptr);
    return tv.tv_sec * 1e3 + tv.tv_usec / 1e3;
}

struct Sample { double connect_ms, first_byte_ms; };

struct Percentiles { double mn, p50, p90, p99, mx, mean; };
static Percentiles summarize(const std::vector<double>& v) {
    if (v.empty()) return {0,0,0,0,0,0};
    std::vector<double> s = v;
    std::sort(s.begin(), s.end());
    double sum = 0; for (double x : s) sum += x;
    auto at = [&](double q) { size_t i = static_cast<size_t>(q * (s.size() - 1) + 0.5); return s[i]; };
    return {s.front(), at(0.50), at(0.90), at(0.99), s.back(), sum / s.size()};
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: sifrprobe host[:port] [-n COUNT] [-t TIMEOUT_MS] [--http] [--json]\n"); return 2; }
    std::string target = argv[1];
    int count = 10, timeout_ms = 2000;
    bool http = false, json = false;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-n") && i + 1 < argc) count = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--http")) http = true;
        else if (!strcmp(argv[i], "--json")) json = true;
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
    std::string host = target, port = "80";
    size_t colon = target.rfind(':');
    if (colon != std::string::npos) { host = target.substr(0, colon); port = target.substr(colon + 1); }

    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) { fprintf(stderr, "resolve failed: %s\n", host.c_str()); return 1; }

    std::vector<double> connects, first_bytes;
    int ok = 0;
    for (int i = 0; i < count; i++) {
        int fd = -1;
        for (addrinfo* p = res; p && fd < 0; p = p->ai_next)
            fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) { fprintf(stderr, "socket failed\n"); continue; }
        // nonblocking connect to measure connect time
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        double t0 = now_ms();
        int rc = connect(fd, res->ai_addr, res->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) { close(fd); continue; }
        if (rc < 0) {
            fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
            timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
            int sel = select(fd + 1, nullptr, &wf, nullptr, &tv);
            if (sel <= 0) { close(fd); continue; }
        }
        double t1 = now_ms();
        double fb = -1;
        if (http) {
            std::string req = "GET / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
            if (write(fd, req.data(), req.size()) >= 0) {
                char buf[64];
                timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
                fd_set rf; FD_ZERO(&rf); FD_SET(fd, &rf);
                int sel = select(fd + 1, &rf, nullptr, nullptr, &tv);
                if (sel > 0) { ssize_t n = read(fd, buf, sizeof buf); if (n > 0) fb = now_ms() - t1; }
            }
        }
        close(fd);
        connects.push_back(t1 - t0);
        if (fb >= 0) first_bytes.push_back(fb);
        ok++;
    }
    freeaddrinfo(res);

    if (json) {
        Percentiles c = summarize(connects);
        Percentiles f = summarize(first_bytes);
        printf("{\"target\":\"%s\",\"count\":%d,\"ok\":%d,\"connect\":{\"min\":%.3f,\"p50\":%.3f,\"p90\":%.3f,\"p99\":%.3f,\"max\":%.3f,\"mean\":%.3f}", host.c_str(), count, ok, c.mn, c.p50, c.p90, c.p99, c.mx, c.mean);
        if (!first_bytes.empty())
            printf(",\"first_byte\":{\"min\":%.3f,\"p50\":%.3f,\"p90\":%.3f,\"p99\":%.3f,\"max\":%.3f,\"mean\":%.3f}", f.mn, f.p50, f.p90, f.p99, f.mx, f.mean);
        printf("}\n");
    } else {
        Percentiles c = summarize(connects);
        printf("sifrprobe %s  ok=%d/%d\n", target.c_str(), ok, count);
        printf("  connect   min %.3f  p50 %.3f  p90 %.3f  p99 %.3f  max %.3f  mean %.3f ms\n", c.mn, c.p50, c.p90, c.p99, c.mx, c.mean);
        if (!first_bytes.empty()) {
            Percentiles f = summarize(first_bytes);
            printf("  first_byte min %.3f  p50 %.3f  p90 %.3f  p99 %.3f  max %.3f  mean %.3f ms\n", f.mn, f.p50, f.p90, f.p99, f.mx, f.mean);
        }
    }
    return ok == 0 ? 1 : 0;
}
