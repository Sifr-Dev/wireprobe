<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
    <img alt="sifr-probe — built from zero" src=".github/banner-light.svg" width="100%">
  </picture>
</p>

# sifrprobe

zero-dependency TCP latency prober in ~150 lines of C++17. connect RTT and HTTP
first-byte timing with min/p50/p90/p99/max/mean, human or `--json` output.
links nothing. posix sockets only.

## usage

```sh
sifrprobe example.com:80 -n 20 --http
sifrprobe 127.0.0.1:8899 --http --json | jq .first_byte.p99
```

## evidence (this machine, 2026-11-17)

```console
sifrprobe 127.0.0.1:8899  ok=5/5
  connect    min 0.033  p50 0.073  p90 0.076  p99 0.076  max 0.076  mean 0.059 ms
  first_byte min 1.488  p50 2.021  p90 5.321  p99 5.321  max 5.321  mean 2.550 ms
```

## tests

```sh
make test           # 193 deterministic checks
make test-sanitize  # same checks under ASan + UBSan
```

The harness exercises the real logic the prober uses: percentile statistics,
target and argument parsing, JSON escaping, HTTP/1.0 request framing, and the
phase/cause failure classification. It is deterministic — fixed seed, no wall
clock, no DNS, no external network. CI runs both targets.

Most checks are pure and network-free. The diagnostics checks drive the real
binary over a real kernel socket on `127.0.0.1`, using a fork-based fixture
server on an ephemeral port: a peer FIN, an abortive close (RST), a FIN after
the request, a one-byte answer, and a peer that stays silent past the deadline.
Those cases are what prove the prober reports *what actually happened* rather
than folding every post-connect failure into "timed out".

## diagnostics

A failed sample names the phase it failed in and the cause, e.g.
`sample 1: connection closed by peer before first byte`,
`sample 1: connection reset by peer before first byte`,
`sample 1: first byte timed out after 250 ms`, or
`sample 1: connection refused`.

A deadline expiry and a peer that closed or reset are deliberately distinct: a
timeout means nothing arrived before the deadline, while a close or reset is a
definite answer from the network. Only the failing sample is reported.


## install

```sh
git clone https://github.com/Sifr-Dev/wireprobe && cd sifr-probe && make
```

## build from source / test

`make` (no dependencies — g++ + libc). test: run against a local server, e.g.
`python3 -m http.server 8899` then `sifrprobe 127.0.0.1:8899 --http`.

## license
`MIT`. built from zero.
