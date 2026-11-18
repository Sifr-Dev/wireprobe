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

## install

```sh
git clone https://github.com/Sifr-Dev/wireprobe && cd sifr-probe && make
```

## build from source / test

`make` (no dependencies — g++ + libc). test: run against a local server, e.g.
`python3 -m http.server 8899` then `sifrprobe 127.0.0.1:8899 --http`.

## license
`MIT`. built from zero.
