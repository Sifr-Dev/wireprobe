CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
TESTFLAGS ?= -O1 -g -std=c++17 -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer

all: sifrprobe

sifrprobe: main.cpp probe.hpp stats.hpp
	$(CXX) $(CXXFLAGS) -o $@ main.cpp

# Deterministic verification harness: no sockets, no DNS, no wall-clock input.
verify: tests/verify.cpp probe.hpp stats.hpp sifrprobe
	$(CXX) $(CXXFLAGS) -o tests/verify tests/verify.cpp

test: verify
	./tests/verify ./sifrprobe

# Same checks under AddressSanitizer + UBSan to catch memory/UB defects in the
# parsing and statistics code paths.
test-sanitize: tests/verify.cpp probe.hpp stats.hpp
	$(CXX) $(TESTFLAGS) -o tests/verify-sanitize tests/verify.cpp
	$(CXX) $(TESTFLAGS) -o sifrprobe-sanitize main.cpp
	./tests/verify-sanitize ./sifrprobe-sanitize

clean:
	rm -f sifrprobe sifrprobe-sanitize tests/verify tests/verify-sanitize

.PHONY: all clean verify test test-sanitize
