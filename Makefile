CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
all: sifrprobe
sifrprobe: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<
clean:
	rm -f sifrprobe
.PHONY: all clean
