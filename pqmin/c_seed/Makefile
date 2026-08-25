CC ?= cc
CFLAGS ?= -O3 -march=native -std=c17 -Wall -Wextra -Wpedantic
LDLIBS ?= -lzstd

.PHONY: all clean

all: candidate

candidate: candidate.c
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

clean:
	rm -f candidate
