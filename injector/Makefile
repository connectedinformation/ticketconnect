# injector — privileged (eBPF detection + ptrace action). WIP: remote-call core.

CC        ?= cc
CFLAGS    ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
CFLAGS    += -I.

LIB_SRC   := remote.c symbols.c
TEST_BINS := test/test_remote test/test_symbols

.PHONY: all clean test check

all: test ## nothing to ship yet — build the tests

test/%: test/%.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_SRC)

test: $(TEST_BINS) ## build the test binaries

check: $(TEST_BINS) ## run the injector tests (trace/resolve own child; unprivileged)
	@echo "== remote-call primitive ==" && ./test/test_remote
	@echo "== symbol resolution ==" && ./test/test_symbols

clean:
	rm -f $(TEST_BINS)
