# injector — privileged (eBPF detection + ptrace action). WIP.

CC        ?= cc
CFLAGS    ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
CFLAGS    += -I.
SSL_FLAGS := $(shell pkg-config --cflags openssl)
SSL_LIBS  := $(shell pkg-config --libs openssl)

LIB_SRC   := remote.c symbols.c install.c
TEST_BINS := test/test_remote test/test_symbols test/test_install

.PHONY: all clean test check

all: test ## nothing to ship yet — build the tests

# Non-OpenSSL tests: pure ptrace/ELF, no libssl link.
test/test_remote: test/test_remote.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_SRC)

test/test_symbols: test/test_symbols.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_SRC)

# Install test links libssl for its in-process victim.
test/test_install: test/test_install.c $(LIB_SRC)
	$(CC) $(CFLAGS) $(SSL_FLAGS) -o $@ $< $(LIB_SRC) $(SSL_LIBS)

test: $(TEST_BINS) ## build the test binaries

check: $(TEST_BINS) ## run injector tests (own child; unprivileged)
	@echo "== remote-call primitive ==" && ./test/test_remote
	@echo "== symbol resolution =="      && ./test/test_symbols
	@echo "== real install (agent -> injector -> resume) ==" && PORT=$(PORT) bash test/run.sh

PORT ?= 15443

clean:
	rm -f $(TEST_BINS)
