# injector — privileged (eBPF detection + ptrace action). WIP.

CC        ?= cc
CFLAGS    ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
CFLAGS    += -I.
SSL_FLAGS := $(shell pkg-config --cflags openssl)
SSL_LIBS  := $(shell pkg-config --libs openssl)

LIB_SRC   := remote.c symbols.c install.c
TEST_BINS := test/test_remote test/test_symbols test/test_install test/test_failclosed

BPF_DIR   := ../bpf
BPF_FLAGS := $(shell pkg-config --cflags libbpf)
BPF_LIBS  := $(shell pkg-config --libs libbpf)
AGENT_DIR := ../ticket-agent
BIN       := injector

.PHONY: all clean test check

all: $(BIN) ## build the injector daemon

# The daemon links the BPF skeleton and the agent's UDS client; it does NOT link
# OpenSSL — libssl functions are invoked remotely in the target, not called here.
$(BIN): main.c $(LIB_SRC) $(AGENT_DIR)/uds.c $(AGENT_DIR)/pool.c $(BPF_DIR)/ssl_connect.skel.h
	$(CC) $(CFLAGS) -I$(BPF_DIR) -I$(AGENT_DIR) $(BPF_FLAGS) -o $@ \
		main.c $(LIB_SRC) $(AGENT_DIR)/uds.c $(AGENT_DIR)/pool.c $(BPF_LIBS)

# Non-OpenSSL tests: pure ptrace/ELF, no libssl link.
test/test_remote: test/test_remote.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_SRC)

test/test_symbols: test/test_symbols.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_SRC)

# These link libssl for their in-process victims.
test/test_install: test/test_install.c $(LIB_SRC)
	$(CC) $(CFLAGS) $(SSL_FLAGS) -o $@ $< $(LIB_SRC) $(SSL_LIBS)

test/test_failclosed: test/test_failclosed.c $(LIB_SRC)
	$(CC) $(CFLAGS) $(SSL_FLAGS) -o $@ $< $(LIB_SRC) $(SSL_LIBS)

test: $(TEST_BINS) ## build the test binaries

$(BPF_DIR)/ssl_connect.skel.h:
	$(MAKE) -C $(BPF_DIR) ssl_connect.skel.h

# Capstone wire-up: links the injector, libssl (victim), and the BPF skeleton.
test/test_wireup: test/test_wireup.c $(LIB_SRC) $(BPF_DIR)/ssl_connect.skel.h
	$(CC) $(CFLAGS) -I$(BPF_DIR) $(SSL_FLAGS) $(BPF_FLAGS) -o $@ test/test_wireup.c $(LIB_SRC) $(SSL_LIBS) $(BPF_LIBS)

check: $(TEST_BINS) ## run injector tests (own child; unprivileged)
	@echo "== remote-call primitive ==" && ./test/test_remote
	@echo "== symbol resolution =="      && ./test/test_symbols
	@echo "== fail-closed (negatives) ==" && ./test/test_failclosed
	@echo "== real install (agent -> injector -> resume) ==" && PORT=$(PORT) bash test/run.sh

check-wireup: test/test_wireup ## capstone: detect+freeze -> install -> resume (sudo)
	@echo "== wire-up (uncooperative, eBPF freeze) ==" && PORT=$(PORT) bash test/run_wireup.sh

PORT ?= 15443

clean:
	rm -f $(BIN) $(TEST_BINS) test/test_wireup
