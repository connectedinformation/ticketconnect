# ticket-agent — authority component (unprivileged)

CC        ?= cc
CFLAGS    ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
CFLAGS    += -I.
PKG       := openssl
CFLAGS    += $(shell pkg-config --cflags $(PKG))
LDLIBS    += $(shell pkg-config --libs $(PKG))

BIN       := ticket-agent
LIB_SRC   := session_source.c pool.c uds.c
TEST_BINS := test/test_session test/test_pool test/test_uds
PORT      ?= 14433

.PHONY: all clean test check

all: $(BIN)

$(BIN): main.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

test/%: test/%.c $(LIB_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_SRC) $(LDLIBS)

test: $(TEST_BINS) ## build the test binaries

check: $(BIN) $(TEST_BINS) ## run Tier 1–2 tests (hermetic + against a local PQC s_server)
	@echo "== hermetic (pool) =="   && ./test/test_pool
	@echo "== hermetic (uds) =="    && ./test/test_uds
	@echo "== network (session + serve/get) ==" && PORT=$(PORT) bash test/run.sh

clean:
	rm -f $(BIN) $(TEST_BINS)
