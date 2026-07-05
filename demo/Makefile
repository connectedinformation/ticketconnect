# demo — host-level acceptance demo helpers

CC     ?= cc
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
CFLAGS += $(shell pkg-config --cflags openssl)
LDLIBS += $(shell pkg-config --libs openssl)

.PHONY: all clean

all: loop_client

loop_client: loop_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f loop_client
