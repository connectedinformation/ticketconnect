# bpf — CO-RE uprobe (detection). Needs clang (BPF target), bpftool, libbpf.

CLANG    ?= clang
BPFTOOL  ?= bpftool
ARCH     := x86

BPF_CFLAGS    := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I.
LOADER_CFLAGS := -O2 -g -Wall -Wextra -I. $(shell pkg-config --cflags libbpf openssl)
LOADER_LIBS   := $(shell pkg-config --libs libbpf openssl)

.PHONY: all clean check

all: test/test_detect ## build the detection loader + BPF object

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

ssl_connect.bpf.o: ssl_connect.bpf.c event.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ssl_connect.skel.h: ssl_connect.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

test/test_detect: test/test_detect.c ssl_connect.skel.h event.h
	$(CC) $(LOADER_CFLAGS) -o $@ $< $(LOADER_LIBS)

check: test/test_detect ## run the detection test (needs BPF privilege -> sudo)
	sudo ./test/test_detect

clean:
	rm -f ssl_connect.bpf.o ssl_connect.skel.h test/test_detect
