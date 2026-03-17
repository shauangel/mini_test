CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

CFLAGS := -O2 -g
BPF_CFLAGS := -O2 -g -target bpf

all: nrf_uprobe

nrf_uprobe.bpf.o: nrf_uprobe.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

nrf_uprobe.skel.h: nrf_uprobe.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

nrf_uprobe: nrf_uprobe.c nrf_uprobe.skel.h
	$(CC) $(CFLAGS) nrf_uprobe.c -o nrf_uprobe -lbpf -lelf -lz

clean:
	rm -f nrf_uprobe nrf_uprobe.bpf.o nrf_uprobe.skel.h