CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

CFLAGS := -O2 -g
BPF_CFLAGS := -O2 -g -target bpf

LIBS := -lbpf -lelf -lz

all: nrf_api_tracer nrf_conn_tracer

nrf_api_tracer.bpf.o: nrf_api_tracer.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

nrf_api_tracer.skel.h: nrf_api_tracer.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

nrf_api_tracer: nrf_api_tracer.c nrf_api_tracer.skel.h
	$(CC) $(CFLAGS) nrf_api_tracer.c -o nrf_api_tracer -lbpf -lelf -lz

nrf_conn_tracer.bpf.o: nrf_conn_tracer.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

nrf_conn_tracer.skel.h: nrf_conn_tracer.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

nrf_conn_tracer: nrf_conn_tracer.c nrf_conn_tracer.skel.h
	$(CC) $(CFLAGS) nrf_conn_tracer.c -o nrf_conn_tracer -lbpf -lelf -lz

clean:
	rm -f nrf_api_tracer nrf_api_tracer.bpf.o nrf_api_tracer.skel.h nrf_conn_tracer nrf_conn_tracer.bpf.o nrf_conn_tracer.skel.h