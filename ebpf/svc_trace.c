#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "nettrace.skel.h"  // 由 bpftool gen skeleton 產生

static volatile sig_atomic_t exiting = 0;

static void handle_sigint(int sig)
{
    exiting = 1;
}

static void print_ipv4(__u32 addr, __u16 port)
{
    unsigned char b1 = (addr >> 24) & 0xff;
    unsigned char b2 = (addr >> 16) & 0xff;
    unsigned char b3 = (addr >> 8)  & 0xff;
    unsigned char b4 = addr & 0xff;

    printf("%u.%u.%u.%u:%u", b1, b2, b3, b4, port);
}

// 跟 BPF 端 struct net_event 對應
struct net_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    char  comm[16];

    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;

    __u8  direction;
    __u8  family;
    __u16 _pad;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct net_event *e = data;
    double ts_sec = e->ts_ns / 1e9;

    // 簡單印 unix time（秒），你可以改成相對時間
    printf("[%.6f] %s (pid=%u uid=%u) : ", ts_sec, e->comm, e->pid, e->uid);

    // <saddr:sport> -> <daddr:dport>
    printf("<");
    print_ipv4(e->saddr, e->sport);
    printf("> -> <");
    print_ipv4(e->daddr, e->dport);
    printf("> ");

    if (e->direction == 0)
        printf("[OUT]\n");
    else
        printf("[IN]\n");

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct nettrace_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    skel = nettrace_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open skeleton\n");
        return 1;
    }

    err = nettrace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load skeleton: %d\n", err);
        goto cleanup;
    }

    err = nettrace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer: %d\n", errno);
        goto cleanup;
    }

    printf("nettrace: tracing connect()/accept4() via tracepoint. Ctrl+C to stop.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR) {
            break;
        } else if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    nettrace_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
