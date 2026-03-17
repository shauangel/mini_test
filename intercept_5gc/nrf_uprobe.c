// nrf_uprobe.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "nrf_uprobe.skel.h"

static volatile sig_atomic_t exiting = 0;

struct event {
    __u32 pid;
    __u32 api_id;
};

static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    const char *api = "UNKNOWN";

    switch (e->api_id) {
    case 1:
        api = "HTTPRegisterNFInstance";
        break;
    case 2:
        api = "HTTPSearchNFInstances";
        break;
    }

    printf("pid=%u api=%s\n", e->pid, api);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct bpf_link *link1 = NULL, *link2 = NULL;
    struct nrf_uprobe_bpf *skel;
    const char *bin = "./bin/nrf";
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = nrf_uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load skeleton\n");
        return 1;
    }

    link1 = bpf_program__attach_uprobe(
        skel->progs.nrf_http_register,
        false,   // uprobe entry
        -1,      // all pids
        bin,
        0xcce560 // HTTPRegisterNFInstance
    );
    if (!link1) {
        fprintf(stderr, "failed to attach register uprobe\n");
        err = 1;
        goto cleanup;
    }

    link2 = bpf_program__attach_uprobe(
        skel->progs.nrf_http_search,
        false,
        -1,
        bin,
        0xccdf60 // HTTPSearchNFInstances
    );
    if (!link2) {
        fprintf(stderr, "failed to attach search uprobe\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing NRF uprobes...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }
        err = 0;
    }

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link1);
    bpf_link__destroy(link2);
    nrf_uprobe_bpf__destroy(skel);
    return err;
}