#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>

int main(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int err;

    obj = bpf_object__open_file("svc_connect.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_connect");
    if (!prog) {
        fprintf(stderr, "failed to find program handle_connect\n");
        return 1;
    }

    link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_connect");
    if (!link) {
        fprintf(stderr, "failed to attach tracepoint: %d\n", errno);
        return 1;
    }

    printf("eBPF program attached to sys_enter_connect. Ctrl+C to exit.\n");

    while (1)
        sleep(1);

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
