// eBPF CO-RE
#include "vmlinux.h"
// libbpf headers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_v4_connect, struct sock *sk){
    __u16 sport = 0, dport = 0;
    __u32 saddr = 0, daddr = 0;

}