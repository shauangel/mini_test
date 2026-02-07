// eBPF CO-RE
#include "vmlinux.h"
// libbpf headers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(struct pt_regs *ctx){
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u16 sport = 0, dport = 0;
    __u32 saddr = 0, daddr = 0;

    // Map socket common fields
    sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    //Convert dport from network byte order to host byte order
    __u16 dport_cov = bpf_ntohs(dport);

    bpf_printk("tcp_v4_connect: sport=%d, dport=%d, saddr=%x, daddr=%x\n", sport, dport_cov, saddr, daddr);

    return 0;
}