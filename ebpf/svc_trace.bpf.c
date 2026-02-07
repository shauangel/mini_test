// eBPF CO-RE
#include "vmlinux.h"
// libbpf headers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>


char LICENSE[] SEC("license") = "GPL";

#define DIR_IN 1
#define DIR_OUT 0

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

    __u8  direction; // 0 = outbound(connect), 1 = inbound(accept)
    __u8  family;    // AF_INET, AF_INET6
    __u16 _pad;
};

// ring buffer: user-space 用來讀 events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16MB
} events SEC(".maps");

// 用來在 enter/exit accept4 之間暫存 user pointer
struct accept_ctx {
    __u64 upeer_sockaddr;
    __u64 upeer_addrlen_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);            // tid
    __type(value, struct accept_ctx);
} accept_args SEC(".maps");

// syscall tracepoint 的 raw 結構 (在 vmlinux.h 也會有同名定義)
// 如果編譯時抱怨重複定義，可以把下面這段刪掉，改用 vmlinux.h 裡的版本。
struct trace_entry {
    __u16 type;
    __u8  flags;
    __u8  preempt_count;
    __s32 pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    long args[6];
};

struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    long id;
    long ret;
};

static __always_inline void fill_common(struct net_event *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->uid = (__u32)uid_gid;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->ts_ns = bpf_ktime_get_ns();
}

// outbound: connect()
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in sa = {};
    struct net_event *e;
    void *uservaddr;
    int addrlen;
    __u16 family;
    __u32 daddr;
    __u16 dport;

    uservaddr = (void *)ctx->args[1];
    addrlen   = (int)ctx->args[2];

    if (addrlen < sizeof(sa))
        return 0;

    if (bpf_probe_read_user(&sa, sizeof(sa), uservaddr))
        return 0;

    family = sa.sin_family;
    if (family != AF_INET)
        return 0;

    daddr = bpf_ntohl(sa.sin_addr.s_addr);
    dport = bpf_ntohs(sa.sin_port);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);

    e->family    = AF_INET;
    e->direction = DIR_OUT;

    // 本機位址目前拿不到，暫時填 0
    e->saddr = 0;
    e->sport = 0;

    e->daddr = daddr;
    e->dport = dport;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// inbound: accept4() enter，先存 user pointer
SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct accept_ctx ac = {};

    ac.upeer_sockaddr    = (__u64)ctx->args[1];
    ac.upeer_addrlen_ptr = (__u64)ctx->args[2];

    bpf_map_update_elem(&accept_args, &tid, &ac, BPF_ANY);
    return 0;
}

// inbound: accept4() exit，這時候 user-space 的 sockaddr 已經被 kernel 填好
SEC("tracepoint/syscalls/sys_exit_accept4")
int handle_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct accept_ctx *ac;
    struct sockaddr_in sa = {};
    int addrlen = 0;
    struct net_event *e;
    __u16 family;
    __u32 saddr;
    __u16 sport;

    // accept 失敗
    if (ctx->ret < 0)
        goto cleanup;

    ac = bpf_map_lookup_elem(&accept_args, &tid);
    if (!ac)
        return 0;

    // 先讀 addrlen
    if (bpf_probe_read_user(&addrlen, sizeof(addrlen), (void *)ac->upeer_addrlen_ptr))
        goto cleanup;

    if (addrlen < sizeof(sa))
        goto cleanup;

    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ac->upeer_sockaddr))
        goto cleanup;

    family = sa.sin_family;
    if (family != AF_INET)
        goto cleanup;

    saddr = bpf_ntohl(sa.sin_addr.s_addr);
    sport = bpf_ntohs(sa.sin_port);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);

    e->family    = AF_INET;
    e->direction = DIR_IN;

    // 這裡的 saddr/sport 是「client 的 IP/port」
    e->saddr = saddr;
    e->sport = sport;

    // server 端本機 IP/port 暫時未知，先填 0
    e->daddr = 0;
    e->dport = 0;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&accept_args, &tid);
    return 0;
}
