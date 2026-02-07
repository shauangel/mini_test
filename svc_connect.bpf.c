#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2

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

struct my_in_addr {
    __u32 s_addr;
};

struct my_sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    struct my_in_addr sin_addr;
    __u8  pad[8];
};

// Can only see in
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    const struct my_sockaddr_in *uaddr =
        (const struct my_sockaddr_in *)ctx->args[1];

    struct my_sockaddr_in sa4 = {};

    if (!uaddr)
        return 0;

    if (bpf_probe_read_user(&sa4, sizeof(sa4), uaddr))
        return 0;

    if (sa4.sin_family != AF_INET)
        return 0;

    __u16 dport = __bpf_ntohs(sa4.sin_port);

    /* microservices ports */
    if (dport < 8000 || dport > 8003)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u32 addr = sa4.sin_addr.s_addr;

    bpf_printk("svc-connect: %s -> port %d\n", comm, dport);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept(struct trace_event_raw_sys_enter *ctx)
{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("svc-accept: %s is accepting()\n", comm);
    return 0;
}




/*    bpf_printk("svc-connect: %s -> %d.%d.%d.%d:%d\n",
               comm,
               addr & 0xff,
               (addr >> 8) & 0xff,
               (addr >> 16) & 0xff,
               (addr >> 24) & 0xff,
               dport);
*/