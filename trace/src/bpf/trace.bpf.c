// SPDX-License-Identifier: GPL-2.0
// Kernel side of chouf-trace: what the processes of one sandbox really do.
// Only cgroups the daemon was asked to watch are reported: every hook first checks a counter (zero when nobody
// watches, so the rest of the machine pays one load), then walks the current task's cgroup ancestors.
// Connection and DNS code comes from 3assas (same author, same licence).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2
#define AF_INET6 10
#define PROTO_TCP 6
#define PROTO_UDP 17
#define ST_SYN_SENT 2
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define DNS_PORT 53
#define DNS_MAX 1232
#define PATH_LEN 256
#define ARGS_LEN 256
#define MAX_DEPTH 16

enum kind { EV_EXEC = 1, EV_OPEN = 2, EV_CONNECT = 3, EV_UDP = 4, EV_EXIT = 5, EV_FORK = 6 };

// Shared with userspace (src/event.rs): 584 bytes, no implicit padding.
struct event {
	u64 ts_ns;
	u64 cgroup;      // the watched cgroup this came from
	u32 tgid;
	u32 ppid;
	u32 uid;
	u32 flags;       // exec: length of args; open: f_flags; exit: exit code
	u16 family;
	u16 dport;
	u8 kind;
	u8 _pad[3];
	u8 daddr[16];
	char comm[16];
	char path[PATH_LEN];   // exec: the file run; open: the file opened
	char args[ARGS_LEN];   // exec: argv, NUL-separated
};

// A raw DNS answer for a watched cgroup, parsed in userspace (src/dns.rs). Told apart by its size.
struct dns_event {
	u32 len;
	u32 _pad;
	u64 cgroup;
	u8 data[DNS_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 << 20);
} events SEC(".maps");

// Watched cgroup ids (cgroup v2 directory inode numbers).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u64);
	__type(value, u8);
} watched SEC(".maps");

struct udp_key {
	u32 tgid;
	u16 family;
	u16 dport;
	u8 daddr[16];
};

// First packet of each UDP flow only: enough to know where a sandboxed program sends data.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct udp_key);
	__type(value, u8);
} udp_seen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} drops SEC(".maps");

// Number of watched cgroups, set by userspace. Zero: every hook returns after one load.
volatile u32 watching;

static __always_inline void count_drop(void)
{
	u32 zero = 0;
	u64 *n = bpf_map_lookup_elem(&drops, &zero);
	if (n)
		(*n)++;
}

// The watched cgroup the current task lives in (itself or an ancestor), or 0.
static __always_inline u64 watched_cgroup(void)
{
	if (!watching)
		return 0;
	for (int level = 1; level < MAX_DEPTH; level++) {
		u64 id = bpf_get_current_ancestor_cgroup_id(level);
		if (!id)
			return 0;
		if (bpf_map_lookup_elem(&watched, &id))
			return id;
	}
	return 0;
}

static __always_inline struct event *reserve(u8 kind, u64 cg)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return NULL;
	}
	// Only the header is zeroed (cheap on a hot path like file_open). path is always NUL-terminated and args
	// carries its length in flags: userspace reads nothing past those, so stale bytes never leave the daemon.
	__builtin_memset(e, 0, offsetof(struct event, path));
	e->path[0] = 0;
	e->args[0] = 0;
	u64 id = bpf_get_current_pid_tgid();
	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup = cg;
	e->kind = kind;
	e->tgid = id >> 32;
	e->uid = (u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	u64 cg = watched_cgroup();
	if (!cg)
		return 0;
	struct event *e = reserve(EV_EXEC, cg);
	if (!e)
		return 0;
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), BPF_CORE_READ(bprm, filename));
	unsigned long start = BPF_CORE_READ(p, mm, arg_start), end = BPF_CORE_READ(p, mm, arg_end);
	unsigned long len = end - start;
	if (len > ARGS_LEN - 1)
		len = ARGS_LEN - 1;
	barrier_var(len);
	// flags = how many bytes of args are real: the rest of the buffer is not cleared and must never be read.
	if (len > 0 && len < ARGS_LEN && !bpf_probe_read_user(e->args, len, (void *)start))
		e->flags = len;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// A new process (not a thread): a subshell running `$(cat ~/.ssh/id_rsa)` never execs, but its children must
// still hang under the script that started it.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))
		return 0;
	u64 cg = watched_cgroup();
	if (!cg)
		return 0;
	struct event *e = reserve(EV_FORK, cg);
	if (!e)
		return 0;
	e->tgid = BPF_CORE_READ(child, tgid);
	e->ppid = BPF_CORE_READ(parent, tgid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	if (BPF_CORE_READ(p, pid) != BPF_CORE_READ(p, tgid)) // threads: only the process as a whole
		return 0;
	u64 cg = watched_cgroup();
	if (!cg)
		return 0;
	struct event *e = reserve(EV_EXIT, cg);
	if (!e)
		return 0;
	e->flags = BPF_CORE_READ(p, exit_code) >> 8;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(on_open, struct file *file)
{
	u64 cg = watched_cgroup();
	if (!cg)
		return 0;
	struct event *e = reserve(EV_OPEN, cg);
	if (!e)
		return 0;
	e->flags = file->f_flags;
	if (bpf_d_path(&file->f_path, e->path, sizeof(e->path)) < 0)
		e->path[0] = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline void sk_dest(const struct sock *sk, struct event *e)
{
	e->family = sk->__sk_common.skc_family;
	e->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	if (e->family == AF_INET)
		bpf_probe_read_kernel(e->daddr, 4, &sk->__sk_common.skc_daddr);
	else
		bpf_probe_read_kernel(e->daddr, 16, &sk->__sk_common.skc_v6_daddr);
}

// SYN_SENT runs in the connect() caller's context, so "current" is the program that connects.
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_tcp_state, struct sock *sk, int oldstate, int newstate)
{
	if (newstate != ST_SYN_SENT || sk->sk_protocol != PROTO_TCP)
		return 0;
	u64 cg = watched_cgroup();
	if (!cg)
		return 0;
	struct event *e = reserve(EV_CONNECT, cg);
	if (!e)
		return 0;
	sk_dest(sk, e);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int udp_send(struct sock *sk, struct msghdr *msg, u16 family)
{
	u64 cg = watched_cgroup();
	if (!cg)
		return 0;
	struct udp_key k = {};
	k.family = family;
	void *name = msg->msg_name;
	if (name) {
		if (family == AF_INET) {
			struct sockaddr_in sin;
			bpf_probe_read_kernel(&sin, sizeof(sin), name);
			k.dport = bpf_ntohs(sin.sin_port);
			__builtin_memcpy(k.daddr, &sin.sin_addr, 4);
		} else {
			struct sockaddr_in6 sin6;
			bpf_probe_read_kernel(&sin6, sizeof(sin6), name);
			k.dport = bpf_ntohs(sin6.sin6_port);
			__builtin_memcpy(k.daddr, &sin6.sin6_addr, 16);
		}
	} else {
		k.dport = bpf_ntohs(sk->__sk_common.skc_dport);
		if (family == AF_INET)
			bpf_probe_read_kernel(k.daddr, 4, &sk->__sk_common.skc_daddr);
		else
			bpf_probe_read_kernel(k.daddr, 16, &sk->__sk_common.skc_v6_daddr);
	}
	k.tgid = bpf_get_current_pid_tgid() >> 32;
	u8 one = 1;
	if (bpf_map_update_elem(&udp_seen, &k, &one, BPF_NOEXIST)) // already reported
		return 0;
	struct event *e = reserve(EV_UDP, cg);
	if (!e)
		return 0;
	e->family = family;
	e->dport = k.dport;
	__builtin_memcpy(e->daddr, k.daddr, 16);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp4, struct sock *sk, struct msghdr *msg, size_t len)
{
	return udp_send(sk, msg, AF_INET);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(on_udp6, struct sock *sk, struct msghdr *msg, size_t len)
{
	return udp_send(sk, msg, AF_INET6);
}

// Attached by the daemon to each watched cgroup (not the root): sees what the sandbox's sockets receive.
// Never drops a packet: always returns 1.
SEC("cgroup_skb/ingress")
int on_ingress(struct __sk_buff *skb)
{
	u32 off;
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;
		if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) || ip.protocol != PROTO_UDP)
			return 1;
		off = ip.ihl * 4;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;
		if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)) || ip6.nexthdr != PROTO_UDP)
			return 1;
		off = sizeof(ip6);
	} else {
		return 1;
	}
	struct udphdr udp;
	if (bpf_skb_load_bytes(skb, off, &udp, sizeof(udp)) || udp.source != bpf_htons(DNS_PORT))
		return 1;
	off += sizeof(udp);
	if (skb->len <= off)
		return 1;
	u32 len = skb->len - off;
	if (len > DNS_MAX)
		len = DNS_MAX;

	u64 cg = 0;
	for (int level = 1; level < MAX_DEPTH; level++) {
		u64 id = bpf_skb_ancestor_cgroup_id(skb, level);
		if (!id)
			break;
		if (bpf_map_lookup_elem(&watched, &id)) {
			cg = id;
			break;
		}
	}
	if (!cg)
		return 1;

	struct dns_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 1;
	}
	barrier_var(len);
	if (len < 1 || len > DNS_MAX || bpf_skb_load_bytes(skb, off, e->data, len)) {
		bpf_ringbuf_discard(e, 0);
		return 1;
	}
	e->len = len;
	e->_pad = 0;
	e->cgroup = cg;
	bpf_ringbuf_submit(e, 0);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
