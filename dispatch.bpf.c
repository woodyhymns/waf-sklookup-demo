// SPDX-License-Identifier: GPL-2.0
/* sk_lookup demo: steer configured ports to one listening socket */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);   /* destination port (host byte order as in ctx->local_port) */
	__type(value, __u8);  /* presence = open */
} open_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} redir_socket SEC(".maps");

SEC("sk_lookup")
int dispatch(struct bpf_sk_lookup *ctx)
{
	__u16 port;
	__u8 *open;
	struct bpf_sock *sk;
	__u32 key = 0;
	long err;

	/* Only TCP for this demo */
	if (ctx->protocol != IPPROTO_TCP)
		return SK_PASS;

	port = ctx->local_port;
	open = bpf_map_lookup_elem(&open_ports, &port);
	if (!open)
		return SK_PASS; /* not our port — leave to normal bind lookup */

	sk = bpf_map_lookup_elem(&redir_socket, &key);
	if (!sk)
		return SK_DROP;

	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return err ? SK_DROP : SK_PASS;
}
