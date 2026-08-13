// SPDX-License-Identifier: GPL-2.0
/* sk_lookup demo: steer configured ports to a listening socket.
 *
 * Product model: every steered port maps to one internal listen. Protocol
 * (plaintext HTTP vs TLS) is NOT decided here — production OpenResty/Tengine
 * does that on the listen via https_allow_http.
 *
 * Stock OpenResty 1.19.3.2 has no https_allow_http, so the demo may register
 * a second listen FD (redir_socket key 1) as a fallback. open_ports values
 * are sockmap indices (0 or 1), not a boolean.
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	/* 131072: M3 30K/60K fills need >>1024. Hash maps should not sit at 100%
	 * occupancy (60K/65536 ≈ 92%), so 2×64K gives headroom.
	 * Memory: kernel precharges max_entries × hash-elem overhead (not just
	 * u16+u8). Expect ~8–16 MB memlock for this map (bpftool map show);
	 * old 1024-entry map was ~64–128 KB. Userspace RSS is not the 60K×port
	 * cost — that lives in the kernel map. Restart the loader once after
	 * this change so the new size is pinned; OpenResty need not reload.
	 */
	__uint(max_entries, 131072);
	__type(key, __u16);   /* destination port (host byte order as in ctx->local_port) */
	__type(value, __u8);  /* redir_socket sockmap index (0 = primary, 1 = stock TLS fallback) */
} open_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} redir_socket SEC(".maps");

SEC("sk_lookup")
int dispatch(struct bpf_sk_lookup *ctx)
{
	__u16 port;
	__u8 *slot;
	struct bpf_sock *sk;
	__u32 key;
	long err;

	/* Only TCP for this demo */
	if (ctx->protocol != IPPROTO_TCP)
		return SK_PASS;

	port = ctx->local_port;
	slot = bpf_map_lookup_elem(&open_ports, &port);
	if (!slot)
		return SK_PASS; /* not our port — leave to normal bind lookup */

	key = *slot;
	if (key > 1)
		return SK_DROP;

	sk = bpf_map_lookup_elem(&redir_socket, &key);
	if (!sk)
		return SK_DROP;

	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return err ? SK_DROP : SK_PASS;
}
