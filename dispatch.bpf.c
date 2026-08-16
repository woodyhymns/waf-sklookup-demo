// SPDX-License-Identifier: GPL-2.0
/* sk_lookup dispatcher: steer configured (family, addr, port) tuples to a
 * listening socket owned by the local L7 engine.
 *
 * Product model: every steered port maps to one internal listen. Protocol
 * (plaintext HTTP vs TLS) is NOT decided here — production OpenResty/Tengine
 * does that on the listen via https_allow_http.
 *
 * ---------------------------------------------------------------------------
 * Production hardening (see docs/hardening.md):
 *
 *  1. Destination match is (family, addr, port), not port alone. A wildcard
 *     address (all-zero) still means "any address", so single-VIP setups keep
 *     working, but multi-VIP hosts can now isolate tenants per VIP.
 *
 *  2. IPv6 is a first-class citizen. Previously an IPv6 SYN matched a
 *     port-only key and then hit bpf_sk_assign() with an IPv4 socket, which
 *     the kernel rejects with -EAFNOSUPPORT; the program returned SK_DROP and
 *     the packet was silently lost. Unsupported families now fall through
 *     with SK_PASS.
 *
 *  3. Listen sockets are sharded per worker. redir_socket is no longer two
 *     protocol slots but SHARD_STRIDE slots per protocol group, and we pass
 *     BPF_SK_LOOKUP_F_NO_REUSEPORT so this program — not an implicit second
 *     reuseport hash — decides which worker receives the SYN. A dead worker
 *     therefore costs 1/N of new connections instead of all of them.
 *
 *  4. Every terminal path is counted, and bpf_sk_assign() failures are
 *     classified by errno. "Port unreachable" is now diagnosable from
 *     metrics alone.
 * ---------------------------------------------------------------------------
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

/* Keep in sync with rust/loader/src/pin.rs. */
#define SHARD_STRIDE 64	 /* max workers per protocol group */
#define REDIR_GROUPS 2	 /* group 0 = primary, group 1 = stock TLS fallback */
#define REDIR_MAX_ENTRIES (SHARD_STRIDE * REDIR_GROUPS)

/* bpf_sk_assign() flag: skip the reuseport hash on the socket we selected, so
 * shard selection here is authoritative. Defined locally because older UAPI
 * headers may not carry it.
 */
#ifndef BPF_SK_LOOKUP_F_NO_REUSEPORT
#define BPF_SK_LOOKUP_F_NO_REUSEPORT (1ULL << 1)
#endif

/* Destination key. Byte order matches struct bpf_sk_lookup: local_port is host
 * order, local_ip4/local_ip6 are network order. addr is all-zero for wildcard
 * ("any address on this host"), which is what a single-VIP deployment uses.
 */
struct port_key {
	__u16 port;
	__u16 family; /* AF_INET = 2, AF_INET6 = 10 */
	__u32 addr[4];
};

/* Destination value. `group` selects the protocol group inside redir_socket;
 * `shards` is how many worker slots of that group are currently populated.
 */
struct port_val {
	__u8 group;
	__u8 shards;
	__u16 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	/* 131072: M3 30K/60K fills need >>1024. Hash maps should not sit at 100%
	 * occupancy (60K/65536 ~= 92%), so 2x64K gives headroom.
	 * Memory: kernel precharges max_entries x hash-elem overhead, so memlock
	 * is constant regardless of how many ports are populated, and it is not
	 * counted in userspace RSS. See docs/capacity.md.
	 */
	__uint(max_entries, 131072);
	__type(key, struct port_key);
	__type(value, struct port_val);
} open_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, REDIR_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
} redir_socket SEC(".maps");

/* Metric slots. Keep in sync with rust/loader/src/metrics.rs. */
enum stat_slot {
	STAT_ASSIGN_OK = 0,
	STAT_PORT_MISS = 1,
	STAT_NO_SLOT = 2,
	STAT_INVALID_GROUP = 3,
	STAT_ERR_EEXIST = 4,
	STAT_ERR_EAFNOSUPPORT = 5,
	STAT_ERR_ESOCKTNOSUPPORT = 6,
	STAT_ERR_EPROTOTYPE = 7,
	STAT_ERR_OTHER = 8,
	STAT_PASS_NON_TCP = 9,
	STAT_PASS_BAD_FAMILY = 10,
	STAT_SHARD_FALLBACK = 11,
	STAT__MAX = 16,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT__MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* Rate-limited anomaly sampling. Userspace drains this to explain drops. */
struct anomaly_event {
	__u64 ts_ns;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u16 remote_port;
	__u16 local_port;
	__u16 family;
	__s16 err;
	__u32 slot;
	__u32 reason;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB */
} anomalies SEC(".maps");

/* Sampling budget. Index 0 = last emit timestamp, index 1 = emitted count. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} anomaly_gate SEC(".maps");

#define ANOMALY_MIN_INTERVAL_NS 1000000ULL /* <=1000 events/sec */

static __always_inline void bump(__u32 slot)
{
	__u64 *val = bpf_map_lookup_elem(&stats, &slot);

	if (val)
		(*val)++;
}

/* Emit at most one anomaly per ANOMALY_MIN_INTERVAL_NS so an error storm
 * cannot turn reporting into the bottleneck.
 */
static __always_inline void sample_anomaly(struct bpf_sk_lookup *ctx, __u32 reason,
					   long err, __u32 slot)
{
	__u32 zero = 0, one = 1;
	__u64 *last, *count;
	__u64 now;
	struct anomaly_event *ev;

	last = bpf_map_lookup_elem(&anomaly_gate, &zero);
	if (!last)
		return;

	now = bpf_ktime_get_ns();
	if (now - *last < ANOMALY_MIN_INTERVAL_NS)
		return;
	*last = now;

	ev = bpf_ringbuf_reserve(&anomalies, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->ts_ns = now;
	ev->family = ctx->family;
	ev->remote_port = (__u16)ctx->remote_port;
	ev->local_port = ctx->local_port;
	ev->remote_ip4 = ctx->family == 2 ? ctx->remote_ip4 : 0;
	ev->local_ip4 = ctx->family == 2 ? ctx->local_ip4 : 0;
	ev->err = (__s16)err;
	ev->slot = slot;
	ev->reason = reason;
	bpf_ringbuf_submit(ev, 0);

	count = bpf_map_lookup_elem(&anomaly_gate, &one);
	if (count)
		(*count)++;
}

/* Classify bpf_sk_assign() failures. Each errno means a different operational
 * fault, so they must not collapse into one counter:
 *   -EEXIST            another sk_lookup program already selected a socket
 *   -EAFNOSUPPORT      socket family incompatible with the packet
 *   -ESOCKTNOSUPPORT   socket is not in TCP listening state (stale worker fd)
 *   -EPROTOTYPE        L4 protocol mismatch
 */
static __always_inline void count_assign_err(long err)
{
	switch (err) {
	case -17: /* -EEXIST */
		bump(STAT_ERR_EEXIST);
		break;
	case -97: /* -EAFNOSUPPORT */
		bump(STAT_ERR_EAFNOSUPPORT);
		break;
	case -94: /* -ESOCKTNOSUPPORT */
		bump(STAT_ERR_ESOCKTNOSUPPORT);
		break;
	case -91: /* -EPROTOTYPE */
		bump(STAT_ERR_EPROTOTYPE);
		break;
	default:
		bump(STAT_ERR_OTHER);
		break;
	}
}

/* Spread connections across worker shards. The 4-tuple hash keeps a given
 * client pinned to one worker for the life of the connection attempt, which
 * is friendlier to per-worker caches than a round-robin counter.
 */
static __always_inline __u32 pick_shard(struct bpf_sk_lookup *ctx, __u8 shards)
{
	__u32 h;

	if (shards <= 1)
		return 0;

	h = ctx->remote_port ^ ((__u32)ctx->local_port << 16);
	if (ctx->family == 2)
		h ^= ctx->remote_ip4;
	else
		h ^= ctx->remote_ip6[3] ^ ctx->remote_ip6[0];

	/* Mix so low bits are not dominated by the port. */
	h ^= h >> 16;
	h *= 0x45d9f3bU;
	h ^= h >> 16;

	return h % shards;
}

static __always_inline int lookup_and_assign(struct bpf_sk_lookup *ctx,
					     struct port_key *key)
{
	struct port_val *val;
	struct bpf_sock *sk;
	__u32 slot, fallback;
	long err;

	val = bpf_map_lookup_elem(&open_ports, key);
	if (!val)
		return -1; /* caller decides: try wildcard, or SK_PASS */

	if (val->group >= REDIR_GROUPS || val->shards == 0 ||
	    val->shards > SHARD_STRIDE) {
		bump(STAT_INVALID_GROUP);
		sample_anomaly(ctx, STAT_INVALID_GROUP, 0, val->group);
		return SK_DROP;
	}

	slot = (__u32)val->group * SHARD_STRIDE + pick_shard(ctx, val->shards);

	sk = bpf_map_lookup_elem(&redir_socket, &slot);
	if (!sk) {
		/* Shard empty (worker restarting). Fall back to shard 0 of the
		 * same group before giving up, so a single dead worker does not
		 * black-hole its share of new connections.
		 */
		fallback = (__u32)val->group * SHARD_STRIDE;
		if (fallback != slot) {
			sk = bpf_map_lookup_elem(&redir_socket, &fallback);
			if (sk) {
				bump(STAT_SHARD_FALLBACK);
				slot = fallback;
			}
		}
		if (!sk) {
			bump(STAT_NO_SLOT);
			sample_anomaly(ctx, STAT_NO_SLOT, 0, slot);
			return SK_DROP;
		}
	}

	err = bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_NO_REUSEPORT);
	bpf_sk_release(sk);

	if (err) {
		count_assign_err(err);
		sample_anomaly(ctx, STAT_ERR_OTHER, err, slot);
		return SK_DROP;
	}

	bump(STAT_ASSIGN_OK);
	return SK_PASS;
}

SEC("sk_lookup")
int dispatch(struct bpf_sk_lookup *ctx)
{
	struct port_key key = {};
	int ret;

	/* Only TCP is steered. */
	if (ctx->protocol != IPPROTO_TCP) {
		bump(STAT_PASS_NON_TCP);
		return SK_PASS;
	}

	/* AF_INET = 2, AF_INET6 = 10. Anything else must fall through, never
	 * drop: an unknown family reaching bpf_sk_assign() would be rejected
	 * with -EAFNOSUPPORT and the packet lost with no bind-lookup fallback.
	 */
	if (ctx->family != 2 && ctx->family != 10) {
		bump(STAT_PASS_BAD_FAMILY);
		return SK_PASS;
	}

	key.port = ctx->local_port;
	key.family = ctx->family;

	/* Exact destination address first. */
	if (ctx->family == 2) {
		key.addr[0] = ctx->local_ip4;
	} else {
		key.addr[0] = ctx->local_ip6[0];
		key.addr[1] = ctx->local_ip6[1];
		key.addr[2] = ctx->local_ip6[2];
		key.addr[3] = ctx->local_ip6[3];
	}

	ret = lookup_and_assign(ctx, &key);
	if (ret >= 0)
		return ret;

	/* Then the wildcard entry for this family (addr all-zero). */
	key.addr[0] = 0;
	key.addr[1] = 0;
	key.addr[2] = 0;
	key.addr[3] = 0;

	ret = lookup_and_assign(ctx, &key);
	if (ret >= 0)
		return ret;

	/* Not our port — leave it to the normal bind lookup. */
	bump(STAT_PORT_MISS);
	return SK_PASS;
}
