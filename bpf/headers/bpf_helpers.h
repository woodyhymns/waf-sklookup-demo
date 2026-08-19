/* Minimal BPF helpers used by dispatch.bpf.c (IDs from linux/bpf.h).
 *
 * Kept hand-rolled rather than pulling in libbpf's bpf_helpers.h so the C and
 * Rust dataplanes compile from the same tiny, auditable surface. Helper IDs
 * come from `enum bpf_func_id` in linux/bpf.h and are stable UAPI.
 */
#ifndef WAF_SKLOOKUP_BPF_HELPERS_H
#define WAF_SKLOOKUP_BPF_HELPERS_H

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* BPF_FUNC_map_lookup_elem */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
/* BPF_FUNC_ktime_get_ns */
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
/* BPF_FUNC_sk_release */
static long (*bpf_sk_release)(void *sock) = (void *)86;
/* BPF_FUNC_sk_assign */
static long (*bpf_sk_assign)(void *ctx, void *sk, __u64 flags) = (void *)124;
/* BPF_FUNC_ringbuf_reserve */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
/* BPF_FUNC_ringbuf_submit */
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
/* BPF_FUNC_ringbuf_discard */
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

#endif
