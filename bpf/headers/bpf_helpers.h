/* Minimal BPF helpers used by dispatch.bpf.c (IDs from linux/bpf.h). */
#ifndef WAF_SKLOOKUP_BPF_HELPERS_H
#define WAF_SKLOOKUP_BPF_HELPERS_H

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_sk_release)(void *sock) = (void *)86;
static long (*bpf_sk_assign)(void *ctx, void *sk, __u64 flags) = (void *)124;

#endif
