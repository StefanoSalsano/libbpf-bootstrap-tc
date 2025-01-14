// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#if 1
#include <vmlinux.h>
#include <errno.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2

/*   */
#define CLOCK_BOOTTIME		7

#else
#include <time.h>
#include <errno.h>

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#endif

#define ETH_P_IP	0x0800 /* Internet Protocol packet */
#define ETH_P_IPV6	0x86DD /* Internet Protocol V6 packet */

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

/*
 * Note: including linux/compiler.h or linux/kernel.h for the macros below
 * conflicts with vmlinux.h include in BPF files, so we define them here.
 *
 * Following functions are taken from kernel sources and
 * break aliasing rules in their original form.
 *
 * While kernel is compiled with -fno-strict-aliasing,
 * perf uses -Wstrict-aliasing=3 which makes build fail
 * under gcc 4.4.
 *
 * Using extra __may_alias__ type to allow aliasing
 * in this case.
 */
typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
	case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
	case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
	case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
	default:
		asm volatile ("" : : : "memory");
		__builtin_memcpy((void *)res, (const void *)p, size);
		asm volatile ("" : : : "memory");
	}
}

#define READ_ONCE(x)					\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__c = { 0 } };			\
	__read_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

#if 0
static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
	case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
	case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
	case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
	default:
		asm volatile ("" : : : "memory");
		__builtin_memcpy((void *)p, (const void *)res, size);
		asm volatile ("" : : : "memory");
	}
}

#define WRITE_ONCE(x, val)				\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__val = (val) }; 			\
	__write_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})
#endif

/* in KB */
#define RB_SIZE (254 * 1024)
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RB_SIZE);
} rbuf SEC(".maps");

struct hmap_elem_ab {
	__u64 a;
	__u64 b;
};

struct hmap_elem {
	__u64 init;
	__u64 counter;
	/* protected by bpf spin lock */
	struct hmap_elem_ab ab;

	struct bpf_timer timer;
	struct bpf_spin_lock lock;
	/* NOTE: that sizeof(lock) is 32 bit wide. If we need to move it in the
	 * structure we should fill the holes manually to avoid the verfier
	 * complains about the structure layout, e.g. strange errors such as
	 * missing timer definition in map during timer set up, etc.
	 */
	__u32 pad0;
};

#define HMAP_MAX_ENTRIES 256
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HMAP_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct hmap_elem);
} hmap SEC(".maps");

enum {
	KEY_PROTO_UNDEF	= 0,
	KEY_PROTO_IP	= 1,
};

struct test_hmap_elem {
	__u32 hit_counter;
};

/* test map used for checking syscal bpf invokation from userland */
#define TEST_HMAP_MAX_ENTRIES 1024
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TEST_HMAP_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct test_hmap_elem);
} test_hmap SEC(".maps");

static __always_inline void
update_map_block_protected(struct hmap_elem *helem,
			   struct hmap_elem_ab *copy_ab)
{
	struct hmap_elem_ab *ab = &helem->ab;

	bpf_spin_lock(&helem->lock);

	/* some trival ops that must be considered as a whole */
	++ab->a;
	ab->b = ab->a << 1;

	if (copy_ab)
		memcpy(copy_ab, ab, sizeof(*copy_ab));

	bpf_spin_unlock(&helem->lock);
}

#if ALWAYS_PRINT_UPDATE
static __always_inline void print_hmap_elem_ab(struct hmap_elem_ab *ab)
{
	bpf_printk("hmap_elem_ab (a=%llu, b=%llu)", ab->a, ab->b);
}
#endif

static __always_inline int update_test_hmap(struct hmap_elem *helem)
{
	struct hmap_elem_ab copy_ab;
	struct test_hmap_elem *val;
	__u64 counter;
	__u32 key;

	update_map_block_protected(helem, &copy_ab);
#if ALWAYS_PRINT_UPDATE
	print_hmap_elem_ab(&copy_ab);
#endif

	/* READ_ONCE as counter could be modified by another cpu */
	counter = READ_ONCE(helem->counter);
	key = counter & (TEST_HMAP_MAX_ENTRIES - 1);

	val = bpf_map_lookup_elem(&test_hmap, &key);
	if (!val) {
		struct test_hmap_elem init = {
			.hit_counter = 1,
		};

		return bpf_map_update_elem(&test_hmap, &key, &init, 0);
	}

	__sync_fetch_and_add(&val->hit_counter, 1);

	return 0;
}

#define BPF_TIMER_TIMEOUT ((__u64)5000000000)

static int timer_cb(void *map, int *key, struct hmap_elem *helem)
{
	struct hmap_elem_ab copy_ab;
	struct event *e;

	update_map_block_protected(helem, &copy_ab);

	bpf_printk("timer_cb called, key=%d, helem->counter=%llu, (a=%llu, b=%llu)",
		   *key, helem->counter, copy_ab.a, copy_ab.b);

	/* let's send data to userspace using ring buffer */
	e = bpf_ringbuf_reserve(&rbuf, sizeof(*e), 0);
	if (!e)
		/* no space left on ring buffer */
		goto out;

	/* fill the event */
	e->ts = bpf_ktime_get_ns();
	/* TODO: harcoded at the moment */
	e->flowid = 1;
	e->counter = copy_ab.a;

	bpf_ringbuf_submit(e, 0);
out:
	return 0;
}

static __always_inline int timer_init(void *map, struct hmap_elem *helem)
{
	int rc;

	rc = bpf_timer_init(&helem->timer, map, CLOCK_BOOTTIME);
	if (rc) {
		bpf_printk("bpf_timer_init() rc=%d", rc);
		return rc;
	}

	rc = bpf_timer_set_callback(&helem->timer, timer_cb);
	if (rc) {
		bpf_printk("bpf_timer_set_callback() rc=%d", rc);
		return rc;
	}

	return 0;
}

/*   */
static __always_inline
struct hmap_elem *hmap_elem_init_or_get(void *map, __u32 *key)
{
	struct hmap_elem *val, init;
	int rc;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	/* we need to initialize the element */
	memset(&init, 0, sizeof(init));
	init.counter = 0;

	/* note that updating an hashtable element is an atomic op */
	rc = bpf_map_update_elem(map, key, &init, BPF_NOEXIST);
	if (rc) {
		if (rc == -EEXIST)
			/* another cpu has just created the entry, give up*/
			goto lookup;

		/* other errors are not tolerated */
		return NULL;
	}

lookup:
	val = bpf_map_lookup_elem(map, key);
	if (!val)
		return NULL;

	/* see https://reviews.llvm.org/D72184 */
	if (__sync_lock_test_and_set(&val->init, 1))
		/* already initialized */
		return val;

	/* only a single CPU can be here */

	/* we want to initialize a timer only once.
	 * A timer needs to be defined inside a map element which is already
	 * stored in the map. For this reason, we cannot  use a
	 * publish/subscribe approach - e.g. create a map element, initialize
	 * the timer within it and finally update the map with that element.
	 * Publish allows cpus to see the whole map element fully initialized
	 * or not.
	 *
	 * Our approach in this case, is to allow *only* a  CPU to initialized
	 * the timer when a new map element is createde and pushed into the
	 * map. However, in the mean while the CPU is taking the element lock
	 * and initialize the timer, another CPU could reference to that
	 * element finding that timer is not still initialized. We admit this
	 * corner case as it could happen only the first time a new map element
	 * is created inside the map.
	 */
	rc = timer_init(map, val);
	if (rc)
		return NULL;

	return val;
}

#define skb_data(addr)	((void *)(__u64)(addr))

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = skb_data(ctx->data_end);
	void *data = skb_data(ctx->data);
	struct hmap_elem *helem;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key;
	int rc;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	/* here only if we are handling IP packets */

	bpf_printk("! Got IP packet: tot_len: %d, ttl: %d",
		   bpf_ntohs(l3->tot_len), l3->ttl);

	key = KEY_PROTO_IP;
	helem = hmap_elem_init_or_get(&hmap, &key);
	if (!helem) {
		bpf_printk("invalid hmap_elem object");
		goto drop;
	}

	/* atomic add (increment) */
	__sync_fetch_and_add(&helem->counter, 1);

	/* start timer */
	rc = bpf_timer_start(&helem->timer, BPF_TIMER_TIMEOUT, 0);
	if (rc) {
		if (rc == -EINVAL) {
			/* This use case can be tolerated, as it is very rare.
			 * If we have arrived at this point, it indicates that
			 * two packets are being processed simultaneously on
			 * two different CPUs, and both are attempting to
			 * initialize the corresponding element. However, the
			 * operation is intended to be performed by only one
			 * CPU.
			 * Therefore, it is possible that while one CPU is
			 * initializing the timer, the completed operation may
			 * not yet be visible on the current CPU.
			 */
			bpf_printk("bpf_timer not started yet.");
			goto out;
		}

		bpf_printk("bpf_timer_start() rc=%d", rc);
		goto drop;
	}
out:
	/* fill test map used for retrieving hash entries from userland */
	update_test_hmap(helem);

	return TC_ACT_OK;

drop:
	bpf_printk("Dropped IP packet");
	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
