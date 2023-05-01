#ifndef X_MAPS_H
#define X_MAPS_H

#include <stdbool.h>
#include <linux/types.h>

// ifndef __BPF__
#ifdef _UAPI__LINUX_BPF_H__		// yes...
#include <bpf/bpf.h>
#else
#include <linux/bpf.h>
#endif
// #include <bpf/bpf_helpers.h>

struct ip_info
{
	__u32 counter;
	__u32 suspect;
	__u64 ns;
	_Bool ignore;
	_Bool ban;
};
/* example */
// 01 00 00 00 
// 00 00 00 00 
// e2 d5 ff 88 6a 01 
// 00 00 00 00 00
// 00 00 00 00 00

#define DATA_RAW_SIZE	64
struct data_t {
	__u32 ip;
	__u32 size;
	__u8 data[DATA_RAW_SIZE];
};

#ifdef __BPF__
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} ringbuf_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);  // IP-адрес
	__type(value, struct ip_info);
} ip_counter SEC(".maps");
#endif	//__BPF__ || __KERNEL__

#endif


/* 
struct ip_attack_info
{
//	__u32 counter;
//	_Bool ignore;

	// eth
	unsigned char	h_dest[ETH_ALEN];	//	destination eth addr
	unsigned char	h_source[ETH_ALEN];	//	source ether addr

	// ip
		__be32	saddr;
		__be32	daddr;

	// tcp
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
};

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);  // IP-адрес
	__type(value, struct ip_attack_info);
} ip_attack_counter SEC(".maps");
 */
