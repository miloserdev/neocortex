/*
 * Project: DDoS Detection eBPF
 * SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023 miloserdev
 *
 * This file is part of the DDoS Detection eBPF project.
 * You may redistribute it and/or modify it under the terms of
 * the GNU General Public License version 2 or the BSD 3-Clause License.
 *
 * This file is provided "AS IS" without any warranties.
 */

// ❤️

/* this model is pre-trained! */

~~~wont work because of float ~~~

#define INPUT_SIZE 28

  int weights[INPUT_SIZE]
	= {
		146.726257,
		98.522560,
		125.887115,
		139.113770,
		90.624191,
		0.810854,
		47.295021,
		62.724186,
		0.917521,
		47.667629,
		-1.871353,
		-23.879005,
		46.420315,
		-27.500713,
		5.600751,
		58.640572,
		37.176460,
		-47.605495,
		-30.940617,
		9.045582,
		-64.040459,
		44.105637,
		-65.355675,
		-129.341934,
		0.332767,
		62.025013,
		48.740997,
		-221.610611,
};

int bias = -30.265423;

#define N_TERMS 20

int exp ( int x ) {
	int sum  = 1;
	int term = 1;
	for ( int n = 1; n <= N_TERMS; ++n ) {
		term *= x / n;
		sum  += term;
	}
	return sum;
}

static int sigmoid ( int x ) {
	return (int) 1 / ( (int) 1 + exp ( -x ) );
}

int predict ( void *data,
			  int   data_end ) {
	const unsigned char *input = data;
}

#include <stdbool.h>
#include <stdint.h>

#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#define __BPF__ 1
#include "maps.h"

#include "filter.h"

#define LOOPBACK_IFINDEX 1    // yes...

SEC ( "xdp" )

int xdp_ddos_detect ( struct xdp_md *ctx ) {
	void *data     = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	__u64 data_size = data_end - data;
	__u64 now       = bpf_ktime_get_ns( );

	bpf_printk ( "data %d", data_size );

	struct ethhdr *eth = data;
	if (
		(void *) ( eth + 1 ) > data_end
		|| eth->h_proto != __constant_htons ( ETH_P_IP )
	) {
		goto __pass;
	}

	struct iphdr *ip = (void *) ( eth + 1 );
	if (
		(void *) ( ip + 1 ) > data_end
	) {
		goto __pass;
	}

	if (
		ctx->ingress_ifindex == LOOPBACK_IFINDEX
		|| ip->saddr == ip->daddr
	) {
		bpf_printk ( "loopback pass " );
		goto __drop;
	}

	struct tcphdr *tcp = (void *) ip + ip->ihl * 4;
	if (
		(void *) ( tcp + 1 ) > data_end
	) {
		goto __pass;
	}

	__u8  ttl    = ip->ttl;
	__u16 window = __builtin_bswap16 ( tcp->window );

	if (
		ttl != 64
		&& ttl != 128
		&& ttl != 255
	) {
		// bpf_printk("malformed ttl 0x%02x ", ttl);
		//  return XDP_DROP; // malformed TTL ???
	}

	if (
		window < 1000
		|| window > 65535
	) {
		// bpf_printk("malformed window 0x%04x ", window);
		//  return XDP_DROP; // malformed window ???
	}

	if ( tcp->dest == __constant_htons ( 443 ) ) {
		// bpf_printk("HTTP traffic detected ");
	}

	void *payload = (void *) tcp + tcp->doff * 4;
	if ( payload > data_end ) {
		goto __pass;
	}

	size_t payload_len = data_end - payload;

	__u32           s_ip  = __builtin_bswap32 ( ip->saddr );
	__u32           d_ip  = __builtin_bswap32 ( ip->daddr );
	struct ip_info *entry = bpf_map_lookup_elem ( &ip_counter, &s_ip );

	if (                                                           /* detection */
		 ( ( tcp->syn ) && !( tcp->ack ) )                         // by SYN / ACK
		 || ( entry && ( now - entry->ns ) < ( 50000 * 1000 ) )    // by nanosec
	) {
		if ( !entry )
		{ /* not in map */
			struct ip_info val = {
				.counter = 1,
				.ns      = now,
			};

			bpf_map_update_elem ( &ip_counter, &s_ip, &val, BPF_ANY );

		} else
		{ /* in map */

			if (
				(bool) ( entry->ignore )
			) {
				// bpf_printk("ignore %u ", s_ip);
				goto __pass;
			}

			if (
				(bool) ( entry->ban )
			) {
				bpf_printk ( "banned [%d.%d.%d.%d] [%u]", ( s_ip >> 24 ) & 0xFF, ( s_ip >> 16 ) & 0xFF, ( s_ip >> 8 ) & 0xFF, s_ip & 0xFF, s_ip );

				goto __drop;
			}

			( entry->counter )++;
			if (
				//	(now - entry->ns) < (50000 * 1000)
				(bool) ( entry->counter > THRESHOLD )
			) {
				bpf_printk ( "suspective [%d.%d.%d.%d] [%u] last %llu", ( s_ip >> 24 ) & 0xFF, ( s_ip >> 16 ) & 0xFF, ( s_ip >> 8 ) & 0xFF, s_ip & 0xFF, s_ip, entry->ns );

				// goto __drop;
			}

			( entry->ns ) = now;

			goto __process;
		}
	}

	if ( entry )
	{
		goto __pass;
	}

__process:

	bpf_printk ( "eth: src: %02x:%02x:%02x:%02x:%02x:%02x --> dst: %02x:%02x:%02x:%02x:%02x:%02x", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5] );

	bpf_printk ( "ip: proto %d src: %d.%d.%d.%d --> dst: %d.%d.%d.%d", ip->protocol, ( s_ip >> 24 ) & 0xFF, ( s_ip >> 16 ) & 0xFF, ( s_ip >> 8 ) & 0xFF, s_ip & 0xFF, ( d_ip >> 24 ) & 0xFF, ( d_ip >> 16 ) & 0xFF, ( d_ip >> 8 ) & 0xFF, d_ip & 0xFF );

	if ( entry )
	{
		bpf_printk ( "entry: count %d ", entry->counter );
	}

	int sum = 0;
	for ( size_t i = 0; i < DATA_RAW_SIZE; i++ )
	{
		sum = bias;
		if ( payload + i + 1 > data_end ) {
			break;
		}
		int fuck  = *( (__u8 *) ( payload + i ) );
		sum      += (int) fuck / (int) 255 * weights[i];
	}

	int predict = sigmoid ( sum );

	bpf_printk ( "predict >>> %d <<< ", predict );

	// bpf_printk("copied++ ");

	bpf_printk ( "payload %d ", payload_len );

	bpf_printk ( "--------------\n" );

	goto __pass;

__drop:
	return XDP_DROP;

__pass:
	return XDP_PASS;
}

char _license[] SEC ( "license" ) = "GPL";
