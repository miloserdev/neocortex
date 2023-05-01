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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "maps.h"
#include "utils.h"

int ip_counter_map_fd = -1;

__u32 ignore_list[] = {
	IP4_ADDR ( 127, 0, 0, 1 ),
	IP4_ADDR ( 192, 168, 0, 1 ),
	IP4_ADDR ( 192, 168, 1, 1 ),
};

int main ( void ) {
	ip_counter_map_fd = bpf_obj_get ( "/sys/fs/bpf/ip_counter" );
	if ( ip_counter_map_fd < 0 ) {
		perror ( "bpf_obj_get" );
		return 1;
	}

	for ( size_t i = 0; i < (size_t) ( sizeof ( ignore_list ) / sizeof ( __u32 ) ); i++ )
	{
		__u32          key   = __builtin_bswap32 ( ignore_list[i] );
		struct ip_info value = {
			.counter = 555,
			.ignore  = true,
		};

		if (
			0 > bpf_map_update_elem (
				ip_counter_map_fd,
				&key,
				&value,
				BPF_ANY
			)
		) {
			perror ( "bpf_map_update_elem" );
			return 1;
		}

		printf ( "updated %u \n", key );
	}

	close ( ip_counter_map_fd );
	return 0;
}
