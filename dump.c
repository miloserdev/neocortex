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
#include <errno.h>
#include <fcntl.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "maps.h"
#include "utils.h"

int main ( int    argc,
		   char **argv ) {
	struct bpf_object *obj                    = NULL;
	int                attack_fingerprint_map = -1;
	int                ip_counter_map         = -1;

	// Открываем карту по имени через bpftool API
	ip_counter_map = bpf_obj_get ( "/sys/fs/bpf/ip_counter" );
	if ( ip_counter_map < 0 ) {
		perror ( "bpf_obj_get" );
		return -1;
	}

	attack_fingerprint_map = bpf_obj_get ( "/sys/fs/bpf/attack_fingerprint" );
	if ( attack_fingerprint_map < 0 ) {
		perror ( "bpf_obj_get" );
		return -1;
	}

	__u32           key, next_key;
	struct ip_info *value;

	int err;
	key = 0;
	while ( bpf_map_get_next_key ( attack_fingerprint_map, &key, &next_key ) == 0 ) {
		err = bpf_map_lookup_elem ( attack_fingerprint_map, &next_key, &value );
		// printf("err %d key %d \n", err, key);

		if ( err != 0 ) {
			fprintf ( stderr, "Failed lookup for key %u: %s\n", next_key, strerror ( errno ) );
			break;
		}
		/*         printf("Key (IP): %u.%u.%u.%u\n",
					(next_key >> 24) & 0xff,
					(next_key >> 16) & 0xff,
					(next_key >> 8) & 0xff,
					next_key & 0xff);
				printf("Value bytes: ");
				 */
		print_bytes ( &value, sizeof ( struct ip_info ) );

		key = next_key;
	}

	close ( attack_fingerprint_map );
	return 0;
}
