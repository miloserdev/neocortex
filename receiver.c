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
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "maps.h"

static volatile bool exiting = false;
static volatile int  limit   = 65535;

static int handle_event (
	void  *ctx,
	void  *data,
	size_t data_sz
) {
	struct data_t *event = data;
	/*
	printf("Got event: ip=%u.%u.%u.%u data=",
		   (event->ip >> 24) & 0xFF, (event->ip >> 16) & 0xFF,
		   (event->ip >> 8) & 0xFF, event->ip & 0xFF
		   );
	*/

	if (
		( limit != -1 )
		&& ( limit > 0 )
	)
	{
		limit--;
	} else {
		exit ( 0 );
	}

	printf ( "{" );
	for ( size_t i = 0; i < DATA_RAW_SIZE; i++ ) {
		printf ( "0x%02x, ", (uint8_t) event->data[i] );
	}

	printf ( "}, \n" );

	return 0;
}

static void handle_signal ( int sig ) {
	exiting = true;
}

int main (
	int    argc,
	char **argv
) {
	struct ring_buffer *rb = NULL;
	int                 ringbuf_map_fd;

	signal ( SIGINT, handle_signal );
	signal ( SIGTERM, handle_signal );

	ringbuf_map_fd = bpf_obj_get ( "/sys/fs/bpf/ringbuf_map" );
	if ( ringbuf_map_fd < 0 ) {
		perror ( "bpf_obj_get" );
		return 1;
	}

	rb = ring_buffer__new (
		ringbuf_map_fd,
		handle_event,
		NULL,
		NULL
	);

	if ( !rb ) {
		fprintf ( stderr, "Failed to create ring buffer\n" );
		return 1;
	}

	while ( !exiting ) {
		int err = ring_buffer__poll ( rb, 100 );
		if ( err < 0 ) {
			fprintf ( stderr, "ring_buffer__poll() failed: %d\n", err );
			break;
		}
	}

	ring_buffer__free ( rb );
	return 0;
}
