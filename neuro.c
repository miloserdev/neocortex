#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <bits/pthreadtypes.h>
#include <pthread.h>

#include "debug.h"
#include "filter.h"
#include "maps.h"
#include "utils.h"

// #include "perceptron.c"
#include <dlfcn.h>
int   ( *neuro_init )( );
float ( *predict ) ( const unsigned char *input );

/* threads */
pthread_t receiver_thread;
void     *receiver_thread_func ( void *data );

pthread_t pardon_thread;
void     *pardon_thread_func ( void *data );

pthread_mutex_t thread_mutex;
int             threads_init ( void );

/* signals */
static volatile bool exiting = false;

static void handle_signal ( int sig ) {
	debug ( "killing... %d ", 0 );
	exiting = true;
	usleep ( (__useconds_t) 1000000 );
	exit ( 0 );
}

/* maps */
int ringbuf_map_fd;
int ip_info_map_fd;

int ip_info_init ( void );
int ip_info_ban_ip ( __u32 key );
int ip_info_suspect_plus_ip ( __u32 key );
int ip_info_pardon_ip ( __u32 key );

int threads_init ( void ) {
	int _ret = 0;

	_ret += pthread_create ( &receiver_thread, NULL, receiver_thread_func, "receiver_thread" );

	_ret += pthread_create ( &pardon_thread, NULL, pardon_thread_func, "pardon_thread" );

	return _ret;
}

static int handle_event (
	void  *ctx,
	void  *data,
	size_t data_sz
) {
	struct data_t *event = data;

	__u32 ip = __builtin_bswap32 ( event->ip );

	float res = predict ( event->data /* , event->size */ );

	debug (
		"[%3u.%3u.%3u.%3u] \t -> size: [%-4d] \t %ff \t %s ",
		( ip >> 24 ) & 0xFF, ( ip >> 16 ) & 0xFF,
		( ip >> 8 ) & 0xFF, ip & 0xFF,
		event->size,
		res, res > 0.3 ? "ATTACK" : "OK"
	);

	if ( res > 0.3 ) /* attack */
	{
		ip_info_suspect_plus_ip ( ip );
	}

	return 0;
}

void *receiver_thread_func ( void *data ) {
	debug ( "thread started %s ", (char *) data );

	struct ring_buffer *rb = NULL;

	ringbuf_map_fd = bpf_obj_get ( "/sys/fs/bpf/ringbuf_map" );
	if (
		0 > ringbuf_map_fd
	) {
		debug ( "bpf_obj_get() failed: %d ", ringbuf_map_fd );
		return (void *) 1;
	}

	rb = ring_buffer__new (
		ringbuf_map_fd,
		handle_event,
		NULL,
		NULL
	);

	if (
		(bool) ( !rb )
	) {
		debug ( "ring_buffer__new() failed: %d ", 1 );
		return (void *) 1;
	}

	while (
		(bool) ( !exiting )
	) {
		int err = ring_buffer__poll ( rb, 100 );
		if ( err < 0 ) {
			debug ( "ring_buffer__poll() failed: %d ", err );
			break;
		}
	}

	ring_buffer__free ( rb );

	return 0;
}

void *pardon_thread_func ( void *data ) {
	debug ( "thread started %s ", (char *) data );

	__u32          key, next_key;
	struct ip_info value;

	while (
		(bool) ( !exiting )
	) {
		int err;
		key = 0;
		while ( bpf_map_get_next_key ( ip_info_map_fd, &key, &next_key ) == 0 ) {
			err = bpf_map_lookup_elem ( ip_info_map_fd, &next_key, &value );
			//	debug("err %d key %d ", err, key);

			if (
				0 != err
			) {
				debug ( "Failed lookup for key %u ", next_key );
				// break;
				goto _pass;
			}

			//	print_bytes(&value, sizeof(struct ip_info));

			if (
				(bool) ( value.ignore )
				&& 0 == (int) value.counter
				&& 0 == (int) value.suspect
			) {
				debug ( "ip [%u.%u.%u.%u] ignored ", ( key >> 24 ) & 0xFF, ( key >> 16 ) & 0xFF, ( key >> 8 ) & 0xFF, key & 0xFF );

				goto _pass;
			}

			// __u32 ip = __builtin_bswap32(next_key);

			ip_info_pardon_ip ( next_key );

			/*
			// or
			bpf_map_delete_elem(ip_info_map_fd, &next_key);
			 */

			key = next_key;
		}

	_pass:

		usleep ( THRESHOLD_PARDON_US );
	}

	return 0;
}

int ip_info_init ( void ) {
	ip_info_map_fd = bpf_obj_get ( "/sys/fs/bpf/ip_counter" );
	if (
		0 > ip_info_map_fd
	) {
		perror ( "bpf_obj_get" );
		return 1;
	}

	return 0;
}

int ip_info_ban_ip ( __u32 key ) {
	struct ip_info value = {
		.counter = 999,
		.ban     = true,
	};

	if (
		0 > bpf_map_update_elem ( ip_info_map_fd, &key, &value, BPF_ANY )
	) {
		perror ( "bpf_map_update_elem" );
		return 1;
	}

	debug ( "ip [%u.%u.%u.%u] banned ", ( key >> 24 ) & 0xFF, ( key >> 16 ) & 0xFF, ( key >> 8 ) & 0xFF, key & 0xFF );

	return 0;
}

int ip_info_suspect_plus_ip ( __u32 key ) {
	struct ip_info value;

	if (
		0 > bpf_map_lookup_elem ( ip_info_map_fd, &key, &value )
	) {
		perror ( "bpf_map_lookup_elem" );
		return 1;
	}

	value.suspect++;

	if (
		(int) value.suspect > 10
	) {
		value.ban = true;
	}

	if (
		0 > bpf_map_update_elem ( ip_info_map_fd, &key, &value, BPF_ANY )
	) {
		perror ( "bpf_map_update_elem" );
		return 1;
	}

	debug ( "ip [%u.%u.%u.%u] suspect %d", ( key >> 24 ) & 0xFF, ( key >> 16 ) & 0xFF, ( key >> 8 ) & 0xFF, key & 0xFF, value.suspect );

	return 0;
}

int ip_info_pardon_ip ( __u32 key ) {
	struct ip_info value;

	if (
		0 > bpf_map_lookup_elem ( ip_info_map_fd, &key, &value )
	) {
		perror ( "bpf_map_lookup_elem" );
		return 1;
	}

	value.counter = 80;
	value.suspect = 0;
	value.ban     = false;

	if (
		0 > bpf_map_update_elem ( ip_info_map_fd, &key, &value, BPF_ANY )
	) {
		perror ( "bpf_map_update_elem" );
		return 1;
	}

	debug ( "ip [%u.%u.%u.%u] pardoned ", ( key >> 24 ) & 0xFF, ( key >> 16 ) & 0xFF, ( key >> 8 ) & 0xFF, key & 0xFF );

	return 0;
}

int main ( void ) {

	/* init lib */
	void *lib = dlopen ( "./libperceptron.so", RTLD_NOW );
	if ( !lib ) {
		fprintf ( stderr, "dlopen failed: %s\n", dlerror( ) );
		return 1;
	}

	*( &neuro_init ) = dlsym ( lib, "neuro_init" );
	*( &predict )    = dlsym ( lib, "predict" );

	neuro_init( );

#if __LEARN__ == 1
	return 0;
#endif

	ip_info_init( );

	threads_init( );

	signal ( SIGINT, handle_signal );
	signal ( SIGTERM, handle_signal );

	while ( 1 )
		;    // for threads
}
