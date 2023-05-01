#ifndef X_CONFIG_UTILS
#define X_CONFIG_UTILS

#include <stdio.h>
#include <stdint.h>


#ifdef __LITTLE_ENDIAN
#define IP4_ADDR(d, c, b ,a) ((__u32)(((a) << 24) | ((b) << 16) | ((c) << 8) | (d)))
#else
#define IP4_ADDR(a, b, c, d) ((__u32)(((a) << 24) | ((b) << 16) | ((c) << 8) | (d)))
#endif

void print_bytes(void *data, size_t size) {
    unsigned char *p = (unsigned char *)data;
    for (size_t i = 0; i < size; i++)
        printf("%02x ", p[i]);
    printf("\n");
}

#endif