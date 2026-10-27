#ifndef CACHE_H
#define CACHE_H
#include <stddef.h>
#define MAX_CACHE_ENTRIES 32
#define MAX_CACHE_DATA 65536
int cache_get(const char *key, unsigned char *data, size_t cap, size_t *out_size);
void cache_put(const char *key, const unsigned char *data, size_t size);
void cache_init(void);
#endif
