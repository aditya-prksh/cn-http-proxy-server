#include "cache.h"
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#define KEY_LEN 4608
typedef struct { int valid; char key[KEY_LEN]; unsigned char data[MAX_CACHE_DATA]; size_t size; unsigned long long stamp; } Entry;
static Entry entries[MAX_CACHE_ENTRIES]; static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER; static unsigned long long clock_hand=0;
void cache_init(void){pthread_mutex_lock(&mu);memset(entries,0,sizeof(entries));clock_hand=0;pthread_mutex_unlock(&mu);}
int cache_get(const char *key,unsigned char *data,size_t cap,size_t *out){if(!key||!data||!out)return -1;pthread_mutex_lock(&mu);for(int i=0;i<MAX_CACHE_ENTRIES;i++)if(entries[i].valid&&!strcmp(entries[i].key,key)){if(entries[i].size>cap){pthread_mutex_unlock(&mu);return -1;}memcpy(data,entries[i].data,entries[i].size);*out=entries[i].size;entries[i].stamp=++clock_hand;pthread_mutex_unlock(&mu);return 1;}pthread_mutex_unlock(&mu);return 0;}
void cache_put(const char *key,const unsigned char *data,size_t size){if(!key||!data||!size||size>=MAX_CACHE_DATA||strlen(key)>=KEY_LEN)return;pthread_mutex_lock(&mu);int slot=-1;unsigned long long oldest=~0ULL;for(int i=0;i<MAX_CACHE_ENTRIES;i++){if(entries[i].valid&&!strcmp(entries[i].key,key)){slot=i;break;}if(!entries[i].valid){slot=i;break;}if(entries[i].stamp<oldest){oldest=entries[i].stamp;slot=i;}}if(slot>=0){strcpy(entries[slot].key,key);memcpy(entries[slot].data,data,size);entries[slot].size=size;entries[slot].valid=1;entries[slot].stamp=++clock_hand;}pthread_mutex_unlock(&mu);}
