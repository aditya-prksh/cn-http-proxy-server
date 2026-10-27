#include "access_control.h"
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#define MAX_BLOCKED 128
#define HOST_LEN 256
static char blocked[MAX_BLOCKED][HOST_LEN]; static size_t count=0; static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER;
void access_control_init(void) { pthread_mutex_lock(&mu); memset(blocked,0,sizeof(blocked)); count=0; pthread_mutex_unlock(&mu); }
int block_host(const char *host) { if(!host||!*host||strlen(host)>=HOST_LEN)return -1; pthread_mutex_lock(&mu); for(size_t i=0;i<count;i++)if(!strcasecmp(blocked[i],host)){pthread_mutex_unlock(&mu);return 0;} if(count==MAX_BLOCKED){pthread_mutex_unlock(&mu);return -1;} strcpy(blocked[count++],host); pthread_mutex_unlock(&mu); return 0; }
int unblock_host(const char *host) { if(!host)return -1; pthread_mutex_lock(&mu); for(size_t i=0;i<count;i++)if(!strcasecmp(blocked[i],host)){for(size_t j=i;j+1<count;j++)strcpy(blocked[j],blocked[j+1]); blocked[--count][0]='\0'; pthread_mutex_unlock(&mu);return 0;} pthread_mutex_unlock(&mu);return -1; }
int is_host_allowed(const char *host) { if(!host||!*host)return 0; pthread_mutex_lock(&mu); int allowed=1; for(size_t i=0;i<count;i++)if(!strcasecmp(blocked[i],host)){allowed=0;break;} pthread_mutex_unlock(&mu); return allowed; }
