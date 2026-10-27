#define _POSIX_C_SOURCE 200809L
#include "logger.h"
#include <pthread.h>
#include <stdio.h>
#include <time.h>
static FILE *fp; static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER;
void logger_init(const char *name){pthread_mutex_lock(&mu);if(fp)fclose(fp);fp=name?fopen(name,"a"):NULL;pthread_mutex_unlock(&mu);logger_log("INFO","Logger initialized");}
void logger_log(const char *level,const char *message){time_t now=time(NULL);struct tm tmv;char ts[32];if(!level||!message)return;localtime_r(&now,&tmv);strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",&tmv);pthread_mutex_lock(&mu);fprintf(stdout,"[%s] [%s] %s\n",ts,level,message);fflush(stdout);if(fp){fprintf(fp,"[%s] [%s] %s\n",ts,level,message);fflush(fp);}pthread_mutex_unlock(&mu);}
void logger_close(void){pthread_mutex_lock(&mu);if(fp){fclose(fp);fp=NULL;}pthread_mutex_unlock(&mu);}
