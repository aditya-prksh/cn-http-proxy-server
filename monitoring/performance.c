#define _POSIX_C_SOURCE 200809L
#include "performance.h"
#include <time.h>
double performance_start(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return t.tv_sec*1000.0+t.tv_nsec/1000000.0;}
double performance_elapsed_ms(double start){struct timespec t;if(start<0||clock_gettime(CLOCK_MONOTONIC,&t))return -1;return t.tv_sec*1000.0+t.tv_nsec/1000000.0-start;}
