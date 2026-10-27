#define _POSIX_C_SOURCE 200809L
#include "connection_handler.h"
#include "../http/http_parser.h"
#include "../http/forwarder.h"
#include "../security/access_control.h"
#include "../monitoring/logger.h"
#include "../monitoring/error_handler.h"
#include "../monitoring/performance.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define MAX_REQUEST 16384
static int send_simple(int fd,int code,const char *reason,const char *body){char h[512];int n=snprintf(h,sizeof(h),"HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",code,reason,strlen(body));if(n<0||(size_t)n>=sizeof(h))return -1;if(send(fd,h,(size_t)n,0)<0)return -1;return send(fd,body,strlen(body),0)<0?-1:0;}
void *handle_client(void *arg){int fd=*(int*)arg;free(arg);double start=performance_start();struct timeval tv={10,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));char raw[MAX_REQUEST+1];size_t used=0;int complete=0;while(used<MAX_REQUEST){ssize_t n=recv(fd,raw+used,MAX_REQUEST-used,0);if(n<0){if(errno==EINTR)continue;if(errno==EAGAIN||errno==EWOULDBLOCK)send_simple(fd,408,"Request Timeout","Timed out waiting for request headers\n");else report_error("CLIENT","recv failed");goto done;}if(n==0)goto done;used+=(size_t)n;raw[used]='\0';if(strstr(raw,"\r\n\r\n")){complete=1;break;}}if(!complete){send_simple(fd,431,"Request Header Fields Too Large","Request headers are too large\n");goto done;}HttpRequest req;char err[256];int p=parse_http_request(raw,&req,err,sizeof(err));if(p==-2){send_simple(fd,501,"Not Implemented","Only GET, HEAD and CONNECT are supported\n");goto done;}if(p<0){logger_log("WARN",err);send_simple(fd,400,"Bad Request","Invalid HTTP request\n");goto done;}if(!is_host_allowed(req.host)){char m[320];snprintf(m,sizeof(m),"Blocked destination: %s",req.host);logger_log("WARN",m);send_simple(fd,403,"Forbidden","Destination blocked by proxy\n");goto done;}char m[512];snprintf(m,sizeof(m),"Received %.15s request for %.200s:%d%.240s",req.method,req.host,req.port,req.is_connect?" (CONNECT)":req.path);logger_log("INFO",m);if(forward_http_request(&req,fd)<0)report_error("FORWARD","Forwarding failed");done:{double ms=performance_elapsed_ms(start);if(ms>=0){char b[128];snprintf(b,sizeof(b),"Request completed in %.2f ms",ms);logger_log("INFO",b);}}close(fd);return NULL;}
