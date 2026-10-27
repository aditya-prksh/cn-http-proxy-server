#define _POSIX_C_SOURCE 200809L
#include "connection_handler.h"
#include "../security/access_control.h"
#include "../security/cache.h"
#include "../monitoring/logger.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 8888
#define BACKLOG 64
static volatile sig_atomic_t running=1; static int listen_fd=-1;
static void on_signal(int sig){(void)sig;running=0;if(listen_fd>=0)close(listen_fd);listen_fd=-1;}
int main(int argc,char **argv){int port=SERVER_PORT;if(argc==2){char *end;long x=strtol(argv[1],&end,10);if(*end||x<1||x>65535){fprintf(stderr,"Usage: %s [port 1-65535]\n",argv[0]);return EXIT_FAILURE;}port=(int)x;}else if(argc>2){fprintf(stderr,"Usage: %s [port]\n",argv[0]);return EXIT_FAILURE;}signal(SIGINT,on_signal);signal(SIGTERM,on_signal);signal(SIGPIPE,SIG_IGN);logger_init("proxy.log");access_control_init();cache_init();block_host("blocked.example");listen_fd=socket(AF_INET,SOCK_STREAM,0);if(listen_fd<0){perror("socket");return EXIT_FAILURE;}int yes=1;setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));struct sockaddr_in a;memset(&a,0,sizeof(a));a.sin_family=AF_INET;a.sin_port=htons((unsigned short)port);inet_pton(AF_INET,SERVER_HOST,&a.sin_addr);if(bind(listen_fd,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");close(listen_fd);return EXIT_FAILURE;}if(listen(listen_fd,BACKLOG)<0){perror("listen");close(listen_fd);return EXIT_FAILURE;}printf("HTTP Proxy Server listening on %s:%d\nPress Ctrl+C to stop.\n",SERVER_HOST,port);while(running){struct sockaddr_in ca;socklen_t len=sizeof(ca);int c=accept(listen_fd,(struct sockaddr*)&ca,&len);if(c<0){if(errno==EINTR)continue;if(!running)break;perror("accept");continue;}int *arg=malloc(sizeof(*arg));if(!arg){close(c);continue;}*arg=c;pthread_t t;if(pthread_create(&t,NULL,handle_client,arg)){close(c);free(arg);logger_log("ERROR","Could not create client thread");continue;}pthread_detach(t);}if(listen_fd>=0)close(listen_fd);logger_log("INFO","Proxy server stopped");logger_close();return EXIT_SUCCESS;}
