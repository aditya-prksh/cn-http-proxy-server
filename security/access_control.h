#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H
void access_control_init(void);
int is_host_allowed(const char *host);
int block_host(const char *host);
int unblock_host(const char *host);
#endif
