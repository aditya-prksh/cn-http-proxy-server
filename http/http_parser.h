#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H
#include <stddef.h>
#define MAX_METHOD_SIZE 16
#define MAX_HOST_SIZE 256
#define MAX_PATH_SIZE 4096
#define MAX_VERSION_SIZE 16
#define MAX_HEADER_SIZE 16384

typedef struct {
    char method[MAX_METHOD_SIZE];
    char host[MAX_HOST_SIZE];
    char path[MAX_PATH_SIZE];
    char version[MAX_VERSION_SIZE];
    int port;
    int is_connect;
    char raw_headers[MAX_HEADER_SIZE];
} HttpRequest;
int parse_http_request(const char *raw, HttpRequest *out, char *err, size_t err_size);
#endif
