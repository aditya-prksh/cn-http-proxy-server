#ifndef FORWARDER_H
#define FORWARDER_H
#include "http_parser.h"
int forward_http_request(const HttpRequest *req,int client_fd);
#endif
