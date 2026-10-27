#define _POSIX_C_SOURCE 200809L
#include "forwarder.h"
#include "../security/cache.h"
#include "../monitoring/logger.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#define IO_BUFSZ 8192
#define SERVER_TIMEOUT 12
static int send_all(int fd, const void *vdata, size_t len)
{
    const char *data = vdata;
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        sent += (size_t)n;
    }
    return 0;
}
static int connect_server(const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *it;
    char ps[16];
    int fd = -1;
    snprintf(ps, sizeof(ps), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    int rc = getaddrinfo(host, ps, &hints, &res);
    if (rc)
    {
        char b[256];
        snprintf(b, sizeof(b), "DNS lookup failed for %s: %s", host, gai_strerror(rc));
        logger_log("ERROR", b);
        return -1;
    }
    for (it = res; it; it = it->ai_next)
    {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;
        struct timeval tv = {SERVER_TIMEOUT, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}
static int send_error(int fd, int code, const char *reason, const char *body)
{
    char h[512];
    int n = snprintf(h, sizeof(h), "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", code, reason, strlen(body));
    if (n < 0 || (size_t)n >= sizeof(h))
        return -1;
    return send_all(fd, h, (size_t)n) || send_all(fd, body, strlen(body)) ? -1 : 0;
}
static int tunnel(int client, int server)
{
    char buf[IO_BUFSZ];
    int client_open = 1, server_open = 1;
    while (client_open || server_open)
    {
        fd_set r;
        FD_ZERO(&r);
        int maxfd = -1;
        if (client_open)
        {
            FD_SET(client, &r);
            if (client > maxfd)
                maxfd = client;
        }
        if (server_open)
        {
            FD_SET(server, &r);
            if (server > maxfd)
                maxfd = server;
        }
        struct timeval tv = {60, 0};
        int rc = select(maxfd + 1, &r, NULL, NULL, &tv);
        if (rc <= 0)
            break;
        int fds[2] = {client, server};
        for (int i = 0; i < 2; i++)
        {
            int from = fds[i], to = fds[1 - i];
            if ((i == 0 && client_open && FD_ISSET(from, &r)) || (i == 1 && server_open && FD_ISSET(from, &r)))
            {
                ssize_t n = recv(from, buf, sizeof(buf), 0);
                if (n <= 0)
                {
                    if (i == 0)
                        client_open = 0;
                    else
                        server_open = 0;
                    shutdown(to, SHUT_WR);
                    continue;
                }
                if (send_all(to, buf, (size_t)n) < 0)
                {
                    client_open = server_open = 0;
                    break;
                }
            }
        }
    }
    return 0;
}
static int forward_connect(const HttpRequest *req, int client)
{
    int server = connect_server(req->host, req->port);
    if (server < 0)
        return send_error(client, 502, "Bad Gateway", "Unable to connect to tunnel destination\n");
    const char *ok = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: CN-Proxy-Server\r\n\r\n";
    if (send_all(client, ok, strlen(ok)) < 0)
    {
        close(server);
        return -1;
    }
    char m[320];
    snprintf(m, sizeof(m), "CONNECT tunnel established to %s:%d", req->host, req->port);
    logger_log("INFO", m);
    tunnel(client, server);
    close(server);
    return 0;
}
static int build_request(const HttpRequest *r, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s %s %s\r\nHost: %s%s%s\r\n", r->method, r->path, r->version, strchr(r->host, ':') ? "[" : "", r->host, strchr(r->host, ':') ? "]" : "");
    if (n < 0 || (size_t)n >= cap)
        return -1;
    size_t used = (size_t)n;
    char *copy = strdup(r->raw_headers);
    if (!copy)
        return -1;
    char *save = NULL, *line = strtok_r(copy, "\r\n", &save);
    (void)line;
    while ((line = strtok_r(NULL, "\r\n", &save)))
    {
        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = '\0';
        if (!strcasecmp(line, "Host") || !strcasecmp(line, "Connection") || !strcasecmp(line, "Proxy-Connection") || !strcasecmp(line, "Proxy-Authorization") || !strcasecmp(line, "Keep-Alive"))
            continue;
        *colon = ':';
        n = snprintf(out + used, cap - used, "%s\r\n", line);
        if (n < 0 || (size_t)n >= cap - used)
        {
            free(copy);
            return -1;
        }
        used += (size_t)n;
    }
    free(copy);
    n = snprintf(out + used, cap - used, "Connection: close\r\n\r\n");
    if (n < 0 || (size_t)n >= cap - used)
        return -1;
    return (int)(used + (size_t)n);
}


static int parse_content_length(const char *headers, long long *length)
{
    const char *p = headers;
    int found = 0;
    *length = -1;

    while (*p)
    {
        const char *end = strstr(p, "\r\n");
        if (!end)
            break;

        if (end == p)
            break;

        const char *colon = memchr(p, ':', (size_t)(end - p));
        if (colon && (size_t)(colon - p) == 14 &&
            strncasecmp(p, "Content-Length", 14) == 0)
        {
            char value[32];
            size_t len = (size_t)(end - colon - 1);

            while (len > 0 && (colon[1] == ' ' || colon[1] == '\t'))
            {
                colon++;
                len--;
            }

            if (len == 0 || len >= sizeof(value))
                return -1;

            memcpy(value, colon + 1, len);
            value[len] = '\0';

            char *tail;
            errno = 0;
            long long parsed = strtoll(value, &tail, 10);
            if (errno || tail == value || *tail != '\0' || parsed < 0)
                return -1;

            if (found && parsed != *length)
                return -1;

            *length = parsed;
            found = 1;
        }

        p = end + 2;
    }

    return found;
}

int forward_http_request(const HttpRequest *req, int client)
{
    char key[4608], request[24576], buf[IO_BUFSZ];
    unsigned char cached[MAX_CACHE_DATA];
    size_t cached_size = 0;
    int server, request_len, cacheable = !strcmp(req->method, "GET");
    if (req->is_connect)
        return forward_connect(req, client);
    snprintf(key, sizeof(key), "%s:%d%s", req->host, req->port, req->path);
    if (cacheable)
    {
        int hit = cache_get(key, cached, sizeof(cached), &cached_size);
        if (hit == 1)
        {
            logger_log("INFO", "Cache HIT");
            return send_all(client, cached, cached_size);
        }
        logger_log("INFO", hit < 0 ? "Cache entry too large for buffer" : "Cache MISS");
    }
    request_len = build_request(req, request, sizeof(request));
    if (request_len < 0)
        return send_error(client, 400, "Bad Request", "Request too large\n");
    server = connect_server(req->host, req->port);
    if (server < 0)
        return send_error(client, 502, "Bad Gateway", "Could not connect to destination server\n");
    if (send_all(server, request, (size_t)request_len) < 0)
    {
        close(server);
        return send_error(client, 502, "Bad Gateway", "Could not send request to destination server\n");
    }
    size_t captured = 0;
int overflow = 0, first = 1, status = 0, receive_failed = 0;
char response_headers[32768];
size_t header_bytes = 0;
int headers_complete = 0;
int has_content_length = 0;
long long expected_body_bytes = -1;
size_t response_body_bytes = 0;
int response_incomplete = 0;
int no_response_body = 0;
    
    for (;;)
    {
        ssize_t n = recv(server, buf, sizeof(buf), 0);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;

            receive_failed = 1;

            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                logger_log("WARN", "Destination response timed out");

                if (first)
                {
                    close(server);
                    return send_error(
                        client,
                        504,
                        "Gateway Timeout",
                        "Destination server response timed out\n");
                }
            }
            else
            {
                logger_log("ERROR", "Receive from destination failed");
            }

            break;
        }

                if (n == 0)
            break;

        
        if (first)
        {
            char tmp[64] = {0};
            size_t z = (size_t)n < sizeof(tmp) - 1
                           ? (size_t)n
                           : sizeof(tmp) - 1;

            memcpy(tmp, buf, z);

            if (sscanf(tmp, "HTTP/%*s %d", &status) != 1)
            {
                response_incomplete = 1;
                cacheable = 0;
            }

            first = 0;
        }

                if (!headers_complete)
        {
            size_t available = sizeof(response_headers) - 1 - header_bytes;
            size_t copy_len = (size_t)n < available
                                  ? (size_t)n
                                  : available;

            if (copy_len > 0)
            {
                memcpy(response_headers + header_bytes, buf, copy_len);
                header_bytes += copy_len;
                response_headers[header_bytes] = '\0';
            }

            char *header_end = strstr(response_headers, "\r\n\r\n");

            if (header_end != NULL)
            {
                size_t header_end_offset =
                    (size_t)(header_end + 4 - response_headers);

                long long parsed_length = -1;
                int parsed = parse_content_length(
                    response_headers, &parsed_length);

                headers_complete = 1;

                if (parsed < 0)
                {
                    response_incomplete = 1;
                    cacheable = 0;
                }
                else if (parsed == 1)
                {
                    has_content_length = 1;
                    expected_body_bytes = parsed_length;
                }

                no_response_body =
                    (status >= 100 && status < 200) ||
                    status == 204 || status == 304;

                if (header_bytes > header_end_offset)
                {
                    response_body_bytes +=
                        header_bytes - header_end_offset;
                }
            }
            else if (header_bytes == sizeof(response_headers) - 1)
            {
                response_incomplete = 1;
                cacheable = 0;
            }
        }
        else
        {
            response_body_bytes += (size_t)n;
        }

        if (has_content_length &&
            !no_response_body &&
            response_body_bytes > (size_t)expected_body_bytes)
        {
            response_incomplete = 1;
            cacheable = 0;
        }

        if (cacheable && !overflow)
        {
            if (captured + (size_t)n < sizeof(cached))
            {
                memcpy(cached + captured, buf, (size_t)n);
                captured += (size_t)n;
            }
            else
            {
                overflow = 1;
            }
        }

        if (send_all(client, buf, (size_t)n) < 0)
        {
            logger_log("WARN", "Client disconnected while response was streaming");
            cacheable = 0;
            break;
        }
        if (first)
        {
            char tmp[64] = {0};
            size_t z = (size_t)n < sizeof(tmp) - 1 ? (size_t)n : sizeof(tmp) - 1;
            memcpy(tmp, buf, z);
            sscanf(tmp, "HTTP/%*s %d", &status);
            first = 0;
        }
        if (cacheable && !overflow)
        {
            if (captured + (size_t)n < sizeof(cached))
            {
                memcpy(cached + captured, buf, (size_t)n);
                captured += (size_t)n;
            }
            else
                overflow = 1;
        }
        if (send_all(client, buf, (size_t)n) < 0)
        {
            logger_log("WARN", "Client disconnected while response was streaming");
            cacheable = 0;
            break;
        }
    }
    close(server);
    
        if (headers_complete &&
        !response_incomplete &&
        (!has_content_length ||
         no_response_body ||
         response_body_bytes == (size_t)expected_body_bytes) &&
        cacheable &&
        !receive_failed &&
        !overflow &&
        captured > 0 &&
        status >= 200 &&
        status < 300)
{
    cache_put(key, cached, captured);
    logger_log("INFO", "Cache STORE: response stored");
}
else if (cacheable)
{
    logger_log("WARN", "Cache STORE skipped");
}
    return 0;
}
