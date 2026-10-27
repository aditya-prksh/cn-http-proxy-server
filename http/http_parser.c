#define _POSIX_C_SOURCE 200809L
#include "http_parser.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static void trim(char *s) {
    size_t n = strlen(s), start = 0;
    while (start < n && isspace((unsigned char)s[start])) start++;
    while (n > start && isspace((unsigned char)s[n-1])) n--;
    if (start) memmove(s, s + start, n - start);
    s[n-start] = '\0';
}
static int copy_field(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n >= cap) return -1;
    memcpy(dst, src, n + 1); return 0;
}
static int parse_authority(const char *authority, char *host, size_t hostcap, int *port, int default_port) {
    char tmp[MAX_HOST_SIZE + 32], *p, *end;
    long value;
    if (!authority || !*authority || strlen(authority) >= sizeof(tmp)) return -1;
    strcpy(tmp, authority); trim(tmp);
    if (tmp[0] == '[') { /* IPv6 literal */
        char *close = strchr(tmp, ']');
        if (!close) return -1;
        if (close[1] && close[1] != ':') return -1;
        if (close[1] == ':') { p = close + 2; value = strtol(p, &end, 10); if (*p == '\0' || *end || value < 1 || value > 65535) return -1; *port=(int)value; }
        else *port=default_port;
        *close='\0'; return copy_field(host, hostcap, tmp+1);
    }
    p = strrchr(tmp, ':');
    if (p && strchr(tmp, ':') == p) {
        *p++='\0'; value=strtol(p,&end,10);
        if (*p == '\0' || *end || value < 1 || value > 65535) return -1;
        *port=(int)value;
    } else *port=default_port;
    if (!*tmp) return -1;
    return copy_field(host, hostcap, tmp);
}
int parse_http_request(const char *raw, HttpRequest *out, char *err, size_t err_size) {
    char *copy=NULL, *save=NULL, *line, *method, *target, *version, *headers_end;
    char host_header[MAX_HOST_SIZE]="";
    if (!raw || !out) return -1;
    memset(out,0,sizeof(*out)); out->port=80;
    if (strlen(raw) >= MAX_HEADER_SIZE) { snprintf(err,err_size,"Request headers too large"); return -1; }
    copy=strdup(raw); if (!copy) { snprintf(err,err_size,"Out of memory"); return -1; }
    headers_end=strstr(copy,"\r\n\r\n");
    if (!headers_end) { free(copy); snprintf(err,err_size,"Incomplete HTTP headers"); return -1; }
    *headers_end='\0';
    if (copy_field(out->raw_headers,sizeof(out->raw_headers),copy) != 0) { free(copy); snprintf(err,err_size,"Headers too large"); return -1; }
    line=strtok_r(copy,"\r\n",&save);
    if (!line) { free(copy); snprintf(err,err_size,"Missing request line"); return -1; }
    char *request_save = NULL;
    method = strtok_r(line, " \t", &request_save);
    target = strtok_r(NULL, " \t", &request_save);
    version = strtok_r(NULL, " \t", &request_save);
    if (!method || !target || !version ||
        strtok_r(NULL, " \t", &request_save)) {
        free(copy);
        snprintf(err, err_size, "Malformed request line");
        return -1;
    }
    if (copy_field(out->method,sizeof(out->method),method)||copy_field(out->version,sizeof(out->version),version)) { free(copy); snprintf(err,err_size,"Method/version too long"); return -1; }
    if (strcmp(version,"HTTP/1.0") && strcmp(version,"HTTP/1.1")) { free(copy); snprintf(err,err_size,"Only HTTP/1.0 and HTTP/1.1 are supported"); return -1; }
    out->is_connect = !strcmp(method,"CONNECT");
    if (out->is_connect) {
        if (parse_authority(target,out->host,sizeof(out->host),&out->port,443)) { free(copy); snprintf(err,err_size,"Invalid CONNECT authority"); return -1; }
        strcpy(out->path,target);
    } else if (!strcmp(target,"*")) { strcpy(out->path,"*"); }
    else if (!strncasecmp(target,"http://",7)) {
        char *authority=target+7, *slash=strpbrk(authority,"/?#");
        if (slash) {
            char saved=*slash; *slash='\0';
            if (parse_authority(authority,out->host,sizeof(out->host),&out->port,80)) { free(copy); snprintf(err,err_size,"Invalid URL authority"); return -1; }
            *slash=saved;
            if (*slash=='?') snprintf(out->path,sizeof(out->path),"/%s",slash);
            else if (*slash=='#') strcpy(out->path,"/");
            else copy_field(out->path,sizeof(out->path),slash);
        } else {
            if (parse_authority(authority,out->host,sizeof(out->host),&out->port,80)) { free(copy); snprintf(err,err_size,"Invalid URL authority"); return -1; }
            strcpy(out->path,"/");
        }
    } else {
        if (target[0] != '/') { free(copy); snprintf(err,err_size,"Expected absolute HTTP URL or origin-form path"); return -1; }
        if (copy_field(out->path,sizeof(out->path),target)) { free(copy); snprintf(err,err_size,"Path too long"); return -1; }
    }
    while ((line=strtok_r(NULL,"\r\n",&save))) {
        char *colon=strchr(line,':');
        if (!colon) { free(copy); snprintf(err,err_size,"Malformed header"); return -1; }
        *colon='\0';
        if (!strcasecmp(line,"Host")) { copy_field(host_header,sizeof(host_header),colon+1); trim(host_header); }
    }
    if (!out->is_connect && !out->host[0]) {
        if (!host_header[0] || parse_authority(host_header,out->host,sizeof(out->host),&out->port,80)) { free(copy); snprintf(err,err_size,"Missing or invalid Host header"); return -1; }
    }
    free(copy);
    if (!strcmp(out->method,"GET") || !strcmp(out->method,"HEAD") || out->is_connect) return 0;
    snprintf(err,err_size,"Method not supported (supported: GET, HEAD, CONNECT)"); return -2;
}
