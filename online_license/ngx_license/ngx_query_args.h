#ifndef NGX_QUERY_ARGS_H_
#define NGX_QUERY_ARGS_H_

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>

struct ngx_http_querystring_args_t{
    ngx_queue_t queue;
    ngx_str_t key;
    ngx_str_t data;
};

struct ngx_http_querystring_ctx_t{
    ngx_str_t page;
    uint32_t querystring_count;
#define kMaxQueryStrCount 32
    struct ngx_http_querystring_args_t querystring[kMaxQueryStrCount];
};

void KeyValuePair(const u_char* b, const u_char* p, int store_index, struct ngx_http_querystring_ctx_t* ctx);
void QueryAgrs(ngx_http_request_t *r, const u_char* b, int blen, struct ngx_http_querystring_ctx_t* ctx);

#endif