#include "ngx_query_args.h"
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>
#include <stdarg.h>
#include <ngx_log.h>
#include "ngx_base.h"

void KeyValuePair(const u_char* b, const u_char* p, int store_index, struct ngx_http_querystring_ctx_t* ctx) {
  u_char* equal = (u_char*)strlchr(b, p, '=');
  if (equal == NULL) {
    return;
  }
  ctx->querystring[store_index].key.data = (u_char*)malloc(equal - b + 1);
  ctx->querystring[store_index].key.len = equal - b;
  strncpy((char*)ctx->querystring[store_index].key.data, (const char*)b, ctx->querystring[store_index].key.len);
  ctx->querystring[store_index].data.data = (u_char*)malloc(p - (equal + 1) + 1);
  ctx->querystring[store_index].data.len = p - (equal + 1);
  strncpy((char*)ctx->querystring[store_index].data.data, (const char*)(equal + 1), ctx->querystring[store_index].data.len);
  ctx->querystring_count++;
}

void QueryAgrs(ngx_http_request_t *r, const u_char* b, int blen, struct ngx_http_querystring_ctx_t* ctx) {
  const u_char* last = b + blen;
  u_char* p  = NULL;
  ctx->querystring_count = 0;
  while ((p = (u_char*)strlchr(b, last, (u_char)'&')) != NULL) {
    if (p != NULL) {
      KeyValuePair(b, p, ctx->querystring_count, ctx);
      b = p + 1;
    }
  }
  KeyValuePair(b, last, ctx->querystring_count, ctx);
}