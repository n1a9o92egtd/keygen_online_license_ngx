#ifndef NGX_BASE64_H_
#define NGX_BASE64_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_file.h>


ngx_int_t NgxGetRoot(u_char *buf, size_t len);
const u_char* strlchr(const u_char *p, const u_char *last, u_char c);
void FetchFile(const char* filepath, ngx_str_t *src);
ngx_int_t NgxHTTPSendOutput(ngx_http_request_t *r, const ngx_str_t *src, const ngx_str_t *content_type);
ngx_int_t NgxHTTPSendStr(ngx_http_request_t *r, u_char *data_buffer, int len);
ngx_int_t NgxHTTPSendJSON(ngx_http_request_t *r, u_char *data_buffer, int len);


int UrlDecode(char *str, int len);

#ifdef __cplusplus
};
#endif

#endif