#ifndef NGX_HTTP_LICENSE_POST_H_
#define NGX_HTTP_LICENSE_POST_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_file.h>


typedef struct {
    unsigned done:1;
    unsigned waiting_more_body:1;
} ngx_http_license_post_ctx_t;

ngx_int_t ngx_http_license_post_process_init(ngx_cycle_t *cycle);
ngx_int_t ngx_http_license_post_module_handler(ngx_http_request_t *r);

#ifdef __cplusplus
};
#endif

#endif