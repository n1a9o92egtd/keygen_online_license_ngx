#ifndef NGX_HTTP_LICENSE_GET_H_
#define NGX_HTTP_LICENSE_GET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_file.h>

ngx_int_t ngx_http_license_get_module_handler(ngx_http_request_t *r);

#ifdef __cplusplus
};
#endif

#endif