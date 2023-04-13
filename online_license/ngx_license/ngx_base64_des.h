#ifndef NGX_BASE64_DES_H_
#define NGX_BASE64_DES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_file.h>

void NgxEnc(const ngx_str_t *msg, const ngx_str_t *key, const ngx_str_t *iv, ngx_str_t* out_data);
void NgxDec(const ngx_str_t *msg, const ngx_str_t *key, const ngx_str_t *iv, ngx_str_t* out_data);

#ifdef __cplusplus
};
#endif

#endif