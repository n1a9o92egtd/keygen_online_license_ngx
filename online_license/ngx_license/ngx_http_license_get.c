#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>
#include <ngx_log.h>
#include "ngx_config.h"
#include "ngx_http_license_get.h"
#include "ngx_base.h"
#include "../keygen/keygen.h"
#include "../keygen/keygen_tester.h"
#include "ngx_query_args.h"

ngx_int_t SendOctetStream(ngx_http_request_t *r, const u_char* filepath, ngx_str_t* content_type) {
    ngx_str_t src;
    FetchFile((const char*)filepath, &src);
    if (src.len == 0 || src.data == NULL) {
        ngx_log_stderr(0, "xxx_URI NO EXISTS:%s-%s", r->exten.data, filepath);
        if (src.data) {
            free(src.data);
        }
        return NGX_OK;
    }
#if 0
    ngx_log_stderr(0, "xxx_URLxxxs2:%s-%s", r->exten.data, filepath);
#endif
    ngx_int_t rc = NgxHTTPSendOutput(r, &src, content_type);
    if (src.data) {
        free(src.data);
    }
    if (rc != NGX_HTTP_OK) {
        return NGX_OK;
    }
    return NGX_HTTP_OK;
}

void WriteLicense(const char* filepath, const char* license_iv) {
    // int inp = open(filepath, O_RDWR);
    // ngx_log_stderr(0, "filepath:%s-license_iv:%s", filepath, license_iv);
    FILE* inp = fopen(filepath, "wb");
    if (!inp) {
        return;
    }
    fwrite(license_iv, sizeof(char), strlen(license_iv), inp); 
    fflush(inp);
    fclose(inp);
}

/*
    http://127.0.0.1/keygen?user=kjdhsjkshfjksdhfskj
    http://127.0.0.1/license/FgWPEqJKOqGcFoFoCDQDFqEgAqAPEqFoLDQDFDGoFmATEMAqOoGoFoQPEPArAMIMENAcEmAMAMEmAPEgIgATATETEMEMEqArArFmBr
    http://127.0.0.1/tester?key=FgWPEqJKOqGcFoFoCDQDFqEgAqAPEqFoLDQDFDGoFmATEMAqOoGoFoQPEPArAMIMENAcEmAMAMEmAPEgIgATATETEMEMEqArArFmBr
*/

ngx_int_t ngx_http_license_get_module_handler(ngx_http_request_t *r) {
    u_char root_dir[512] = {0};
    if(!NgxGetRoot(root_dir, 511)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_snprintf(root_dir, 511, "%s/html", root_dir);
    char license_path[1024] = {0};
    char license_path_spy[1024] = {0};
    // const char* file_exten = (const char*)r->exten.data;
    // int file_exten_len = r->exten.len;
    if (!ngx_strncasecmp(r->uri.data, (u_char*)"/keygen", r->uri.len)) {
        struct ngx_http_querystring_ctx_t* ctx = NULL;
        ctx = (struct ngx_http_querystring_ctx_t*)alloca(sizeof(struct ngx_http_querystring_ctx_t));
        QueryAgrs(r, (const u_char*)r->args.data, r->args.len, ctx);
        char license[1024] = {0};
        char license_iv[1024] = {0};
        bool is_gen_ok = false;
        for (uint32_t i = 0; i < ctx->querystring_count; i++) {
            if (strncasecmp((char*)ctx->querystring[i].key.data, "user", 4) == 0) {
                int try_count = 0;
                do {
                    if (try_count >= 3){
                        is_gen_ok = false;
                        break;
                    }
                    // LicenseGen("asdadsadadadada1111", license, license_iv);
                    LicenseGen((const char*)ctx->querystring[i].data.data, license, license_iv);
                    int license_len = strlen(license);
                    strncpy(license_path, (const char*)root_dir, strlen((const char*)root_dir));
                    strncat(license_path, "/license", sizeof("/license") - 1);
                    if (access(license_path, R_OK) != R_OK) {
                        mkdir(license_path, 0755);
                    }
                    strncat(license_path, "/", 1);
                    strncat(license_path, license, license_len);
                    WriteLicense(license_path, license_iv);
                    ++try_count;
                    is_gen_ok = true;
                } while (access(license_path, F_OK) != F_OK);
                break;
            }
        }
        if (is_gen_ok) {
            return NgxHTTPSendStr(r, (u_char*)license, ngx_strlen(license));
        }
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/license", r->uri.len)) {
        strncpy(license_path_spy, (const char*)root_dir, strlen((const char*)root_dir));
        strncat(license_path_spy, (char*)r->uri.data, r->uri.len); // buffer overflow!!!
        if (access(license_path_spy, F_OK) == F_OK) {
            ngx_str_t content_type = {sizeof("text/plain; charset=utf-8") - 1, (u_char*)("text/plain; charset=utf-8")};
            return SendOctetStream(r, (u_char*)license_path_spy, &content_type);
        }
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/tester", r->uri.len)) {
        struct ngx_http_querystring_ctx_t* ctx = NULL;
        ctx = (struct ngx_http_querystring_ctx_t*)alloca(sizeof(struct ngx_http_querystring_ctx_t));
        QueryAgrs(r, (const u_char*)r->args.data, r->args.len, ctx);
        for (uint32_t i = 0; i < ctx->querystring_count; i++) {
            if (strncasecmp((char*)ctx->querystring[i].key.data, "key", 4) == 0) {
                strncpy(license_path_spy, (const char*)root_dir, strlen((const char*)root_dir));
                strncat(license_path_spy, (char*)"/license/", ctx->querystring[i].data.len);
                strncat(license_path_spy, (char*)ctx->querystring[i].data.data, ctx->querystring[i].data.len); // buffer overflow!!!
                if (access(license_path_spy, F_OK) != F_OK) {
                    continue;
                }
                ngx_str_t src;
                FetchFile((const char*)license_path_spy, &src);
                if (KeyGenTester((const char*)ctx->querystring[i].data.data, (const char*)src.data)) {
                    if (src.data) {
                        free(src.data);
                    }
                    const char ok[] = "ok";
                    return NgxHTTPSendStr(r, (u_char*)ok, ngx_strlen(ok));
                }
                else {
                    if (src.data) {
                        free(src.data);
                    }
                    const char ok[] = "fail";
                    return NgxHTTPSendStr(r, (u_char*)ok, ngx_strlen(ok));
                }
                if (src.data) {
                    free(src.data);
                }
            }
        }
    }
    return NGX_DECLINED;
}
