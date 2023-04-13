/*
    http://iosapp.iosnrzs.com/API/GetVersion
    http://iosapp.iosnrzs.com/API/Preset
    http://iosapp.iosnrzs.com/API/AppAd
    http://iosapp.iosnrzs.com/API/GetAllGame
    http://iosapp.iosnrzs.com/API/UserNameReg
    http://iosapp.iosnrzs.com/API/GetAllGame
    http://iosapp.iosnrzs.com/API/GetGameDetail
    http://iosapp.iosnrzs.com/API/GetScriptDetail
    http://iosapp.iosnrzs.com/api/GetUserInfo
    http://data.niaoren001.com/api/IOSCollectData?
*/

#include "ngx_http_license_post.h"

#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>
#include <stdarg.h>
#include <ngx_log.h>
#include "ngx_config.h"
#include "../third_party/cJSON/cJSON.h"
#include <openssl/des.h>

#include "ngx_base64_des.h"
#include "ngx_base.h"
#include "ngx_query_args.h"

#include "../third_party/btree/btree.h"

extern ngx_module_t ngx_http_license_module;

static void NRZSEncrypt(const ngx_str_t* src, ngx_str_t* dst) {
    ngx_str_t key = {0, (u_char*)"ZHcuXXppA054EB42QFV5ORUVFRUVFeU/AAAAAABAb0A="};
    key.len = strlen((char*)key.data);
    ngx_str_t iv = {0, (u_char*)"eBAeNkBVeTkVFRUVFRXlPw=="};
    iv.len = strlen((char*)iv.data);
    NgxEnc(src, &key, &iv, dst);
}

static void NRZSDecrypt(const ngx_str_t* src, ngx_str_t* dst) {
    ngx_str_t key = {0, (u_char*)"ZHcuXXppA054EB42QFV5ORUVFRUVFeU/AAAAAABAb0A="};
    key.len = strlen((char*)key.data);
    ngx_str_t iv = {0, (u_char*)"eBAeNkBVeTkVFRUVFRXlPw=="};
    iv.len = strlen((char*)iv.data);
    NgxDec(src, &key, &iv, dst);
}

static void UrlQueryStr(ngx_http_request_t *r, const u_char* b, int blen, struct ngx_http_querystring_ctx_t* ctx){
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
  uint32_t i;
  for (i = 0; i < ctx->querystring_count; i++) {
    if (ngx_strncmp(ctx->querystring[i].key.data, "Data", 4) == 0) {
        if (ctx->querystring[i].data.data) {
            ctx->querystring[i].data.len = UrlDecode((char*)ctx->querystring[i].data.data, ctx->querystring[i].data.len);
            ngx_str_t dst = {0, NULL};
            NRZSDecrypt(&ctx->querystring[i].data, &dst);
            free(ctx->querystring[i].data.data);
            ctx->querystring[i].data.data = dst.data;
            ctx->querystring[i].data.len = dst.len;
            break;
            // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Preset err:%s", ctx->querystring[i].data.data);
        }
    }
  }
}

static void UrlQueryFree(struct ngx_http_querystring_ctx_t* ctx){
  uint32_t i;
  for (i = 0; i < ctx->querystring_count; i++) {
    if (ctx->querystring[i].key.data)
      free(ctx->querystring[i].key.data);
    if (ctx->querystring[i].data.data)
      free(ctx->querystring[i].data.data);
  }
}

void SendStrMsg(ngx_http_request_t *r, const u_char* buf) {
    ngx_int_t rc = NgxHTTPSendJSON(r, (u_char*)buf, ngx_strlen(buf));
    if (rc != NGX_HTTP_OK) {
        ngx_log_stderr(0, "xxx_SendStrMsg:%s-%d-12213131", r->uri.data, rc);
        ngx_http_finalize_request(r, rc);
    }
}

void SendJsonMsg(ngx_http_request_t *r, const char* json_obj, const char* msg) {
  cJSON *monitor = cJSON_CreateObject();
  cJSON_AddNumberToObject(monitor, "Code", 1);
  if (json_obj == NULL || (json_obj[0] == 'n' && json_obj[1] == 'u' && json_obj[2] == 'l' && json_obj[3] == 'l')) {
    cJSON_AddStringToObject(monitor, "Data", "null");
  }
  else {
    ngx_str_t src;
    src.len = strlen(json_obj);
    src.data = (u_char*)json_obj;
    ngx_str_t dst = {0, NULL};
    NRZSEncrypt(&src, &dst);
    // NSString* enc = NRZSEncrypt([NSString stringWithUTF8String:json_obj]);
    if (dst.data) {
        cJSON_AddStringToObject(monitor, "Data", (char*)dst.data);
        free(dst.data);
        dst.data = NULL;
    }
  }
  cJSON_AddStringToObject(monitor, "Msg", msg);
  const char* str = (const char*)cJSON_Print(monitor);
  if (monitor != NULL) {
      cJSON_Delete(monitor);
  }
  SendStrMsg(r, (const u_char*)str);
  if (str != NULL) {
    free((void*)str);
  }
}

struct GameScripts {
    uint32_t game_id;
    uint32_t scripts_num;
    uint32_t scripts_id[64];
};

#define MAX_GAME_NUM 512
static struct GameScripts game_scripts[MAX_GAME_NUM];
static uint32_t game_num = 0;

static uint32_t nrzs_script_id_to_game_id(uint32_t script_id) {
    uint32_t i, j;
    for (i = 0; i < game_num; i++) {
        for (j = 0; j < game_scripts[i].scripts_num; j++) {
            if (game_scripts[i].scripts_id[j] == script_id) {
                // ngx_log_stderr(0, "xxxx_GameId:%d", game_scripts[i].game_id);
                return game_scripts[i].game_id;
            }
        }
    }
    return -1;
}

static void nrzs_games_key_value_pair(const char* root_path,uint32_t game_index_counter, uint32_t game_id) {
    char buf[1024];
    sprintf(buf, "%s/nrzs/games/%d/GetGameDetail", root_path, game_id);
    ngx_str_t src = {0, NULL};
    FetchFile(buf, &src);
    cJSON* json_games = cJSON_Parse((const char*)src.data);
    if (json_games != NULL) {
        cJSON* item = cJSON_GetObjectItem(json_games, "ScriptInfos");
        uint32_t scripts_id_counter = 0;
        cJSON* scripts = item->child;
        while (scripts != NULL) {
            int ScriptId = cJSON_GetObjectItem(scripts, "ScriptId")->valueint;
            game_scripts[game_index_counter].scripts_id[scripts_id_counter++] = ScriptId;
            scripts = scripts->next;
        }
        game_scripts[game_index_counter].game_id = game_id;
        game_scripts[game_index_counter].scripts_num = scripts_id_counter;
        game_scripts[game_index_counter].scripts_id[scripts_id_counter++] = -1;
        cJSON_Delete(json_games);
    }
    if (src.data) {
        free(src.data);
        src.data = NULL;
    }
}

ngx_int_t nrzsGameScriptsInit() {
    // ngx_log_stderr(0, "ScriptIdxxxx:x");
    char buf[1024] = {0};
    char root_path[511] = {0};
    if(!NgxGetRoot((u_char*)root_path, 511))
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    snprintf(buf, 1023, "%s/nrzs/api/GetAllGame", root_path);
    ngx_str_t src = {0, NULL};
    FetchFile(buf, &src);
    cJSON* json_games = cJSON_Parse((char*)src.data);
    if (json_games != NULL) {
        cJSON* game = json_games->child;
        game_num = 0;
        while (game != NULL){
            if (game_num >= MAX_GAME_NUM) {
                break;
            }
            int game_id = cJSON_GetObjectItem(game, "ID")->valueint;
            nrzs_games_key_value_pair(root_path, game_num, game_id);
            // ngx_log_stderr(0, "xxxx_Game:%d", game_id);
            ++game_num;
            game = game->next;
        }
        cJSON_Delete(json_games);
    }
    if (src.data) {
        free(src.data);
        src.data = NULL;
    }
    return NGX_OK;
}

void ReadPostBody(ngx_http_request_t *r, ngx_str_t* body) {
    ngx_chain_t *bufs = r->request_body->bufs;
    body->data = ngx_pnalloc(r->pool, r->headers_in.content_length_n + 1);
    size_t i;
    for (i = 0; bufs && body->data; ) {
         ngx_buf_t *buf = bufs->buf;
         memcpy(body->data + i, buf->pos, buf->last - buf->pos);
         i += (buf->last - buf->pos);
         bufs = bufs->next;
    }
    if (!body->data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "read_body fail!");
        body->len = 0;
        body->data = NULL;
        return;
    }
    body->len = r->headers_in.content_length_n;
}

static bool ngx_http_write_post_static_body(ngx_http_request_t *r) {
    ngx_http_license_post_process_init(NULL);
    if (!ngx_strncasecmp(r->uri.data, (u_char*)"/api/IOSCollectData?", r->uri.len)) {
        SendStrMsg(r, (const u_char*)"{\"code\":0,\"data\":null,\"msg\":null,\"r\":0,\"sign\":null}");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/API/AppAd", r->uri.len)) {
        SendJsonMsg(r, "[]", "通用广告列表获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/API/Preset", r->uri.len)) {
        SendJsonMsg(r, "{\"SearchTagContent\":\"问题反馈交流群:671145622\",\"PrivacyAgreement\":\"http://niaoren003.com/\",\"RunSiteHost\":\"http://ios.niaoren003.com\",\"PayUrl\":\"http://niaoren003.com/\",\"CardBuyUrl\":\"http://niaoren003.com/\"}", "预置信息获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/API/GetVersion", r->uri.len)) {
        SendJsonMsg(r, "null", "版本信息获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/api/用户脚本获取成功", r->uri.len)) {
        SendJsonMsg(r, "null", "用户脚本获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/API/GetSearchKey", r->uri.len)) {
        SendJsonMsg(r, "null", "搜索关键字获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/API/GetSearchResult", r->uri.len)) {
        SendJsonMsg(r, "null", "搜索关键字获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/api/GetUserInfo", r->uri.len)) {
        SendJsonMsg(r, "{\"UCID\":1782972,\"NickName\":\"woshishui\",\"PhoneNumber\":null,\"Avatar\":null,\"SessionID\":\"A2D5FEF2D199A4FEAA8B723BE3D61526E8CF3593595569903420B89B9EC644D8\",\"LoginToken\":\"91AE4E9EBEECA5770FDF31D1A6FBD918EFF61F7718ACD4DD\",\"GoldCoinNum\":100.0}", "用户信息获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/API/UserNameReg", r->uri.len) || 
            !ngx_strncasecmp(r->uri.data, (u_char*)"/API/UserNameLogin", r->uri.len) || 
            !ngx_strncasecmp(r->uri.data, (u_char*)"/API/UserLoginAuto", r->uri.len)) {
        SendJsonMsg(r, "{\"UCID\":1783155,\"NickName\":\"woshishui\",\"PhoneNumber\":\"\",\"Avatar\":\"\",\"SessionID\":\"A2D5FEF2D199A4FEAA8B723BE3D61526E8CF3593595569903420B89B9EC644D8\",\"LoginToken\":\"91AE4E9EBEECA5770FDF31D1A6FBD918EFF61F7718ACD4DD\",\"GoldCoinNum\":100.0}", "用户信息获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/api/ScriptRunTJ", r->uri.len)) {
        SendJsonMsg(r, "{\"SID\":13120701}", "运行脚本获取成功");
        return true;
    }
    else if (!ngx_strncasecmp(r->uri.data, (u_char*)"/api/Heartbeat", r->uri.len)) {
        SendJsonMsg(r, "{\"Status\":1,\"IsShowMsg\":false,\"Msg\":\"\",\"OutDeviceType\":null,\"OutDeviceLoginTime\":null}", "运行脚本获取成功");
        return true;
    }
    else {
        return false;
    }
}

static void ngx_http_read_post_body(ngx_http_request_t *r)
{
    ngx_http_license_post_ctx_t* ctx1;
    ctx1 = ngx_http_get_module_ctx(r, ngx_http_license_module);
    ctx1->done = 1;
#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif
    if (ctx1->waiting_more_body) {
        ctx1->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
        return;
    }
    ngx_http_license_post_process_init(NULL);
    // ngx_log_stderr(0, "ngx_http_read_post_body:%d", r->uri.data);
    if (ngx_http_write_post_static_body(r)) {
        return;
    }
    char buf[1024] = {0};
    char root_path[512] = {0};
    if (root_path[0] == 0) {
        if(!NgxGetRoot((u_char*)root_path, 511)){
            return;
        }
    }
    ngx_str_t body;
    struct ngx_http_querystring_ctx_t* ctx = NULL;
    if (ngx_strncasecmp(r->uri.data, (u_char*)"/API/GetAllGame", r->uri.len) == 0) {
        snprintf(buf, 1023, "%s/nrzs/api/GetAllGame", root_path);
        ngx_str_t src = {0, NULL};
        FetchFile(buf, &src);
        if (src.data) {
            SendJsonMsg(r, (const char*)src.data, "全部游戏获取成功");
            free(src.data);
        }
        else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetAllGame err:%s", buf);
        }
    }
    else if ((ngx_strncasecmp(r->uri.data, (u_char*)"/API/GetGameDetail", r->uri.len) == 0) || 
        (ngx_strncasecmp(r->uri.data, (u_char*)"/api/GetScripts", r->uri.len) == 0)) {
        ctx = (struct ngx_http_querystring_ctx_t*)alloca(sizeof(struct ngx_http_querystring_ctx_t));
        ReadPostBody(r, &body);
        UrlQueryStr(r, (const u_char*)body.data, r->headers_in.content_length_n, ctx);
        uint32_t i;
        for (i = 0; i < ctx->querystring_count; i++) {
            if (strncasecmp((char*)ctx->querystring[i].key.data, "Data", 4) == 0) {
                cJSON* json = cJSON_Parse((char*)ctx->querystring[i].data.data);
                if (!json) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ScriptInfos err GameId1???:");
                    continue;
                }
                cJSON* item = cJSON_GetObjectItem(json, "GameId");
                if (item == NULL || !cJSON_IsNumber(item)) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ScriptInfos err GameId2???:");
                    cJSON_Delete(json);
                    continue;
                }
                snprintf(buf, 1023, "%s/nrzs/games/%d/GetGameDetail", root_path, item->valueint);
                cJSON_Delete(json);
                ngx_str_t src = {0, NULL};
                FetchFile(buf, &src);
                if (ngx_strncasecmp(r->uri.data, (u_char*)"/api/GetScripts", r->uri.len) != 0) {
                    if(src.data){
                       SendJsonMsg(r, (const char*)src.data, "游戏信息获取成功"); 
                    }
                    else {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetScripts err GameId3???:");
                    }
                }
                else {
                    if (!src.data) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetGameDetail err GameId4???:");
                        continue;
                    }
                    json = cJSON_Parse((const char*)src.data);
                    if (json != NULL) {
                        cJSON* item = cJSON_GetObjectItem(json, "ScriptInfos");
                        const char* str = (const char*)cJSON_Print(item);
                        if (str != NULL) {
                            SendJsonMsg(r, str, "游戏信息获取成功");
                            free((void*)str);
                        }
                        else {
                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetGameDetail err GameId4.1???:");
                        }
                        cJSON_Delete(json);
                    }
                }
                if (src.data) {
                    free(src.data);
                    src.data = NULL;
                }
                break;
            }
        }
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetGameDetail err:%s", read_body);
    }
    else if (ngx_strncasecmp(r->uri.data, (u_char*)"/API/GetScriptDetail", r->uri.len) == 0) {
        ctx = (struct ngx_http_querystring_ctx_t*)alloca(sizeof(struct ngx_http_querystring_ctx_t));
        ReadPostBody(r, &body);
        UrlQueryStr(r, (const u_char*)body.data, r->headers_in.content_length_n, ctx);
        uint32_t i;
        for (i = 0; i < ctx->querystring_count; i++) {
            if (strncasecmp((char*)ctx->querystring[i].key.data, "Data", 4) == 0) {
                cJSON* json = cJSON_Parse((char*)ctx->querystring[i].data.data);
                if (!json) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ScriptInfos err GameId6???:");
                    continue;
                }
                cJSON* item = cJSON_GetObjectItem(json, "ScriptId");
                if (item == NULL || !cJSON_IsNumber(item)) {
                    cJSON_Delete(json);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ScriptInfos err GameId5???:");
                    continue;
                }
                uint32_t script_id = item->valueint;
                int game_id = nrzs_script_id_to_game_id(item->valueint);
                if (game_id == -1) {
                    nrzsGameScriptsInit();
                    game_id = nrzs_script_id_to_game_id(item->valueint);
                    if (game_id == -1) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetScriptDetail err -1:%d", item->valueint);
                        cJSON_Delete(json);
                        continue;
                    }
                }
                cJSON_Delete(json);
                snprintf(buf, 1023, "%s/nrzs/games/%d/%d.ScriptDetail", root_path, game_id, script_id);
                ngx_str_t src = {0, NULL};
                FetchFile(buf, &src);
                if (src.data) {
                    SendJsonMsg(r, (const char*)src.data, "游戏信息获取成功");
                    free(src.data);
                    src.data = NULL;
                    // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetScriptDetail err:%s", buf);
                }
                break;
            }
        }
    }
    else if (ngx_strncasecmp(r->uri.data, (u_char*)"/api/GetRunPerm", r->uri.len) == 0) {
        ctx = (struct ngx_http_querystring_ctx_t*)alloca(sizeof(struct ngx_http_querystring_ctx_t));
        ReadPostBody(r, &body);
        UrlQueryStr(r, (const u_char*)body.data, r->headers_in.content_length_n, ctx);
        uint32_t i;
        for (i = 0; i < ctx->querystring_count; i++) {
            if (strncasecmp((char*)ctx->querystring[i].key.data, "Data", 4) == 0) {
                cJSON* json = cJSON_Parse((char*)ctx->querystring[i].data.data);
                if (!json) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetRunPerm err GameId8???:");
                    break;
                }
                cJSON* item = cJSON_GetObjectItem(json, "ScriptId");
                if (item == NULL || !cJSON_IsNumber(item)) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetRunPerm err GameId9???:");
                    cJSON_Delete(json);
                    break;
                }
                uint32_t script_id = item->valueint;
                int game_id = nrzs_script_id_to_game_id(item->valueint);
                if (game_id == -1) {
                    nrzsGameScriptsInit();
                    game_id = nrzs_script_id_to_game_id(item->valueint);
                    if (game_id == -1) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetRunPerm err xxx:%d", item->valueint);
                        cJSON_Delete(json);
                        break;
                    }
                }
                cJSON_Delete(json);
                snprintf(buf, 1023, "%s/nrzs/games/%d/%d.RunPerm", root_path, game_id, script_id);
                ngx_str_t src = {0, NULL};
                FetchFile(buf, &src);
                if (src.data == NULL) {
                    break;
                }
                json = cJSON_Parse((char*)src.data);
                if (!json) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GetRunPerm err -111:%d-%d", game_id, script_id);
                    break;
                }
                item = cJSON_GetObjectItem(json, "RunPerm");
                if (item != NULL) {
                    cJSON_ReplaceItemInObject(item, "Run",cJSON_CreateBool(1));
                    cJSON_ReplaceItemInObject(item, "Try",cJSON_CreateBool(0));
                    cJSON_ReplaceItemInObject(item, "TryExpired",cJSON_CreateBool(0));
                }
                item = cJSON_GetObjectItem(json, "ScriptInfo");
                if (item != NULL) {
                    cJSON_ReplaceItemInObject(item, "Level",cJSON_CreateNumber(1));
                }
                const char* str = (const char*)cJSON_Print(json);
                if (json != NULL) {
                    SendJsonMsg(r, (const char*)str, "游戏信息获取成功");
                    cJSON_Delete(json);
                    free((void*)str);
                }
                free(src.data);
                src.data = NULL;
                break;
            }
        }
    }
    if (ctx != NULL) {
        UrlQueryFree(ctx);
        ctx = NULL;
    }
    if (body.data != NULL) {
        ngx_pfree(r->pool, body.data);
        body.data = NULL;
    }
    return;
}

ngx_int_t ngx_http_license_post_process_init(ngx_cycle_t *cycle) {
    static int ht_game_script_infos_initialized = 0;
    if (ht_game_script_infos_initialized) {
        return NGX_OK;
    }
    ngx_int_t r = nrzsGameScriptsInit();
    ht_game_script_infos_initialized = 1;
    return r;
}

#define form_urlencoded_type "application/x-www-form-urlencoded"
#define form_urlencoded_type_len (sizeof(form_urlencoded_type) - 1)

ngx_int_t ngx_http_license_post_module_handler(ngx_http_request_t *r)
{
    ngx_http_license_post_ctx_t* ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_license_module);
    if (ctx != NULL) {
        if (ctx->done) {
            ngx_pfree(r->pool, ctx);
            ngx_http_set_ctx(r, NULL, ngx_http_license_module);
            return NGX_DECLINED;
        }
        return NGX_DONE;
    }
    else {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_license_post_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_license_module);
    }
    if (r->method != NGX_HTTP_POST) {
        // ngx_log_stderr(0, "xxxPOST_NGX_HTTP_NOT_ALLOWED:%s", r->uri.data);
        return NGX_HTTP_NOT_ALLOWED;
    }
    if (r->headers_in.content_type == NULL || r->headers_in.content_type->value.data == NULL) {
        // ngx_log_stderr(0, "xxxPOST_NGX_HTTP_NO_CONTENT:%s", r->uri.data);
        return NGX_HTTP_NO_CONTENT;
    }
    if (NULL == r->headers_in.content_length || 0 == atoi((const char *)r->headers_in.content_length->value.data)) {
        // ngx_log_stderr(0, "xxxPOST_NGX_HTTP_NO_CONTENT:%s", r->uri.data);
        return NGX_HTTP_NO_CONTENT;
    }
    ngx_str_t value = r->headers_in.content_type->value;
    if (value.len < form_urlencoded_type_len || ngx_strncasecmp(value.data, (u_char *) form_urlencoded_type, form_urlencoded_type_len) != 0) {
        return NGX_HTTP_NO_CONTENT;
    }
    ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_read_post_body);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
        (nginx_version >= 1003000 && nginx_version < 1003009)
        r->main->count--;
#endif
        // ngx_log_stderr(0, "xxxPOST_ngx_http_read_client_request_body error!:%s-%d-1-2873901", r->uri.data, rc);
        return rc;
    }
    if (rc == NGX_AGAIN) {
        // ngx_log_stderr(0, "xxxPOST_ngx_http_read_client_request_body error!:%s-%d-1-28739012", r->uri.data, rc);
        ctx->waiting_more_body = 1;
        return NGX_DONE;
    }
    else if (rc != NGX_OK) {
        // ngx_log_stderr(0, "xxxPOST_ngx_http_read_client_request_body error!:%s-%d-1-287390", r->uri.data, rc);
        return rc;
    }
    return NGX_HTTP_OK;
}
