#include "ngx_base.h"
#include <assert.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include "ngx_config.h"

char *exe_of(const pid_t pid, size_t *const sizeptr, size_t *const lenptr)
{
    char   *exe_path = NULL;
    size_t  exe_size = 1024;
    ssize_t exe_used;
    char    path_buf[64];
    uint32_t     path_len;

    path_len = snprintf(path_buf, sizeof(path_buf), "/proc/%ld/exe", (long)pid);
    if (path_len < 1 || path_len >= sizeof(path_buf)) {
        errno = ENOMEM;
        return NULL;
    }

    while (1) {

        exe_path = malloc(exe_size);
        if (!exe_path) {
            errno = ENOMEM;
            return NULL;
        }

        exe_used = readlink(path_buf, exe_path, exe_size - 1);
        if (exe_used == (ssize_t)-1)
            return NULL;

        if (exe_used < (ssize_t)1) {
            /* Race condition? */
            errno = ENOENT;
            return NULL;
        }

        if (exe_used < (ssize_t)(exe_size - 1))
            break;

        free(exe_path);
        exe_size += 1024;
    }

    /* Try reallocating the exe_path to minimum size.
     * This is optional, and can even fail without
     * any bad effects. */
    {
        char *temp;

        temp = (char*)realloc(exe_path, exe_used + 1);
        if (temp) {
            exe_path = temp;
            exe_size = exe_used + 1;
        }
    }

    if (sizeptr)
        *sizeptr = exe_size;

    if (lenptr)
        *lenptr = exe_used;

    exe_path[exe_used] = '\0';
    return exe_path;
}

ngx_int_t NgxGetRoot(u_char *buf, size_t len) {
    ngx_memset(buf, 0, len);
    char* exe = exe_of(getpid(), NULL, NULL);
    if (exe == NULL) {
        if(ngx_getcwd(buf, len))
            return 1;
        else
            return 0;
    }
    uint32_t l1 = ngx_strlen(exe);
    ngx_int_t is_ok = 0;
    if (l1 < len) {
        char* exe1 = strrchr(exe, '/');
        if (exe1 == NULL) {
            free(exe);
            if(ngx_getcwd(buf, len))
                return 1;
            else
                return 0;
        }
        exe1[0] = 0;
        exe1 = strrchr(exe, '/');
        exe1[0] = 0;
        ngx_memmove(buf, exe, ngx_strlen(exe));
        is_ok = 1;
    }
    free(exe);
    return is_ok;
}

const u_char* strlchr(const u_char *p, const u_char *last, u_char c){
  while (p < last) {
    if (*p == c) {
      return p;
    }
    p++;
  }
  return NULL;
}

void FetchFile(const char* filepath, ngx_str_t *src) {
  FILE *fp = fopen(filepath, "rb");
  if (fp != NULL) {
    /* Go to the end of the file. */
    if (fseek(fp, 0L, SEEK_END) == 0) {
        /* Get the size of the file. */
        long bufsize = ftell(fp);
        if (bufsize == -1) { /* Error */
            fclose(fp);
            return;
        }
        /* Allocate our buffer to that size. */
        src->data = malloc(sizeof(char) * (bufsize + 1));
        u_char* pbuf = src->data;
        /* Go back to the start of the file. */
        if (fseek(fp, 0L, SEEK_SET) != 0) { /* Error */ 
            fclose(fp);
            return;
        }
        /* Read the entire file into memory. */
        size_t newLen = fread((char*)pbuf, sizeof(char), bufsize, fp);
        if ( ferror( fp ) != 0 ) {
          fputs("Error reading file", stderr);
        } else {
          pbuf[newLen++] = '\0'; /* Just to be safe. */
          src->len = bufsize;
        }
    }
    fclose(fp);
  }
}


ngx_int_t NgxHTTPSendOutput(ngx_http_request_t *r, const ngx_str_t *src, const ngx_str_t *content_type){
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = src->len;
    r->headers_out.content_type.len = content_type->len;
    r->headers_out.content_type.data = content_type->data; 

    //prepare output chain 
    ngx_buf_t* out_buf;
    ngx_chain_t out;
    out_buf = ngx_pnalloc(r->pool,sizeof(ngx_buf_t));
    if(out_buf == NULL){
        ngx_log_error(NGX_LOG_ALERT,r->connection->log,0,"handle output alloc memory error");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    out_buf->pos = ngx_pnalloc(r->pool, src->len);
    if(out_buf->pos == NULL){
        ngx_log_error(NGX_LOG_ALERT,r->connection->log,0,"handle output alloc memory error");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(out_buf->pos, src->data, src->len);

    out_buf->memory = 1;
    out_buf->last   = out_buf->pos + src->len;
    out_buf->last_buf= 1;
    out_buf->in_file = 0;
    out.buf  = out_buf;
    out.next = NULL;

    if (!r->header_sent) {
        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_log_error(NGX_LOG_ALERT,r->connection->log,0,"demo output send header error");
            return rc;
        }
    }

    ngx_http_output_filter(r, &out);
    return NGX_HTTP_OK;
}

ngx_int_t NgxHTTPSendStr(ngx_http_request_t *r, u_char *data_buffer, int len) {
    ngx_str_t content_type = {
        sizeof("text/plain; charset=utf-8") - 1,
        (u_char*)("text/plain; charset=utf-8")
    };
    ngx_str_t src = {len, data_buffer};
    return NgxHTTPSendOutput(r, &src, &content_type);
}


ngx_int_t NgxHTTPSendJSON(ngx_http_request_t *r, u_char *data_buffer, int len) {
    ngx_str_t content_type = {
        sizeof("application/json; charset=utf-8") - 1,
        (u_char*)("application/json; charset=utf-8")
    };
    ngx_str_t src = {len, data_buffer};
    return NgxHTTPSendOutput(r, &src, &content_type);
}

int UrlDecode(char *str, int len) {
  char *dest = str;
  char *data = str;
  int value;
  int c;
  while (len--) {
    if (*data == '+') {
      *dest = ' ';
    }
    else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1))  && isxdigit((int) *(data + 2))) {
      c = ((unsigned char *)(data+1))[0];
      if (isupper(c))
        c = tolower(c);
      value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;
      c = ((unsigned char *)(data+1))[1];
      if (isupper(c))
        c = tolower(c);
      value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
      *dest = (char)value;
      data += 2;
      len -= 2;
    }
    else {
      *dest = *data;
    }
    data++;
    dest++;
  }
  *dest = '\0';
  return (int)(dest - str);
}

