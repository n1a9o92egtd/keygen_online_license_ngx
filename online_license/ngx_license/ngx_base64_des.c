#include "ngx_base64_des.h"
#include <assert.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include "ngx_config.h"
#include <openssl/des.h>
#include <openssl/evp.h>

void fillPadding(const ngx_str_t *msg, ngx_str_t* newOutput) {
    size_t inLength = msg->len;
    size_t outLength = (inLength + 8) / 8 * 8;

    newOutput->data = malloc(outLength + 1);
    memcpy(newOutput->data, msg->data, inLength);

    const int padding = 8 - inLength % 8;

    if (padding <= 8) {
        size_t i;
        for (i = inLength; i < outLength; i++) {
            newOutput->data[i] = (unsigned char) padding;
        }
    }

    newOutput->data[outLength] = 0x00;
    newOutput->len = outLength;
}

void deletePadding(ngx_str_t *msg, size_t len) {
    if (len < 2) 
        return;

    int lastPos = len - 2;
    unsigned char lastChar = msg->data[lastPos];
    if (lastChar >= 0x01 && lastChar <= 0x08) {

        size_t length = len - lastChar;
        size_t lastCharPos = length - 1;
        unsigned char *newMsg = malloc(length);
        memcpy(newMsg, msg->data, lastCharPos);
        newMsg[lastCharPos] = 0x00;
        free(msg->data);
        msg->data = newMsg;
        msg->len = lastCharPos;
        return;
    } else {
        msg->len = len;
        return;
    }
}

void cbcEncrypt(const ngx_str_t *msg, const u_char *keyText, const u_char *iv, ngx_str_t* out) {
    DES_cblock key;
    DES_key_schedule key_schedule;

    memcpy(key, keyText, 8);
    DES_set_key_unchecked(&key, &key_schedule);

    ngx_str_t paddingStr;
    fillPadding(msg, &paddingStr);

    size_t len = (paddingStr.len + 7) / 8 * 8;
    out->data = malloc(len + 1);

    DES_cblock ivec;
    memcpy(ivec, iv, 8);

    DES_ncbc_encrypt(paddingStr.data, out->data, paddingStr.len, &key_schedule, &ivec, DES_ENCRYPT);

    out->data[len] = 0x00;
    out->len = len;
}

void cbcDecrypt(const ngx_str_t *msg, const u_char *keyText, const u_char *iv, ngx_str_t* out) {
    //loguchar("cbcDecrypt msg", msg);
    DES_cblock key;
    DES_key_schedule key_schedule;

    memcpy(key, keyText, 8);
    DES_set_key_unchecked(&key, &key_schedule);

    size_t lastPos = (msg->len + 7) / 8 * 8;
    size_t length = lastPos + 1;
    out->data = malloc(length);
    //logger("cbcDecrypt size = ", "%lu", strlen(msg));

    DES_cblock ivec;
    memcpy(ivec, iv, 8);

    DES_ncbc_encrypt(msg->data, out->data, msg->len, &key_schedule, &ivec, DES_DECRYPT);

    out->data[lastPos] = 0x00;
    deletePadding(out, length);
}

void base64(const u_char *input, int length, ngx_str_t* output) {
  const size_t pl = 4*((length+2)/3);
  output->data = (u_char*)calloc(pl+1, 1);
  output->len = EVP_EncodeBlock((u_char*)output->data, input, length);
  output->data[output->len] = 0;
}

void decode64(const u_char *input, int length, ngx_str_t* output) {
  const size_t pl = 3*length/4;
  output->data = (u_char*)calloc(pl+1, 1);
  output->len = EVP_DecodeBlock(output->data, (u_char*)input, length);
  output->data[output->len] = 0;
}

void NgxEnc(const ngx_str_t *msg, const ngx_str_t *key, const ngx_str_t *iv, ngx_str_t* out_data) {
    ngx_str_t msg_data = {0, NULL};
    ngx_str_t key_data = {0, NULL};
    decode64(key->data, key->len, &key_data);
    ngx_str_t iv_data = {0, NULL};
    decode64(iv->data, iv->len, &iv_data);
    cbcEncrypt(msg, key_data.data, iv_data.data, &msg_data);
    base64(msg_data.data, msg_data.len, out_data);
    if (msg_data.data) {
        free(msg_data.data);
        msg_data.data = NULL;
    }
    if (key_data.data) {
        free(key_data.data);
        key_data.data = NULL;
    }
    if (iv_data.data) {
        free(iv_data.data);
        iv_data.data = NULL;
    }
}

void NgxDec(const ngx_str_t *msg, const ngx_str_t *key, const ngx_str_t *iv, ngx_str_t* out_data) {
    ngx_str_t msg_data = {0, NULL};
    decode64(msg->data, msg->len, &msg_data);
    ngx_str_t key_data = {0, NULL};
    decode64(key->data, key->len, &key_data);
    ngx_str_t iv_data = {0, NULL};
    decode64(iv->data, iv->len, &iv_data);
    cbcDecrypt(&msg_data, key_data.data, iv_data.data, out_data);
    if (msg_data.data) {
        free(msg_data.data);
        msg_data.data = NULL;
    }
    if (key_data.data) {
        free(key_data.data);
        key_data.data = NULL;
    }
    if (iv_data.data) {
        free(iv_data.data);
        iv_data.data = NULL;
    }
}
