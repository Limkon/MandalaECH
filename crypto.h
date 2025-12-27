#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "common.h" // 确保包含 common.h 以获取 TLSContext 定义

// [Production] 加密层配置快照，解耦全局变量
typedef struct {
    BOOL enableFragment;
    int fragMin;
    int fragMax;
    int fragDelay;
    
    BOOL enablePadding;
    int padMin;
    int padMax;
    
    BOOL enableChromeCiphers;
} CryptoSettings;

// 线程安全的全局初始化 (BIO Method 等)
void init_crypto_global();
void cleanup_crypto_global();

// 支持传入配置快照的初始化函数
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings);

int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

#endif
