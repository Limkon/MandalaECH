#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

// --- 结构体定义 (确保与 common.h 一致或在此处定义) ---
// 注意：如果在 common.h 中已经定义了 TLSContext，这里不需要重复定义
// 如果 common.h 中没有，则保留此处的定义
#ifndef TLS_CONTEXT_DEFINED
#define TLS_CONTEXT_DEFINED
typedef struct { 
    SOCKET sock; 
    SSL *ssl; 
} TLSContext;
#endif

// --- BIO 分片过滤器 ---
BIO_METHOD *BIO_f_fragment(void);

// --- OpenSSL 全局初始化与销毁 ---
void init_openssl_global();
void FreeGlobalSSLContext();

// --- TLS 连接函数 (已更新签名) ---
// [Fix] 增加 target_sni 和 target_host 参数，支持线程安全的配置传递
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host);

// --- TLS 读写函数 ---
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// --- WebSocket 辅助函数 ---
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

#endif // CRYPTO_H
