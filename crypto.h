#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>

// 定义 TLS 上下文结构体
typedef struct {
    SOCKET sock;
    SSL *ssl;
} TLSContext;

// --- BIO 分片过滤器 ---
BIO_METHOD *BIO_f_fragment(void);

// --- OpenSSL 全局初始化与销毁 ---
void init_openssl_global();
void FreeGlobalSSLContext();

// --- TLS 连接函数 (增加 ECH 参数) ---
// target_sni, target_host, ech_config_b64
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const char* ech_config_b64);

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
