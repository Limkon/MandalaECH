#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>

// [修复] 删除了导致冲突的 typedef CryptoSettings
// 类型已由 common.h 统一提供

// 全局加密环境初始化
void init_crypto_global();

// 全局加密环境清理
void cleanup_crypto_global();

// --- TLS 连接封装 ---
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings);
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// --- WebSocket 协议封装 ---
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

// --- BIO Filters ---
BIO_METHOD *BIO_f_fragment(void);
void BIO_set_params(BIO *b, const CryptoSettings *s);

#endif // CRYPTO_H
