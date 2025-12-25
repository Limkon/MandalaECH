#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>

// [修复] 删除原有的 typedef struct CryptoSettings CryptoSettings;
// 直接使用 common.h 中定义的 CryptoSettings 类型即可

// 全局加密环境初始化
void init_crypto_global();

// 全局加密环境清理
void cleanup_crypto_global();

// --- TLS 连接封装 ---

// 初始化并建立 TLS 连接
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings);

// 通用 TLS 写
int tls_write(TLSContext *ctx, const char *data, int len);

// 通用 TLS 读
int tls_read(TLSContext *ctx, char *out, int max);

// 精确读取指定长度
int tls_read_exact(TLSContext *ctx, char *buf, int len);

// 关闭 TLS 连接
void tls_close(TLSContext *ctx);

// --- WebSocket 协议封装 ---
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

// --- BIO Filters ---
BIO_METHOD *BIO_f_fragment(void);
void BIO_set_params(BIO *b, const CryptoSettings *s);

#endif // CRYPTO_H
