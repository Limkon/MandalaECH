#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

// --- 初始化与清理 ---
void init_crypto_global();
void cleanup_crypto_global();

// --- BIO 扩展 (Fragmentation) ---
BIO_METHOD *BIO_f_fragment(void);
void BIO_set_params(BIO *b, const CryptoSettings *s);

// --- TLS 连接与 IO ---
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings);
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// --- WebSocket 辅助 ---
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);

// [Fix] 增加 max_len 参数防止缓冲区溢出
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len, int max_len);

#endif // CRYPTO_H
