#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

// OpenSSL 初始化與清理
void init_openssl_global();
void FreeGlobalSSLContext();

// TLS 連接操作
int tls_init_connect(TLSContext *ctx);
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// WebSocket 封裝
int build_ws_frame(const char *in, int len, char *out);
int check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

// BIO 分片過濾器 (內部使用，但若需要可在這裡聲明)
BIO_METHOD *BIO_f_fragment(void);

#endif // CRYPTO_H