#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

// 初始化与清理
void init_openssl_global();
void FreeGlobalSSLContext();

// TLS 连接相关
int tls_init_connect(TLSContext *ctx);
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// WebSocket 协议辅助
// [注意] 实现位于 crypto.c，proxy.c 通过包含此头文件调用
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

#endif // CRYPTO_H
