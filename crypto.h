#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

int tls_init_connect(TLSContext *ctx);
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// WebSocket 辅助
int build_ws_frame(const char *in, int len, char *out);
// [修复] 返回值改为 long long 以匹配 proxy.c 中的定义
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

#endif // CRYPTO_H
