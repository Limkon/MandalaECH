#ifndef CRYPTO_H
#define CRYPTO_H

#include <winsock2.h>
#include <openssl/ssl.h>

// 防止日志消息 ID 重复定义
#ifndef WM_LOG_UPDATE
#define WM_LOG_UPDATE (WM_USER + 1)
#endif

// [修复] 完整的上下文结构定义
// 之前这里缺失导致 crypto.c 无法识别 ctx 成员
typedef struct {
    SOCKET sock;
    SSL_CTX *ctx;
    SSL *ssl;
} TLSContext;

// 全局初始化与清理 (供 gui.c 调用)
void init_openssl_global();
void FreeGlobalSSLContext();
void tls_cleanup_global();

// 核心连接函数
int tls_init_connect(TLSContext *ctx, const char *sni, const char *host, const char *ech_config_b64);
void tls_close(TLSContext *ctx);

// 读写函数
int tls_read(TLSContext *ctx, char *buf, int len);
int tls_write(TLSContext *ctx, const char *buf, int len);

// WebSocket 协议辅助
int build_ws_frame(const char *payload, int len, char *out_frame);
long long check_ws_frame(unsigned char *buf, int len, int *header_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *buf, int exact_len);

#endif // CRYPTO_H
