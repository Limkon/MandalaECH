#ifndef CRYPTO_H
#define CRYPTO_H

#include <winsock2.h>
#include <openssl/ssl.h>

// --- 数据结构 ---
typedef struct {
    int enableFragment;
    int fragMin;
    int fragMax;
    int fragDelay;
    int enablePadding;
    int padMin;
    int padMax;
    int enableChromeCiphers;
} CryptoSettings;

// [Fix] 定义 TLSContext 结构体，解决 unknown type name 错误
typedef struct {
    SSL* ssl;
    SOCKET sock;
} TLSContext;

// --- 函数声明 ---

// 全局初始化
void init_crypto_global();
void cleanup_crypto_global();

// TLS 连接
// 返回 0 成功, -1 失败
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings);

int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// WebSocket 辅助
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

// [Fix] 添加缺失的宏定义
#define MAX_WS_FRAME_SIZE 65536

#endif // CRYPTO_H
