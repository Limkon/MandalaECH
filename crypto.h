#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>

// [修复] 前向声明 CryptoSettings 结构体，解决编译时类型未定义错误
typedef struct CryptoSettings CryptoSettings;

// 全局加密环境初始化 (加载算法库、根证书)
void init_crypto_global();

// 全局加密环境清理
void cleanup_crypto_global();

// --- TLS 连接封装 ---

// 初始化并建立 TLS 连接 (支持 SNI, ECH 占位, ALPN)
// [修复] 使用 const CryptoSettings* 确保与 crypto.c 定义一致
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings);

// 通用 TLS 写 (处理 Partial Write 和 Retry)
int tls_write(TLSContext *ctx, const char *data, int len);

// 通用 TLS 读
int tls_read(TLSContext *ctx, char *out, int max);

// 精确读取指定长度 (用于解析定长头部)
int tls_read_exact(TLSContext *ctx, char *buf, int len);

// 关闭 TLS 连接
void tls_close(TLSContext *ctx);

// --- WebSocket 协议封装 ---

// 构建 WebSocket 数据帧 (自动 Mask处理)
int build_ws_frame(const char *in, int len, char *out);

// 检查 WebSocket 帧头完整性
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);

// 读取 WebSocket 负载 (处理变长头)
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

// --- BIO Filters (Fragmentation/Padding) ---
BIO_METHOD *BIO_f_fragment(void);

// [修复] 设置参数接口，解决 crypto.c 中的参数识别问题
void BIO_set_params(BIO *b, const CryptoSettings *s);

#endif // CRYPTO_H
