// crypto.h
#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

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

void init_crypto_global();
void cleanup_crypto_global();

// 初始化连接 (阻塞模式，用于握手)
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings);

// 同步读写 (用于握手)
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// [IOCP] 切换到内存 BIO 模式
BOOL tls_switch_to_mem_bio(CONNECTION_CONTEXT* connCtx, TLSContext* tls);

// [IOCP] 内存 BIO 读写辅助
// decrypted_out: 存放解密后的数据
// encrypted_in: 收到的密文数据
int tls_decrypt_from_mem(CONNECTION_CONTEXT* ctx, const char* encrypted_in, int in_len, char* decrypted_out, int max_out);

// encrypted_out: 存放加密后的数据 (准备发送)
// plain_in: 待发送的明文
int tls_encrypt_to_mem(CONNECTION_CONTEXT* ctx, const char* plain_in, int in_len, char* encrypted_out, int max_out);

// WebSocket 辅助
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

// ECH
unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len);

#endif
